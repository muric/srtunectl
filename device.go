package main

import (
	"fmt"
	"log"
	"os"
	"sync"
	"syscall"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// TUNDevice holds the TUN file descriptor for read/write operations.
type TUNDevice struct {
	file *os.File
	fd   int
	mtu  int
	name string
}

// newTUNDeviceFromFile wraps an already-open TUN file descriptor as a TUNDevice.
// The file must have been obtained from createTunInterface (non-persistent mode).
func newTUNDeviceFromFile(file *os.File, ifName string) (*TUNDevice, error) {
	if err := syscall.SetNonblock(int(file.Fd()), true); err != nil {
		return nil, fmt.Errorf("set nonblock: %w", err)
	}
	return &TUNDevice{
		file: file,
		fd:   int(file.Fd()),
		name: ifName,
	}, nil
}

// Close closes the TUN device file descriptor.
func (d *TUNDevice) Close() error {
	return d.file.Close()
}

// TUNEndpoint adapts a TUN device to gVisor's stack.LinkEndpoint interface.
// It reads raw IP packets from TUN and delivers them to the netstack,
// and writes outgoing packets from the netstack back to TUN.
type TUNEndpoint struct {
	tunDev     *TUNDevice
	mtu        uint32
	dispatcher stack.NetworkDispatcher
	done       chan struct{}
	closeOnce  sync.Once
}

// NewTUNEndpoint creates a new TUNEndpoint wrapping a TUN device.
func NewTUNEndpoint(tunDev *TUNDevice, mtu uint32) *TUNEndpoint {
	tunDev.mtu = int(mtu)
	ep := &TUNEndpoint{
		tunDev: tunDev,
		mtu:    mtu,
		done:   make(chan struct{}),
	}
	return ep
}

// Attach implements stack.LinkEndpoint.
func (e *TUNEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
	go e.dispatchLoop()
	go e.writeLoop()
}

// IsAttached implements stack.LinkEndpoint.
func (e *TUNEndpoint) IsAttached() bool {
	return e.dispatcher != nil
}

// MTU implements stack.LinkEndpoint.
func (e *TUNEndpoint) MTU() uint32 {
	return e.mtu
}

// SetMTU implements stack.LinkEndpoint.
func (e *TUNEndpoint) SetMTU(mtu uint32) {
	e.mtu = mtu
}

// MaxHeaderLength implements stack.LinkEndpoint.
func (e *TUNEndpoint) MaxHeaderLength() uint16 {
	return 0 // TUN devices don't have link-layer headers
}

// LinkAddress implements stack.LinkEndpoint.
func (e *TUNEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

// SetLinkAddress implements stack.LinkEndpoint.
func (e *TUNEndpoint) SetLinkAddress(tcpip.LinkAddress) {}

// Capabilities implements stack.LinkEndpoint.
func (e *TUNEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}

// ARPHardwareType implements stack.LinkEndpoint.
func (e *TUNEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

// AddHeader implements stack.LinkEndpoint.
func (e *TUNEndpoint) AddHeader(*stack.PacketBuffer) {}

// ParseHeader implements stack.LinkEndpoint.
func (e *TUNEndpoint) ParseHeader(*stack.PacketBuffer) bool {
	return true
}

// WritePackets implements stack.LinkEndpoint.
// Writes outgoing packets from the netstack to the TUN device.
func (e *TUNEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	for _, pkt := range pkts.AsSlice() {
		data := pkt.ToView().AsSlice()
		if _, err := syscall.Write(e.tunDev.fd, data); err != nil {
			// Suppress errors during shutdown (fd already closed)
			select {
			case <-e.done:
				return n, &tcpip.ErrAborted{}
			default:
				log.Printf("Error writing to TUN: %v", err)
				return n, &tcpip.ErrAborted{}
			}
		}
		n++
	}
	return n, nil
}

// Wait implements stack.LinkEndpoint.
func (e *TUNEndpoint) Wait() {}

// SetOnCloseAction implements stack.LinkEndpoint.
func (e *TUNEndpoint) SetOnCloseAction(func()) {}

// Close stops the dispatch loop and closes the TUN device.
// Safe to call multiple times (gVisor stack may call it during shutdown).
func (e *TUNEndpoint) Close() {
	e.closeOnce.Do(func() {
		close(e.done)
		_ = e.tunDev.Close()
	})
}

// dispatchLoop reads raw IP packets from the TUN device and delivers
// them to the gVisor netstack for processing.
func (e *TUNEndpoint) dispatchLoop() {
	buf := make([]byte, e.mtu+4) // extra room for safety

	for {
		select {
		case <-e.done:
			return
		default:
		}

		n, err := syscall.Read(e.tunDev.fd, buf)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				// Non-blocking: no data available, try again
				continue
			}
			select {
			case <-e.done:
				return
			default:
				log.Printf("Error reading from TUN: %v", err)
				continue
			}
		}
		if n == 0 {
			continue
		}

		// Determine protocol from IP version field
		pktData := buf[:n]
		var proto tcpip.NetworkProtocolNumber
		if len(pktData) > 0 {
			version := pktData[0] >> 4
			switch version {
			case 4:
				proto = header.IPv4ProtocolNumber
			case 6:
				proto = header.IPv6ProtocolNumber
			default:
				continue // unknown protocol, skip
			}
		}

		// Intercept ICMP echo requests and reply instantly.
		// SS protocol cannot proxy ICMP, so we generate local replies.
		// This gives <1ms ping for TUN-routed IPs — a quick diagnostic
		// that the route goes through the tunnel.
		if e.handleICMPEcho(pktData, proto) {
			continue
		}

		// Create a PacketBuffer and deliver to netstack
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(pktData),
		})
		e.dispatcher.DeliverNetworkPacket(proto, pkt)
		pkt.DecRef()
	}
}

// writeLoop is reserved for channel-based write if needed.
// Currently WritePackets handles writes directly.
func (e *TUNEndpoint) writeLoop() {
	// No-op: writes are handled synchronously in WritePackets
}

// handleICMPEcho intercepts ICMP echo requests and writes an instant echo
// reply back to the TUN device. Returns true if the packet was handled.
func (e *TUNEndpoint) handleICMPEcho(pkt []byte, proto tcpip.NetworkProtocolNumber) bool {
	switch proto {
	case header.IPv4ProtocolNumber:
		return e.handleICMPv4Echo(pkt)
	case header.IPv6ProtocolNumber:
		return e.handleICMPv6Echo(pkt)
	default:
		return false
	}
}

// handleICMPv4Echo handles IPv4 ICMP echo request → echo reply.
func (e *TUNEndpoint) handleICMPv4Echo(pkt []byte) bool {
	// IPv4 header: minimum 20 bytes, ICMP header: 8 bytes
	if len(pkt) < 28 {
		return false
	}

	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+8 {
		return false
	}

	// Check IP protocol field == ICMP (1)
	if pkt[9] != 1 {
		return false
	}

	// Check ICMP type == echo request (8)
	icmp := ihl
	if pkt[icmp] != 8 {
		return false
	}

	// Build reply: copy entire packet, swap addresses, change type
	reply := make([]byte, len(pkt))
	copy(reply, pkt)

	// Swap src ↔ dst IP (offsets 12..15 and 16..19)
	copy(reply[12:16], pkt[16:20])
	copy(reply[16:20], pkt[12:16])

	// Recalculate IPv4 header checksum
	reply[10] = 0
	reply[11] = 0
	ipCsum := ipChecksum(reply[:ihl])
	reply[10] = byte(ipCsum >> 8)
	reply[11] = byte(ipCsum)

	// Set ICMP type to echo reply (0)
	reply[icmp] = 0

	// Recalculate ICMP checksum
	reply[icmp+2] = 0
	reply[icmp+3] = 0
	icmpCsum := ipChecksum(reply[icmp:])
	reply[icmp+2] = byte(icmpCsum >> 8)
	reply[icmp+3] = byte(icmpCsum)

	_, _ = syscall.Write(e.tunDev.fd, reply)
	return true
}

// handleICMPv6Echo handles ICMPv6 echo request → echo reply.
func (e *TUNEndpoint) handleICMPv6Echo(pkt []byte) bool {
	// IPv6 header: 40 bytes, ICMPv6 header: 8 bytes minimum
	if len(pkt) < 48 {
		return false
	}

	// Check Next Header == ICMPv6 (58)
	if pkt[6] != 58 {
		return false
	}

	// Check ICMPv6 type == echo request (128)
	icmp := 40
	if pkt[icmp] != 128 {
		return false
	}

	// Build reply
	reply := make([]byte, len(pkt))
	copy(reply, pkt)

	// Swap src ↔ dst IPv6 addresses (offsets 8..23 and 24..39)
	copy(reply[8:24], pkt[24:40])
	copy(reply[24:40], pkt[8:24])

	// Set ICMPv6 type to echo reply (129)
	reply[icmp] = 129

	// Recalculate ICMPv6 checksum (includes pseudo-header)
	reply[icmp+2] = 0
	reply[icmp+3] = 0
	icmpPayload := reply[icmp:]
	csum := icmpv6Checksum(reply[8:24], reply[24:40], icmpPayload)
	reply[icmp+2] = byte(csum >> 8)
	reply[icmp+3] = byte(csum)

	_, _ = syscall.Write(e.tunDev.fd, reply)
	return true
}

// ipChecksum computes the Internet checksum (RFC 1071).
func ipChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// icmpv6Checksum computes the ICMPv6 checksum with pseudo-header.
func icmpv6Checksum(srcIP, dstIP, icmpData []byte) uint16 {
	var sum uint32

	// Pseudo-header: src address
	for i := 0; i < len(srcIP)-1; i += 2 {
		sum += uint32(srcIP[i])<<8 | uint32(srcIP[i+1])
	}
	// Pseudo-header: dst address
	for i := 0; i < len(dstIP)-1; i += 2 {
		sum += uint32(dstIP[i])<<8 | uint32(dstIP[i+1])
	}
	// Pseudo-header: payload length (32-bit, big-endian)
	plen := uint32(len(icmpData))
	sum += plen >> 16
	sum += plen & 0xffff
	// Pseudo-header: next header (58 = ICMPv6)
	sum += 58

	// ICMPv6 data
	for i := 0; i < len(icmpData)-1; i += 2 {
		sum += uint32(icmpData[i])<<8 | uint32(icmpData[i+1])
	}
	if len(icmpData)%2 == 1 {
		sum += uint32(icmpData[len(icmpData)-1]) << 8
	}

	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

