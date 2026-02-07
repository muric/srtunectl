package main

import (
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"

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

// openTunDevice opens an existing TUN interface for read/write.
// This does NOT create the interface — it must already exist.
func openTunDevice(ifName string) (*TUNDevice, error) {
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}

	ifr := ifreq{
		ifrFlags: IFF_TUN | IFF_NO_PI,
	}
	copy(ifr.ifrName[:], ifName)

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(TUNSETIFF), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		file.Close()
		return nil, fmt.Errorf("ioctl TUNSETIFF: %v", errno)
	}

	// Set non-blocking mode for the fd
	if err := syscall.SetNonblock(int(file.Fd()), true); err != nil {
		file.Close()
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
			log.Printf("Error writing to TUN: %v", err)
			return n, &tcpip.ErrAborted{}
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
func (e *TUNEndpoint) Close() {
	close(e.done)
	e.tunDev.Close()
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

