package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	tcpConnectTimeout = 5 * time.Second
	tcpWaitTimeout    = 60 * time.Second
	udpSessionTimeout = 60 * time.Second
	relayBufferSize   = 32 * 1024
	nicID             = 1
)

// Tunnel connects a TUN device to a Shadowsocks proxy using gVisor netstack.
// It intercepts TCP/UDP packets from the TUN and relays them through the proxy.
type Tunnel struct {
	stack    *stack.Stack
	proxy    *SSProxy
	endpoint *TUNEndpoint
}

// NewTunnel creates and starts a new tunnel.
// It sets up gVisor netstack with TCP and UDP forwarders that relay
// traffic through the given SS proxy.
func NewTunnel(proxy *SSProxy, endpoint *TUNEndpoint) (*Tunnel, error) {
	// Create gVisor network stack
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
	})

	t := &Tunnel{
		stack:    s,
		proxy:    proxy,
		endpoint: endpoint,
	}

	// Set up TCP forwarder — handles all incoming TCP connections
	tcpForwarder := tcp.NewForwarder(s, 0, 65535, func(r *tcp.ForwarderRequest) {
		go t.handleTCP(r)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	// Set up UDP forwarder — handles all incoming UDP packets.
	// Handler returns true to indicate the request was handled (prevents
	// netstack from sending ICMP port unreachable for proxied packets).
	udpForwarder := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		go t.handleUDP(r)
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	// ICMP: no forwarder needed. Shadowsocks protocol only supports TCP/UDP,
	// so ICMP (ping) cannot be proxied. ICMP protocols are registered in the
	// stack so netstack can handle ICMP internally (e.g. port unreachable),
	// but no forwarding to the proxy is required.

	// Create NIC and bind the TUN endpoint
	if err := s.CreateNIC(nicID, endpoint); err != nil {
		return nil, fmt.Errorf("create NIC: %v", err)
	}

	// Enable promiscuous mode to intercept packets for all destination IPs.
	// The TUN device only receives packets that the Linux kernel routes to it
	// (based on routes added by addRoutesFromDir). The netstack must accept
	// all of them regardless of destination IP.
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("set promiscuous mode: %v", err)
	}

	// Enable spoofing to allow sending response packets from any source IP.
	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("set spoofing: %v", err)
	}

	// Set internal route table: accept all traffic arriving at this NIC.
	// This is the gVisor INTERNAL route table, NOT the Linux kernel routes.
	// Only packets routed to TUN by the kernel will reach here.
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         nicID,
		},
	})

	return t, nil
}

// handleTCP handles a new TCP connection from the netstack.
// It dials the SS proxy and relays data bidirectionally.
func (t *Tunnel) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	srcAddr := fmt.Sprintf("%s:%d", id.RemoteAddress.String(), id.RemotePort)
	dstAddr := fmt.Sprintf("%s:%d", id.LocalAddress.String(), id.LocalPort)

	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		log.Printf("[TCP] failed to create endpoint for %s: %v", dstAddr, tcpErr)
		r.Complete(true)
		return
	}
	r.Complete(false)

	localConn := gonet.NewTCPConn(&wq, ep)
	defer localConn.Close()

	// Dial through SS proxy
	ctx, cancel := context.WithTimeout(context.Background(), tcpConnectTimeout)
	defer cancel()

	remoteConn, err := t.proxy.DialContext(ctx, dstAddr)
	if err != nil {
		log.Printf("[TCP] %s <-> %s: dial failed: %v", srcAddr, dstAddr, err)
		return
	}
	defer remoteConn.Close()

	log.Printf("[TCP] %s <-> %s", srcAddr, dstAddr)

	// Bidirectional relay
	pipe(localConn, remoteConn)
}

// handleUDP handles a new UDP packet from the netstack.
// It creates a UDP relay through the SS proxy.
func (t *Tunnel) handleUDP(r *udp.ForwarderRequest) {
	id := r.ID()
	srcAddr := fmt.Sprintf("%s:%d", id.RemoteAddress.String(), id.RemotePort)
	dstAddr := fmt.Sprintf("%s:%d", id.LocalAddress.String(), id.LocalPort)

	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		log.Printf("[UDP] failed to create endpoint for %s: %v", dstAddr, tcpErr)
		return
	}

	localConn := gonet.NewUDPConn(&wq, ep)
	defer localConn.Close()

	// Dial UDP through SS proxy
	remotePC, err := t.proxy.DialUDP()
	if err != nil {
		log.Printf("[UDP] %s <-> %s: dial failed: %v", srcAddr, dstAddr, err)
		return
	}
	defer remotePC.Close()

	remote, err := net.ResolveUDPAddr("udp", dstAddr)
	if err != nil {
		log.Printf("[UDP] resolve %s: %v", dstAddr, err)
		return
	}

	log.Printf("[UDP] %s <-> %s", srcAddr, dstAddr)

	// Bidirectional packet relay
	pipePacket(localConn, remotePC, remote, udpSessionTimeout)
}

// Close shuts down the tunnel and releases resources.
func (t *Tunnel) Close() {
	t.endpoint.Close()
	t.stack.Close()
	t.stack.Wait()
}

// pipe copies data bidirectionally between two connections.
func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, relayBufferSize)
		io.CopyBuffer(b, a, buf)
		if tc, ok := b.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		}
		b.SetReadDeadline(time.Now().Add(tcpWaitTimeout))
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, relayBufferSize)
		io.CopyBuffer(a, b, buf)
		if tc, ok := a.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		}
		a.SetReadDeadline(time.Now().Add(tcpWaitTimeout))
	}()

	wg.Wait()
}

// pipePacket copies packets bidirectionally between two PacketConns.
func pipePacket(local, remote net.PacketConn, to net.Addr, timeout time.Duration) {
	var wg sync.WaitGroup
	wg.Add(2)

	// local -> remote
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			local.SetReadDeadline(time.Now().Add(timeout))
			n, _, err := local.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := remote.WriteTo(buf[:n], to); err != nil {
				return
			}
			remote.SetReadDeadline(time.Now().Add(timeout))
		}
	}()

	// remote -> local
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			remote.SetReadDeadline(time.Now().Add(timeout))
			n, _, err := remote.ReadFrom(buf)
			if err != nil {
				return
			}
			// Write back to local (source is the TUN side)
			if _, err := local.WriteTo(buf[:n], nil); err != nil {
				return
			}
			local.SetReadDeadline(time.Now().Add(timeout))
		}
	}()

	wg.Wait()
}
