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
	relayBufferSize   = 1024 * 1024
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

	// TCP performance tuning for proxy/streaming workloads.
	// gVisor defaults are optimized for containers, not high-throughput proxying.
	rcvBufOpt := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     4 << 10,   // 4 KB
		Default: 212 << 10, // 212 KB
		Max:     4 << 20,   // 4 MB
	}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcvBufOpt)

	sndBufOpt := tcpip.TCPSendBufferSizeRangeOption{
		Min:     4 << 10,   // 4 KB
		Default: 212 << 10, // 212 KB
		Max:     4 << 20,   // 4 MB
	}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sndBufOpt)

	// Enable Selective Acknowledgment for better loss recovery
	sackOpt := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sackOpt)

	// Enable receive buffer auto-tuning (grows window as needed)
	moderateOpt := tcpip.TCPModerateReceiveBufferOption(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &moderateOpt)

	// Use cubic congestion control (better for high-bandwidth links)
	ccOpt := tcpip.CongestionControlOption("cubic")
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &ccOpt)

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
	// CreateEndpoint is called synchronously to register the endpoint
	// before returning. This prevents "port is in use" race conditions
	// when multiple packets for the same flow arrive rapidly (e.g. QUIC).
	// The relay goroutine is spawned only after the endpoint is registered.
	udpForwarder := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			// Endpoint already exists — packet handled by existing session
			return true
		}
		go t.relayUDP(r.ID(), &wq, ep)
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
	defer func() { _ = localConn.Close() }()

	// Dial through SS proxy
	ctx, cancel := context.WithTimeout(context.Background(), tcpConnectTimeout)
	defer cancel()

	remoteConn, err := t.proxy.DialContext(ctx, dstAddr)
	if err != nil {
		log.Printf("[TCP] %s <-> %s: dial failed: %v", srcAddr, dstAddr, err)
		return
	}
	defer func() { _ = remoteConn.Close() }()

	log.Printf("[TCP] %s <-> %s", srcAddr, dstAddr)

	// Bidirectional relay
	//pipe(localConn, remoteConn)
	if err := pipe(localConn, remoteConn); err != nil {
    		log.Printf("[TCP] %s <-> %s: relay error: %v", srcAddr, dstAddr, err)
    		return
	}

}

// relayUDP relays a UDP session through the SS proxy.
// The endpoint is already created and registered by the forwarder handler.
func (t *Tunnel) relayUDP(id stack.TransportEndpointID, wq *waiter.Queue, ep tcpip.Endpoint) {
	srcAddr := fmt.Sprintf("%s:%d", id.RemoteAddress.String(), id.RemotePort)
	dstAddr := fmt.Sprintf("%s:%d", id.LocalAddress.String(), id.LocalPort)

	localConn := gonet.NewUDPConn(wq, ep)
	defer func() { _ = localConn.Close() }()

	// Dial UDP through SS proxy
	remotePC, err := t.proxy.DialUDP()
	if err != nil {
		log.Printf("[UDP] %s <-> %s: dial failed: %v", srcAddr, dstAddr, err)
		return
	}
	defer func() { _ = remotePC.Close() }()

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
// Order: close stack first (drains connections), then endpoint (closes TUN fd).
// stack.Wait() may call endpoint.Close() again — safe due to closeOnce.
func (t *Tunnel) Close() {
	t.stack.Close()
	t.stack.Wait()
	t.endpoint.Close()
}

// pipe copies data bidirectionally between two net.Conn.
// It runs two goroutines that copy in opposite directions and waits
// for both to finish. Improvements over a naive implementation:
// - Captures and returns the first non-EOF error from io.CopyBuffer so
//   callers can react to I/O failures.
// - Uses sync.Once to ensure CloseWrite (half-close) is called only once
//   per connection if supported, otherwise falls back to closing the
//   whole connection (best-effort).
// - Sets a read deadline after closing to unblock the peer's read loop.
// - Enables TCP keep-alive (best-effort) for long-lived connections.
// - Allocates a separate buffer per goroutine to avoid sharing state.
func pipe(a, b net.Conn) error {
	var wg sync.WaitGroup
	wg.Add(2)

	// channel to capture errors from both copy directions
	errCh := make(chan error, 2)

	// closable type for half-close support
	type closable interface {
		CloseWrite() error
	}
	var onceA, onceB sync.Once

	copyFunc := func(dst, src net.Conn, once *sync.Once, name string) {
		defer wg.Done()
		buf := make([]byte, relayBufferSize)
		_, err := io.CopyBuffer(dst, src, buf)
		if err != nil && err != io.EOF {
			errCh <- fmt.Errorf("%s copy error: %w", name, err)
		}
		// attempt half-close, fall back to full close if not supported
		if tc, ok := dst.(closable); ok {
			once.Do(func() { _ = tc.CloseWrite() })
		} else {
			_ = dst.Close()
		}
		// set read deadline to unblock peer reader
		_ = dst.SetReadDeadline(time.Now().Add(tcpWaitTimeout))
	}

	// enable TCP keep-alive when possible (best-effort)
	if tc, ok := a.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	if tc, ok := b.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}

	go copyFunc(b, a, &onceB, "a->b")
	go copyFunc(a, b, &onceA, "b->a")

	wg.Wait()
	close(errCh)

	// return first non-nil error if present
	for e := range errCh {
		if e != nil {
			return e
		}
	}
	return nil
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
			_ = local.SetReadDeadline(time.Now().Add(timeout))
			n, _, err := local.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := remote.WriteTo(buf[:n], to); err != nil {
				return
			}
			_ = remote.SetReadDeadline(time.Now().Add(timeout))
		}
	}()

	// remote -> local
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			_ = remote.SetReadDeadline(time.Now().Add(timeout))
			n, _, err := remote.ReadFrom(buf)
			if err != nil {
				return
			}
			// Write back to local (source is the TUN side)
			if _, err := local.WriteTo(buf[:n], nil); err != nil {
				return
			}
			_ = local.SetReadDeadline(time.Now().Add(timeout))
		}
	}()

	wg.Wait()
}
