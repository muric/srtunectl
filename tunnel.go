package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/socks"
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
	tcpConnectTimeout = 60 * time.Second
	tcpIdleTimeout    = 60 * time.Second // close direction after this much inactivity
	tcpHalfCloseWait  = 40 * time.Second
	udpSessionTimeout = 2 * time.Minute
	relayBufferSize   = 32 * 1024 // 32 KB per direction (matches io.Copy default)
	udpBufferSize     = 64 * 1024 // 64 KB for UDP (max IP packet size)
	metricsLogPeriod  = 30 * time.Second
	nicID             = 1
)

var bufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, relayBufferSize)
		return &buf
	},
}

var udpBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, udpBufferSize)
		return &buf
	},
}

var (
	activeTCPRelays        int64
	activeUDPRelays        int64
	tcpRelayTimeouts       uint64
	tcpRelayErrors         uint64
	udpRelayTimeouts       uint64
	udpRelayErrors         uint64
	udpCreateEndpointError uint64
)

// Tunnel connects a TUN device to a Shadowsocks proxy using gVisor netstack.
// It intercepts TCP/UDP packets from the TUN and relays them through the proxy.
type Tunnel struct {
	stack         *stack.Stack
	proxy         *SSProxy
	endpoint      *TUNEndpoint
	telemetryStop chan struct{}
	telemetryDone chan struct{}
	closeOnce     sync.Once
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
		stack:         s,
		proxy:         proxy,
		endpoint:      endpoint,
		telemetryStop: make(chan struct{}),
		telemetryDone: make(chan struct{}),
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
			atomic.AddUint64(&udpCreateEndpointError, 1)
			// Endpoint already exists — packet handled by existing session
			return true
		}
		go t.relayUDP(r.ID(), &wq, ep, time.Now())
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

	go t.telemetryLoop()

	return t, nil
}

// handleTCP handles a new TCP connection from the netstack.
// It dials the SS proxy and relays data bidirectionally.
func (t *Tunnel) handleTCP(r *tcp.ForwarderRequest) {
	atomic.AddInt64(&activeTCPRelays, 1)
	defer atomic.AddInt64(&activeTCPRelays, -1)

	startTime := time.Now()
	id := r.ID()
	srcAddr := fmt.Sprintf("%s:%d", id.RemoteAddress, id.RemotePort)
	dstAddr := fmt.Sprintf("%s:%d", id.LocalAddress, id.LocalPort)

	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
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
		log.Printf("[TCP] dial fail %s -> %s: %v", srcAddr, dstAddr, err)
		return
	}
	defer func() { _ = remoteConn.Close() }()

	log.Printf("[TCP] %s <-> %s ", srcAddr, dstAddr)

	// Bidirectional relay
	if err := pipe(localConn, remoteConn); err != nil {
		if isTimeoutError(err) {
			atomic.AddUint64(&tcpRelayTimeouts, 1)
			log.Printf("[TCP] %s <-> %s: relay timeout (after %v): %v", srcAddr, dstAddr, time.Since(startTime), err)
			return
		}
		atomic.AddUint64(&tcpRelayErrors, 1)
		log.Printf("[TCP] %s <-> %s: relay error (after %v): %v", srcAddr, dstAddr, time.Since(startTime), err)
	}
}

// relayUDP relays a UDP session through the SS proxy.
// The endpoint is already created and registered by the forwarder handler.
// arriveTime is when the first packet hit the forwarder (before goroutine start).
func (t *Tunnel) relayUDP(id stack.TransportEndpointID, wq *waiter.Queue, ep tcpip.Endpoint, arriveTime time.Time) {
	atomic.AddInt64(&activeUDPRelays, 1)
	defer atomic.AddInt64(&activeUDPRelays, -1)

	srcAddr := fmt.Sprintf("%s:%d", id.RemoteAddress.String(), id.RemotePort)
	dstAddr := fmt.Sprintf("%s:%d", id.LocalAddress.String(), id.LocalPort)

	localConn := gonet.NewUDPConn(wq, ep)
	defer func() { _ = localConn.Close() }()

	// Dial UDP through SS proxy
	remotePC, err := t.proxy.DialUDP()
	if err != nil {
		atomic.AddUint64(&udpRelayErrors, 1)
		log.Printf("[UDP] dial fail %s -> %s: %v", srcAddr, dstAddr, err)
		return
	}
	defer func() { _ = remotePC.Close() }()

	targetAddr := socks.ParseAddr(dstAddr)

	if err := pipePacket(localConn, remotePC, nil, targetAddr, udpSessionTimeout); err != nil {
		if isTimeoutError(err) {
			atomic.AddUint64(&udpRelayTimeouts, 1)
		} else {
			atomic.AddUint64(&udpRelayErrors, 1)
			log.Printf("[UDP] %s <-> %s: relay error: %v", srcAddr, dstAddr, err)
		}
	}
}

// pipe copies data bidirectionally between two connections.
// It handles TCP half-close (FIN) properly and enforces idle timeouts.
func pipe(a, b net.Conn) error {
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = a.Close()
			_ = b.Close()
		})
	}
	defer closeBoth()

	var wg sync.WaitGroup
	wg.Add(2)
	errCh := make(chan error, 2)

	relay := func(dst, src net.Conn) {
		defer wg.Done()
		defer closeBoth()

		pBuf := bufPool.Get().(*[]byte)
		// Ensure we use full capacity even if slice was put back as len 0
		buf := (*pBuf)[:cap(*pBuf)]

		defer func() {
			*pBuf = buf[:0]
			bufPool.Put(pBuf)
		}()

		for {
			_ = src.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
			n, err := src.Read(buf)

			if n > 0 {
				_ = dst.SetWriteDeadline(time.Now().Add(tcpIdleTimeout))
				if _, werr := dst.Write(buf[:n]); werr != nil {
					errCh <- werr
					return
				}
			}

			if err != nil {
				if errors.Is(err, io.EOF) {
					// half-close
					if hc, ok := dst.(interface{ CloseWrite() error }); ok {
						_ = hc.CloseWrite()
					}
					return
				}
				if !isTimeoutError(err) && !errors.Is(err, net.ErrClosed) {
					errCh <- err
				}
				return
			}
		}
	}

	go relay(b, a)
	go relay(a, b)

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

// pipePacket copies packets bidirectionally between two PacketConns.
// On any read/write error it closes both conns so the peer goroutine
// exits immediately instead of lingering until timeout.
func pipePacket(local, remote net.PacketConn, to net.Addr, targetAddr socks.Addr, timeout time.Duration) error {
	var wg sync.WaitGroup
	wg.Add(2)
	errCh := make(chan error, 2)

	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = local.Close()
			_ = remote.Close()
		})
	}

	relay := func(dst, src net.PacketConn, isLocal bool) {
		defer wg.Done()
		defer closeBoth()

		pBuf := udpBufPool.Get().(*[]byte)
		defer func() {
			// clear before returning
			for i := range *pBuf {
				(*pBuf)[i] = 0
			}
			udpBufPool.Put(pBuf)
		}()

		for {
			// create new slice from begining
			buf := (*pBuf)[:cap(*pBuf)]

			_ = src.SetReadDeadline(time.Now().Add(timeout))
			n, _, err := src.ReadFrom(buf)

			if n > 0 {
				// read only readed bytes
				data := buf[:n]

				var werr error
				if isLocal {
					if ssConn, ok := remote.(*ssPacketConn); ok {
						_, werr = ssConn.WriteToTarget(data, targetAddr)
					} else {
						_, werr = remote.WriteTo(data, to)
					}
				} else {
					_, werr = local.WriteTo(data, nil)
				}

				if werr != nil {
					if !isTimeoutError(werr) {
						errCh <- fmt.Errorf("write error: %w", werr)
					}
					return
				}
			}

			if err != nil {
				if !isTimeoutError(err) && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
					errCh <- fmt.Errorf("read error: %w", err)
				}
				return
			}
		}
	}

	go relay(remote, local, true)
	go relay(local, remote, false)

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

// Close shuts down the tunnel and the netstack.
func (t *Tunnel) Close() {
	t.closeOnce.Do(func() {
		close(t.telemetryStop)
		<-t.telemetryDone
		t.stack.Close()
		t.stack.Wait()
		if t.endpoint != nil {
			t.endpoint.Close()
		}
	})
}

// telemetryLoop logs tunnel statistics periodically.
func (t *Tunnel) telemetryLoop() {
	defer close(t.telemetryDone)
	ticker := time.NewTicker(metricsLogPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-t.telemetryStop:
			return
		case <-ticker.C:
			log.Printf("[Stats] TCP: %d, UDP: %d | Errs: TCP:%d, UDP:%d",
				atomic.LoadInt64(&activeTCPRelays), atomic.LoadInt64(&activeUDPRelays),
				atomic.LoadUint64(&tcpRelayErrors), atomic.LoadUint64(&udpRelayErrors))
		}
	}
}

// isTimeoutError returns true if the error is a network timeout.
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
