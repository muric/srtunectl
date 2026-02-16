package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
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
	tcpHalfCloseWait  = 75 * time.Second
	udpSessionTimeout = 2 * time.Minute
	relayBufferSize   = 32 * 1024 // 32 KB per direction (matches io.Copy default)
	metricsLogPeriod  = 30 * time.Second
	nicID             = 1
)

var bufPool = sync.Pool{
	New: func() any {
		return make([]byte, relayBufferSize)
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
	defer localConn.Close()

	// Dial through SS proxy
	ctx, cancel := context.WithTimeout(context.Background(), tcpConnectTimeout)
	defer cancel()

	remoteConn, err := t.proxy.DialContext(ctx, dstAddr)
	if err != nil {
		log.Printf("[TCP] dial fail %s -> %s: %v", srcAddr, dstAddr, err)
		return
	}
	defer remoteConn.Close()

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
	_ = startTime
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
	defer localConn.Close()

	// Dial UDP through SS proxy
	remotePC, err := t.proxy.DialUDP()
	if err != nil {
		log.Printf("[UDP] dial fail %s -> %s: %v", srcAddr, dstAddr, err)
		return
	}
	defer remotePC.Close()

	remote, err := net.ResolveUDPAddr("udp", dstAddr)
	if err != nil {
		return
	}
	targetAddr := socks.ParseAddr(dstAddr)
	if targetAddr == nil {
		log.Printf("[UDP] failed to parse target addr: %s", dstAddr)
		return
	}

	log.Printf("[UDP] %s <-> %s (setup %v)", srcAddr, dstAddr, time.Since(arriveTime))

	// Bidirectional packet relay
	if err := pipePacket(localConn, remotePC, remote, targetAddr, udpSessionTimeout); err != nil {
		if isTimeoutError(err) {
			atomic.AddUint64(&udpRelayTimeouts, 1)
			log.Printf("[UDP] %s <-> %s: relay timeout: %v", srcAddr, dstAddr, err)
			return
		}
		atomic.AddUint64(&udpRelayErrors, 1)
		log.Printf("[UDP] %s <-> %s: relay error: %v", srcAddr, dstAddr, err)
	}
}

// Close shuts down the tunnel and releases resources.
// Order: close stack first (drains connections), then endpoint (closes TUN fd).
// stack.Wait() may call endpoint.Close() again — safe due to closeOnce.
func (t *Tunnel) Close() {
	t.closeOnce.Do(func() {
		close(t.telemetryStop)
		<-t.telemetryDone
		t.stack.Close()
		t.stack.Wait()
		t.endpoint.Close()
	})
}

// idleReader wraps a net.Conn and resets the read deadline before every
// Read call. As long as data keeps arriving within tcpIdleTimeout the
// connection stays alive. Only when the source goes silent for the full
// idle period does the Read return a timeout error.
type idleReader struct {
	conn        net.Conn
	timeout     time.Duration
	lastRefresh time.Time
}

func (r *idleReader) Read(p []byte) (int, error) {
	now := time.Now()
	if now.Sub(r.lastRefresh) > r.timeout/2 {
		_ = r.conn.SetReadDeadline(now.Add(r.timeout))
		r.lastRefresh = now
	}
	return r.conn.Read(p)
}

type timeoutWriter struct {
	net.Conn
	timeout time.Duration
}

func (c *timeoutWriter) Write(p []byte) (int, error) {
	if c.timeout > 0 {
		_ = c.Conn.SetWriteDeadline(time.Now().Add(c.timeout))
	}
	return c.Conn.Write(p)
}

type halfCloser interface {
	CloseWrite() error
}

// set keepalive to tcp connetction
func enableKeepAlive(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(10 * time.Second)
	}
}

func copyFunc(dst, src net.Conn, desc string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dstChan := make(chan []byte, 16)
	srcChan := make(chan error, 1)

	go func() {
		defer close(srcChan)
		buffer := make([]byte, 4096)
		for {
			n, err := src.Read(buffer)
			if err != nil {
				srcChan <- err
				return
			}
			select {
			case dstChan <- buffer[:n]:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		defer close(dstChan)
		buffer := make([]byte, 4096)
		for {
			_, err := dst.Write(buffer)
			if err != nil {
				srcChan <- err
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
		}
	}()

	for {
		select {
		case data, ok := <-dstChan:
			if !ok {
				return
			}
			_, err := dst.Write(data)
			if err != nil {
				srcChan <- err
				return
			}
		case err := <-srcChan:
			log.Printf("%s copy error: %v", desc, err)
			_ = dst.Close()
			_ = src.Close()
			return
		}
	}
}

// pipe copies data bidirectionally between two net.Conn and waits
// for both directions to finish. Returns the first non-EOF error.
//
// Each direction uses idleReader: read deadline is reset before every
// Read, so a connection stays open as long as data flows. When one
// direction finishes (client done sending), the other keeps running
// until the remote side closes or goes idle for tcpIdleTimeout.
//
// If the connection supports half-close (CloseWrite), a TCP FIN is
// sent to signal the peer. SS cipher wrappers don't support it —
// that's fine, the idle timeout handles cleanup without killing
// the reverse direction.
//
// Both connections are closed by the caller (handleTCP defers)
// after pipe returns.
/*
func pipe(a, b net.Conn) error {
	var wg sync.WaitGroup
	wg.Add(2)

	errCh := make(chan error, 2)

	copyFunc := func(dst, src net.Conn, name string) {
		defer wg.Done()

		buf := bufPool.Get().([]byte)
		defer bufPool.Put(buf)

		reader := &idleReader{conn: src, timeout: tcpIdleTimeout}

		_, err := io.CopyBuffer(dst, reader, buf)

		if err != nil && err != io.EOF {
			errCh <- fmt.Errorf("%s copy error: %w", name, err)

			// TcpIdletimout closing
			_ = dst.Close()
			_ = src.Close()
			return
		}
		// Clean EOF: signal peer that this direction is done via
		// half-close if supported. SS cipher wrappers don't implement
		// CloseWrite. In that case cap post-EOF wait to tcpHalfCloseWait
		// to avoid keeping dead relay tails for full tcpIdleTimeout.
		if tc, ok := dst.(halfCloser); ok {
			_ = tc.CloseWrite()
		} else {
			_ = dst.SetReadDeadline(time.Now().Add(tcpHalfCloseWait))
		}
	}

	enableKeepAlive(a)
	enableKeepAlive(b)

	go copyFunc(b, a, "a->b")
	go copyFunc(a, b, "b->a")

	wg.Wait()
	close(errCh)

	// return error if exist
	for e := range errCh {
		if e != nil {
			return e
		}
	}
	return nil
}*/
func pipe(a, b net.Conn) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	srcChan := make(chan []byte, 16)
	dstChan := make(chan error, 2)

	go func() {
		buffer := make([]byte, 4096)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			n, err := a.Read(buffer)
			if err != nil && !strings.Contains(err.Error(), "EOF") {
				dstChan <- err
				return
			}
			select {
			case srcChan <- buffer[:n]:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		for data := range srcChan {
			_, err := b.Write(data)
			if err != nil && !strings.Contains(err.Error(), "EOF") {
				dstChan <- err
				return
			}
		}
	}()

	select {
	case err := <-dstChan:
		if err == context.DeadlineExceeded {
			log.Println("Pipe operation timed out")
		} else {
			log.Printf("Pipe error: %v", err)
		}
		return err
	case <-ctx.Done():
		log.Println("Pipe operation cancelled")
		return ctx.Err()
	}
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

	// local -> remote
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			_ = local.SetReadDeadline(time.Now().Add(timeout))
			n, _, err := local.ReadFrom(buf)
			if err != nil {
				errCh <- fmt.Errorf("local->remote read: %w", err)
				closeBoth()
				return
			}
			if ssConn, ok := remote.(*ssPacketConn); ok {
				if _, err := ssConn.WriteToTarget(buf[:n], targetAddr); err != nil {
					errCh <- fmt.Errorf("local->remote write: %w", err)
					closeBoth()
					return
				}
				continue
			}
			if _, err := remote.WriteTo(buf[:n], to); err != nil {
				errCh <- fmt.Errorf("local->remote write: %w", err)
				closeBoth()
				return
			}
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
				errCh <- fmt.Errorf("remote->local read: %w", err)
				closeBoth()
				return
			}
			// Write back to local (source is the TUN side)
			if _, err := local.WriteTo(buf[:n], nil); err != nil {
				errCh <- fmt.Errorf("remote->local write: %w", err)
				closeBoth()
				return
			}
		}
	}()

	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *Tunnel) telemetryLoop() {
	ticker := time.NewTicker(metricsLogPeriod)
	defer func() {
		ticker.Stop()
		close(t.telemetryDone)
	}()
	for {
		select {
		case <-t.telemetryStop:
			return
		case <-ticker.C:
			pkts, readErrs, icmpReplies := snapshotTUNStats()
			log.Printf(
				"[METRICS] active_tcp=%d active_udp=%d tcp_timeouts=%d tcp_errors=%d udp_timeouts=%d udp_errors=%d udp_create_endpoint_errors=%d tun_packets=%d tun_read_errors=%d icmp_replies=%d",
				atomic.LoadInt64(&activeTCPRelays),
				atomic.LoadInt64(&activeUDPRelays),
				atomic.LoadUint64(&tcpRelayTimeouts),
				atomic.LoadUint64(&tcpRelayErrors),
				atomic.LoadUint64(&udpRelayTimeouts),
				atomic.LoadUint64(&udpRelayErrors),
				atomic.LoadUint64(&udpCreateEndpointError),
				pkts,
				readErrs,
				icmpReplies,
			)
		}
	}
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
