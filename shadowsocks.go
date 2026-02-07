package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

const (
	ssTCPConnectTimeout = 5 * time.Second
)

// SSProxy implements a Shadowsocks proxy that can dial TCP and UDP
// connections through an SS server with optional simple-obfs support.
type SSProxy struct {
	addr     string      // SS server address (or plugin local address)
	cipher   core.Cipher // AEAD cipher for encryption
	obfsMode string      // "http", "tls", or "" (no obfuscation)
	obfsHost string      // host to impersonate for obfuscation
}

// NewSSProxy creates a new Shadowsocks proxy.
// addr is "host:port" of the SS server (or plugin local address).
// method is the cipher name (e.g. "aes-256-gcm").
// obfsMode is "http", "tls", or "" for no obfuscation.
func NewSSProxy(addr, method, password, obfsMode, obfsHost string) (*SSProxy, error) {
	cipher, err := core.PickCipher(method, nil, password)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cipher %s: %w", method, err)
	}

	return &SSProxy{
		addr:     addr,
		cipher:   cipher,
		obfsMode: obfsMode,
		obfsHost: obfsHost,
	}, nil
}

// DialContext establishes a TCP connection through the Shadowsocks server
// to the given target address (host:port).
func (ss *SSProxy) DialContext(ctx context.Context, targetAddr string) (net.Conn, error) {
	// Connect to SS server
	dialer := net.Dialer{Timeout: ssTCPConnectTimeout}
	c, err := dialer.DialContext(ctx, "tcp", ss.addr)
	if err != nil {
		return nil, fmt.Errorf("connect to SS server %s: %w", ss.addr, err)
	}

	// Apply simple-obfs if configured
	if ss.obfsMode != "" {
		c = applyObfs(c, ss.obfsMode, ss.obfsHost, ss.addr)
	}

	// Wrap connection with SS cipher
	c = ss.cipher.StreamConn(c)

	// Write target address in SOCKS5 format (SS protocol standard)
	tgt := socks.ParseAddr(targetAddr)
	if tgt == nil {
		c.Close()
		return nil, fmt.Errorf("failed to parse target address: %s", targetAddr)
	}
	if _, err := c.Write(tgt); err != nil {
		c.Close()
		return nil, fmt.Errorf("failed to write target address: %w", err)
	}

	return c, nil
}

// DialUDP creates a UDP PacketConn through the Shadowsocks server.
func (ss *SSProxy) DialUDP() (net.PacketConn, error) {
	pc, err := net.ListenPacket("udp", "")
	if err != nil {
		return nil, fmt.Errorf("listen UDP: %w", err)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", ss.addr)
	if err != nil {
		pc.Close()
		return nil, fmt.Errorf("resolve SS server UDP address %s: %w", ss.addr, err)
	}

	// Wrap with SS cipher
	pc = ss.cipher.PacketConn(pc)

	return &ssPacketConn{PacketConn: pc, rAddr: udpAddr}, nil
}

// ssPacketConn wraps a PacketConn to always send to the SS server
// with the target address prepended in SOCKS5 format.
type ssPacketConn struct {
	net.PacketConn
	rAddr net.Addr
}

func (pc *ssPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	// Prepend SOCKS5-format target address
	tgt := socks.ParseAddr(addr.String())
	if tgt == nil {
		return 0, fmt.Errorf("failed to parse target address: %s", addr)
	}

	buf := make([]byte, len(tgt)+len(b))
	copy(buf, tgt)
	copy(buf[len(tgt):], b)

	return pc.PacketConn.WriteTo(buf, pc.rAddr)
}

func (pc *ssPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, _, err := pc.PacketConn.ReadFrom(b)
	if err != nil {
		return 0, nil, err
	}

	// Parse target address from response
	tgt := socks.SplitAddr(b[:n])
	if tgt == nil {
		return 0, nil, fmt.Errorf("failed to parse SOCKS address from response")
	}

	// Resolve the SOCKS address to a UDP address
	udpAddr, resolveErr := net.ResolveUDPAddr("udp", tgt.String())
	if resolveErr != nil {
		return 0, nil, fmt.Errorf("resolve response address: %w", resolveErr)
	}

	// Return data after the address header
	addrLen := len(tgt)
	copy(b, b[addrLen:n])
	return n - addrLen, udpAddr, err
}

// applyObfs wraps a connection with simple-obfs (HTTP or TLS mode).
func applyObfs(c net.Conn, mode, host, serverAddr string) net.Conn {
	// TODO: implement simple-obfs wrapper
	// For now, return the connection as-is.
	// simple-obfs will be implemented as a separate module.
	return c
}
