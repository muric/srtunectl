package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

// PluginProcess represents a running SIP003-compatible plugin.
type PluginProcess struct {
	cmd       *exec.Cmd
	localAddr string // "host:port" where the plugin listens
}

// startPlugin starts a SIP003-compatible plugin (e.g. v2ray-plugin).
// The plugin creates a tunnel between a local port and the remote SS server,
// applying obfuscation to the traffic.
//
// SIP003 protocol:
// - Plugin receives config via environment variables
// - Plugin listens on SS_LOCAL_HOST:SS_LOCAL_PORT
// - Plugin forwards traffic to SS_REMOTE_HOST:SS_REMOTE_PORT
// - The SS proxy connects to the local port instead of the server directly
func startPlugin(plugin, pluginOpts string, remoteHost string, remotePort int) (*PluginProcess, error) {
	// Find a free local port for the plugin to listen on
	localPort, err := findFreePort()
	if err != nil {
		return nil, fmt.Errorf("find free port: %w", err)
	}
	localHost := "127.0.0.1"
	localAddr := net.JoinHostPort(localHost, strconv.Itoa(localPort))

	// Set SIP003 environment variables
	env := append(os.Environ(),
		fmt.Sprintf("SS_REMOTE_HOST=%s", remoteHost),
		fmt.Sprintf("SS_REMOTE_PORT=%d", remotePort),
		fmt.Sprintf("SS_LOCAL_HOST=%s", localHost),
		fmt.Sprintf("SS_LOCAL_PORT=%d", localPort),
	)
	if pluginOpts != "" {
		env = append(env, fmt.Sprintf("SS_PLUGIN_OPTIONS=%s", pluginOpts))
	}

	cmd := exec.Command(plugin)
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start plugin %s: %w", plugin, err)
	}

	// Wait a bit for the plugin to start listening
	time.Sleep(500 * time.Millisecond)

	// Verify plugin is still running
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		return nil, fmt.Errorf("plugin %s exited immediately with code %d", plugin, cmd.ProcessState.ExitCode())
	}

	log.Printf("Plugin %s started (pid=%d), listening on %s", plugin, cmd.Process.Pid, localAddr)

	return &PluginProcess{
		cmd:       cmd,
		localAddr: localAddr,
	}, nil
}

// stopPlugin gracefully stops a running plugin process.
// Sends SIGTERM first, waits up to 5 seconds, then SIGKILL.
func stopPlugin(p *PluginProcess) {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return
	}

	log.Printf("Stopping plugin (pid=%d)...", p.cmd.Process.Pid)

	// Send SIGTERM
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		log.Printf("Failed to send SIGTERM to plugin: %v", err)
		_ = p.cmd.Process.Kill()
		return
	}

	// Wait with timeout
	done := make(chan error, 1)
	go func() {
		done <- p.cmd.Wait()
	}()

	select {
	case <-done:
		log.Println("Plugin stopped gracefully")
	case <-time.After(5 * time.Second):
		log.Println("Plugin did not stop in time, sending SIGKILL")
		_ = p.cmd.Process.Kill()
		<-done
	}
}

// findFreePort returns a free TCP port by briefly listening on :0.
func findFreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port, nil
}
