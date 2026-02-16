package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

const (
	defaultGoroutineCount = 4
	defaultDebug          = false
	defaultMTU            = 1500
	defaultSSMTU          = 1500
)

type Config struct {
	// Network
	Gateway          string
	Interface        string
	DefaultGateway   string
	DefaultInterface string
	GoroutineCount   int
	Debug            bool
	MTU              int // 0 = auto (1400 with SS, 1500 without)

	// Shadowsocks
	SSEnabled    bool
	SSServer     string
	SSServerPort int
	SSPassword   string
	SSMethod     string

	// Obfuscation
	ObfsMode string // "disable", "simple-obfs", "v2ray"
	ObfsHost string

	// V2Ray plugin (when ObfsMode == "v2ray")
	SSPlugin     string
	SSPluginOpts string
}

func readConfig(filename string) (Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return Config{}, err
	}
	defer func() {
		if cerr := file.Close(); cerr != nil {
			log.Printf("Error closing config file: %v", cerr)
		}
	}()

	config := Config{
		GoroutineCount: defaultGoroutineCount,
		Debug:          defaultDebug,
		ObfsMode:       "disable",
		SSMethod:       "aes-256-gcm",
	}

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if value == "" {
			continue
		}

		switch key {
		case "gateway":
			config.Gateway = value
		case "interface":
			config.Interface = value
		case "default_gw":
			config.DefaultGateway = value
		case "default_interface":
			config.DefaultInterface = value
		case "goroutine_count":
			config.GoroutineCount, err = strconv.Atoi(value)
			if err != nil {
				return Config{}, fmt.Errorf("invalid goroutine_count value '%s': %w", value, err)
			}
		case "debug":
			config.Debug, err = strconv.ParseBool(value)
			if err != nil {
				return Config{}, fmt.Errorf("invalid debug value '%s': %w", value, err)
			}
		case "mtu":
			config.MTU, err = strconv.Atoi(value)
			if err != nil {
				return Config{}, fmt.Errorf("invalid mtu value '%s': %w", value, err)
			}
		case "ss_enabled":
			config.SSEnabled, err = strconv.ParseBool(value)
			if err != nil {
				return Config{}, fmt.Errorf("invalid ss_enabled value '%s': %w", value, err)
			}
		case "ss_server":
			config.SSServer = value
		case "ss_server_port":
			config.SSServerPort, err = strconv.Atoi(value)
			if err != nil {
				return Config{}, fmt.Errorf("invalid ss_server_port value '%s': %w", value, err)
			}
		case "ss_password":
			config.SSPassword = value
		case "ss_method":
			config.SSMethod = value
		case "obfs_mode":
			config.ObfsMode = value
		case "obfs_host":
			config.ObfsHost = value
		case "ss_plugin":
			config.SSPlugin = value
		case "ss_plugin_opts":
			config.SSPluginOpts = value
		}
	}

	if err := scanner.Err(); err != nil {
		return Config{}, err
	}

	// Auto-detect MTU if not set
	if config.MTU == 0 {
		if config.SSEnabled {
			config.MTU = defaultSSMTU
		} else {
			config.MTU = defaultMTU
		}
	}

	return config, nil
}

// runOneshotMode creates a persistent TUN interface, adds routes and exits.
// TUN interface stays in the system after the process exits.
func runOneshotMode(config Config) {
	log.Println("Creating persistent TUN interface")
	if _, err := createTunInterface(config.Interface, true); err != nil {
		log.Fatalf("System error creating TUN: %v", err)
	}

	log.Println("Setting gateway IP on TUN interface")
	if err := setIpTunInterface(config.Interface, config.Gateway, config.MTU); err != nil {
		log.Fatalf("System error setting IP: %v", err)
	}

	stats := NewStats()
	defer func() {
		stats.Close()
		stats.PrintStats()
	}()

	if config.Interface != "" && config.Gateway != "" {
		log.Println("Adding routes for interface:", config.Interface)
		if err := addRoutesFromDir(mainRouteDir, config.Gateway, config.Interface, config.GoroutineCount, config.Debug, stats); err != nil {
			log.Printf("\033[31mError adding routes: %v\033[0m\n", err)
		}
	}

	if config.DefaultInterface != "" && config.DefaultGateway != "" {
		log.Println("Adding routes for default interface:", config.DefaultInterface)
		if err := addRoutesFromDir(defaultRouteDir, config.DefaultGateway, config.DefaultInterface, config.GoroutineCount, config.Debug, stats); err != nil {
			log.Printf("\033[31mError adding default routes: %v\033[0m\n", err)
		}
	}
}

// runDaemonMode creates a non-persistent TUN, starts SS client, adds routes,
// and blocks until SIGINT/SIGTERM. TUN is auto-destroyed on process exit.
func runDaemonMode(config Config) {
	if config.SSServer == "" || config.SSServerPort == 0 || config.SSPassword == "" {
		log.Fatalf("\033[31mShadowsocks is enabled but ss_server, ss_server_port, or ss_password is not set\033[0m")
	}

	log.Println("Creating non-persistent TUN interface (will be destroyed on exit)")
	tunFile, err := createTunInterface(config.Interface, false)
	if err != nil {
		log.Fatalf("System error creating TUN: %v", err)
	}

	log.Printf("Setting gateway IP and MTU=%d on TUN interface", config.MTU)
	if err := setIpTunInterface(config.Interface, config.Gateway, config.MTU); err != nil {
		log.Fatalf("System error setting IP: %v", err)
	}

	ssAddr := fmt.Sprintf("%s:%d", config.SSServer, config.SSServerPort)
	var pluginCmd *PluginProcess

	switch config.ObfsMode {
	case "v2ray":
		if config.SSPlugin == "" {
			log.Fatalf("\033[31mobfs_mode=v2ray but ss_plugin is not set\033[0m")
		}
		p, err := startPlugin(config.SSPlugin, config.SSPluginOpts,
			config.SSServer, config.SSServerPort)
		if err != nil {
			log.Fatalf("\033[31mFailed to start plugin: %v\033[0m", err)
		}
		ssAddr = p.localAddr
		pluginCmd = p
	case "simple-obfs":
		log.Printf("Using simple-obfs with host: %s", config.ObfsHost)
	case "disable", "":
	default:
		log.Fatalf("\033[31mUnknown obfs_mode: %s\033[0m", config.ObfsMode)
	}

	obfsForProxy := ""
	if config.ObfsMode == "simple-obfs" {
		obfsForProxy = "http"
	}

	proxy, err := NewSSProxy(ssAddr, config.SSMethod, config.SSPassword, obfsForProxy, config.ObfsHost)
	if err != nil {
		log.Fatalf("\033[31mFailed to create SS proxy: %v\033[0m", err)
	}

	tunDev, err := newTUNDeviceFromFile(tunFile, config.Interface)
	if err != nil {
		log.Fatalf("\033[31mFailed to initialize TUN device: %v\033[0m", err)
	}

	endpoint := NewTUNEndpoint(tunDev, uint32(config.MTU))
	tunnel, err := NewTunnel(proxy, endpoint)
	if err != nil {
		log.Fatalf("\033[31mFailed to create tunnel: %v\033[0m", err)
	}

	stats := NewStats()

	if config.Interface != "" && config.Gateway != "" {
		log.Println("Adding routes for interface:", config.Interface)
		if err := addRoutesFromDir(mainRouteDir, config.Gateway, config.Interface, config.GoroutineCount, config.Debug, stats); err != nil {
			log.Printf("\033[31mError adding routes: %v\033[0m\n", err)
		}
	}

	if config.DefaultInterface != "" && config.DefaultGateway != "" {
		log.Println("Adding routes for default interface:", config.DefaultInterface)
		if err := addRoutesFromDir(defaultRouteDir, config.DefaultGateway, config.DefaultInterface, config.GoroutineCount, config.Debug, stats); err != nil {
			log.Printf("\033[31mError adding default routes: %v\033[0m\n", err)
		}
	}

	defer func() {
		stats.Close()
		stats.PrintStats()
	}()

	log.Println("Daemon running. Press Ctrl+C to stop.")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	tunnel.Close()
	if pluginCmd != nil {
		stopPlugin(pluginCmd)
	}
}

func main() {
	config, err := readConfig("srtunectl.conf")
	if err != nil {
		log.Fatalf("\033[31mError reading configuration: %v\033[0m", err)
	}

	if !config.SSEnabled {
		runOneshotMode(config)
		return
	}

	runDaemonMode(config)
}
