package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/vishvananda/netlink"
)

const (
	TUNSETIFF                = 0x400454ca
	IFF_TUN                  = 0x0001
	IFF_NO_PI                = 0x1000
	TUNSETPERSIST            = 0x400454cb
	duplicatesFlushThreshold = 10000
	duplicatesChanBuffer     = 50000
	defaultGoroutineCount    = 100
	defaultDebug             = false
	mainRouteDir             = "data"
	defaultRouteDir          = "default_route"
	duplicatesFilePrefix     = "/tmp/route_duplicates_"
)

type ifreq struct {
	ifrName  [16]byte
	ifrFlags uint16
}

type Config struct {
	Gateway          string
	Interface        string
	DefaultGateway   string
	DefaultInterface string
	GoroutineCount   int
	Debug            bool
}

type Stats struct {
	Success            int64
	AlreadyExist       int64
	NetworkUnreachable int64
	OperationNotPermit int64
	InvalidArgument    int64
	NoRouteToHost      int64
	UnknownError       int64

	dupChan     chan string
	writerDone  chan struct{}
	duplicatesFile *os.File
	filename    string
	closeOnce   sync.Once

	// count of duplicates that could not be enqueued due to a full channel
	DupDropped int64
}

func NewStats() *Stats {
	filename := fmt.Sprintf("%s%s.log", duplicatesFilePrefix, time.Now().Format("2006-01-02_15-04-05"))
	s := &Stats{
		dupChan:    make(chan string, duplicatesChanBuffer),
		writerDone: make(chan struct{}),
		filename:   filename,
	}
	go s.duplicatesWriter()
	return s
}

func (s *Stats) duplicatesWriter() {
	buffer := make([]string, 0, duplicatesFlushThreshold)

	flush := func() {
		if len(buffer) == 0 {
			return
		}

		if s.duplicatesFile == nil {
			// Use CreateTemp to avoid predictable filename issues
			file, err := os.CreateTemp(filepath.Dir(s.filename), filepath.Base(s.filename)+"_*")
			if err != nil {
				// fallback to Create with original filename
				file, err = os.Create(s.filename)
				if err != nil {
					log.Printf("Error creating duplicates file: %v\n", err)
					buffer = buffer[:0]
					return
				}
			}
			s.duplicatesFile = file
		}

		writer := bufio.NewWriter(s.duplicatesFile)
		for _, dup := range buffer {
			if _, err := writer.WriteString(dup); err != nil {
				log.Printf("Error writing duplicate: %v", err)
			}
			if err := writer.WriteByte('\n'); err != nil {
				log.Printf("Error writing newline: %v", err)
			}
		}
		if err := writer.Flush(); err != nil {
			log.Printf("Error flushing duplicates file: %v", err)
		}
		buffer = buffer[:0]
	}

	for route := range s.dupChan {
		buffer = append(buffer, route)
		if len(buffer) >= duplicatesFlushThreshold {
			flush()
		}
	}

	flush()

	if s.duplicatesFile != nil {
		if err := s.duplicatesFile.Close(); err != nil {
			log.Printf("Error closing duplicates file: %v", err)
		}
		log.Printf("Duplicates written to: %s", s.duplicatesFile.Name())
	}

	close(s.writerDone)
}

func (s *Stats) AddSuccess() {
	atomic.AddInt64(&s.Success, 1)
}

func (s *Stats) AddAlreadyExist(route string) {
	atomic.AddInt64(&s.AlreadyExist, 1)
	// Non-blocking send to avoid blocking worker goroutines if writer lags
	select {
	case s.dupChan <- route:
	default:
		atomic.AddInt64(&s.DupDropped, 1)
	}
}

func (s *Stats) AddError(errType string) {
	switch errType {
	case "network_unreachable":
		atomic.AddInt64(&s.NetworkUnreachable, 1)
	case "operation_not_permitted":
		atomic.AddInt64(&s.OperationNotPermit, 1)
	case "invalid_argument":
		atomic.AddInt64(&s.InvalidArgument, 1)
	case "no_route_to_host":
		atomic.AddInt64(&s.NoRouteToHost, 1)
	case "unknown":
		atomic.AddInt64(&s.UnknownError, 1)
	case "no_such_device":
		// treat as unknown for counting purposes if desired
		atomic.AddInt64(&s.UnknownError, 1)
	}
}

func (s *Stats) PrintStats() {
	success := atomic.LoadInt64(&s.Success)
	alreadyExist := atomic.LoadInt64(&s.AlreadyExist)
	networkUnreachable := atomic.LoadInt64(&s.NetworkUnreachable)
	operationNotPermit := atomic.LoadInt64(&s.OperationNotPermit)
	invalidArgument := atomic.LoadInt64(&s.InvalidArgument)
	noRouteToHost := atomic.LoadInt64(&s.NoRouteToHost)
	unknownError := atomic.LoadInt64(&s.UnknownError)
	dropped := atomic.LoadInt64(&s.DupDropped)

	var sb strings.Builder
	sb.WriteString("\n========== Statistics ==========\n")
	fmt.Fprintf(&sb, "Successfully added: %d\n", success)
	fmt.Fprintf(&sb, "Already existed (skipped): %d\n", alreadyExist)

	if networkUnreachable > 0 {
		fmt.Fprintf(&sb, "Network unreachable: %d\n", networkUnreachable)
	}
	if operationNotPermit > 0 {
		fmt.Fprintf(&sb, "Operation not permitted: %d\n", operationNotPermit)
	}
	if invalidArgument > 0 {
		fmt.Fprintf(&sb, "Invalid argument: %d\n", invalidArgument)
	}
	if noRouteToHost > 0 {
		fmt.Fprintf(&sb, "No route to host: %d\n", noRouteToHost)
	}
	if unknownError > 0 {
		fmt.Fprintf(&sb, "Unknown errors: %d\n", unknownError)
	}
	if dropped > 0 {
		fmt.Fprintf(&sb, "Duplicate entries dropped (writer lag): %d\n", dropped)
	}

	totalErrors := alreadyExist + networkUnreachable + operationNotPermit + invalidArgument + noRouteToHost + unknownError
	fmt.Fprintf(&sb, "Total processed: %d\n", success+totalErrors)
	sb.WriteString("================================")

	log.Print(sb.String())
}

func (s *Stats) Close() {
	s.closeOnce.Do(func() {
		close(s.dupChan)
		<-s.writerDone
	})
}

func classifyError(err error) string {
	if err == nil {
		return "unknown"
	}
	errStr := err.Error()

	if strings.Contains(errStr, "file exists") || strings.Contains(errStr, "File exists") {
		return "file_exists"
	}
	if strings.Contains(errStr, "network is unreachable") {
		return "network_unreachable"
	}
	if strings.Contains(errStr, "no such device") {
		return "no_such_device"
	}
	if strings.Contains(errStr, "operation not permitted") {
		return "operation_not_permitted"
	}
	if strings.Contains(errStr, "invalid argument") {
		return "invalid_argument"
	}
	if strings.Contains(errStr, "no route to host") {
		return "no_route_to_host"
	}

	// try to unwrap syscall.Errno if possible
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.EEXIST:
			return "file_exists"
		case syscall.ENETUNREACH:
			return "network_unreachable"
		case syscall.EPERM:
			return "operation_not_permitted"
		case syscall.EINVAL:
			return "invalid_argument"
		case syscall.EHOSTUNREACH:
			return "no_route_to_host"
		}
	}

	return "unknown"
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
	}
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

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
		}
	}

	if err := scanner.Err(); err != nil {
		return Config{}, err
	}

	return config, nil
}

func createTunInterface(ifName string) error {
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := file.Close(); cerr != nil {
			log.Printf("Error closing /dev/net/tun: %v", cerr)
		}
	}()

	ifr := ifreq{
		ifrFlags: IFF_TUN | IFF_NO_PI,
	}
	copy(ifr.ifrName[:], ifName)

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(TUNSETIFF), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		if errno == syscall.EEXIST || errno == syscall.EBUSY {
			fmt.Println("Interface already exists")
			return nil
		}
		return errno
	}

	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(TUNSETPERSIST), 1)
	if errno != 0 {
		return errno
	}

	log.Printf("Interface %s is now persistent", ifName)
	return nil
}

func setIpTunInterface(ifName, gateway string) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("interface not found: %w", err)
	}

	// Accept both plain IP and CIDR; if plain IP -> use /24 for IPv4 (legacy behavior) or /128 for IPv6
	var addr *netlink.Addr
	if strings.Contains(gateway, "/") {
		a, err := netlink.ParseAddr(gateway)
		if err != nil {
			return fmt.Errorf("failed to parse ip: %w", err)
		}
		addr = a
	} else {
		ip := net.ParseIP(gateway)
		if ip == nil {
			return fmt.Errorf("failed to parse ip: %s", gateway)
		}
		var mask net.IPMask
		if ip.To4() == nil {
			mask = net.CIDRMask(128, 128)
		} else {
			mask = net.CIDRMask(24, 32)
		}
		a := &netlink.Addr{IPNet: &net.IPNet{IP: ip, Mask: mask}}
		addr = a
	}

	err = netlink.AddrAdd(link, addr)
	if err != nil {
		if errors.Is(err, syscall.EEXIST) {
			log.Printf("IP %s already set up on interface %s", addr.IP, link.Attrs().Name)
		} else {
			return fmt.Errorf("failed to set up ip: %w", err)
		}
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up interface: %w", err)
	}
	return nil
}

func addRoute(destination string, gwIP net.IP, ifaceIndex int) error {
	var ipNet *net.IPNet

	if _, parsedNet, err := net.ParseCIDR(destination); err != nil {
		ip := net.ParseIP(destination)
		if ip == nil {
			return fmt.Errorf("error parsing destination %s: %w", destination, err)
		}
		// choose mask based on IP family
		if ip.To4() == nil {
			ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
		} else {
			ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
		}
	} else {
		ipNet = parsedNet
	}

	route := &netlink.Route{
		Dst:       ipNet,
		Gw:        gwIP,
		LinkIndex: ifaceIndex,
	}

	if err := netlink.RouteAdd(route); err != nil {
		return fmt.Errorf("error adding route %s: %w", destination, err)
	}

	return nil
}

func addRoutesFromDir(dir, gateway, ifaceName string, goroutineCount int, debug bool, stats *Stats) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		log.Printf("Directory %s does not exist — skipping\n", dir)
		return nil
	}

	// Cache interface lookup and gateway parsing
	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		if strings.Contains(err.Error(), "Link not found") {
			log.Fatalf("\033[31mConfiguration error: interface '%s' does not exist. Check 'interface' or 'default_interface' in config.\033[0m\n", ifaceName)
		}
		return fmt.Errorf("error getting interface %s: %w", ifaceName, err)
	}
	ifaceIndex := iface.Attrs().Index
	gwIP := net.ParseIP(gateway)
	if gwIP == nil {
		// try parse as CIDR and extract IP
		if ipStr := strings.SplitN(gateway, "/", 2)[0]; ipStr != "" {
			gwIP = net.ParseIP(ipStr)
		}
		if gwIP == nil {
			return fmt.Errorf("invalid gateway IP: %s", gateway)
		}
	}

	var jsonFiles []string

	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".json" {
			// store full path (was a bug: stored only info.Name())
			jsonFiles = append(jsonFiles, path)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("error reading folder %s: %w", dir, err)
	}

	if len(jsonFiles) == 0 {
		log.Printf("No route files found in %s — skipping\n", dir)
		return nil
	}

	for _, filePath := range jsonFiles {
		log.Println("Processing:", filePath)
		data, err := os.ReadFile(filePath)
		if err != nil {
			log.Printf("\033[31mError reading file %s: %v\033[0m\n", filePath, err)
			continue
		}

		var destinations []string
		if err := json.Unmarshal(data, &destinations); err != nil {
			log.Printf("\033[31mError parsing JSON %s: %v\033[0m\n", filePath, err)
			continue
		}

		var wg sync.WaitGroup
		sem := make(chan struct{}, goroutineCount)

		for _, dest := range destinations {
			wg.Add(1)
			sem <- struct{}{}
			go func(d string) {
				defer wg.Done()
				defer func() { <-sem }()
				if err := addRoute(d, gwIP, ifaceIndex); err != nil {
					errType := classifyError(err)
					switch errType {
					case "file_exists":
						stats.AddAlreadyExist(fmt.Sprintf("%s via %s dev %s", d, gateway, ifaceName))
					case "no_such_device":
						log.Fatalf("\033[31mConfiguration error: interface '%s' does not exist. Check 'interface' or 'default_interface' in config.\033[0m\n", ifaceName)
					default:
						stats.AddError(errType)
						if debug {
							log.Printf("\033[31mError adding route for %s via %s dev %s: %v\033[0m\n", d, gateway, ifaceName, err)
						}
					}
				} else {
					stats.AddSuccess()
				}
			}(dest)
		}

		wg.Wait()
	}
	return nil
}

func main() {
	config, err := readConfig("iproute.conf")
	if err != nil {
		log.Fatalf("\033[31mError reading configuration: %v\033[0m", err)
	}

	// create tun interface from config
	if config.Interface != "" {
		log.Println("create tun interface from config")
		if err := createTunInterface(config.Interface); err != nil {
			log.Fatalf("System error ioctl: %v", err)
		}
		// set tun interface ip
		if config.Gateway != "" {
			log.Println("set gateway ip to tun interface")
			if err := setIpTunInterface(config.Interface, config.Gateway); err != nil {
				log.Fatalf("System error setting IP: %v", err)
			}
		}
	}

	stats := NewStats()
	defer stats.Close()

	// Graceful shutdown handler
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("\nReceived interrupt signal, shutting down...")
		stats.Close()
		stats.PrintStats()
		os.Exit(0)
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

	stats.Close()
	stats.PrintStats()
}
