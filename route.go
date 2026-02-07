package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/vishvananda/netlink"
)

const (
	mainRouteDir    = "data"
	defaultRouteDir = "default_route"
)

func addRoute(destination string, gwIP net.IP, ifaceIndex int) error {
	var ipNet *net.IPNet

	if _, parsedNet, err := net.ParseCIDR(destination); err != nil {
		ip := net.ParseIP(destination)
		if ip == nil {
			return fmt.Errorf("error parsing destination %s: %w", destination, err)
		}
		ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
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
		return fmt.Errorf("invalid gateway IP: %s", gateway)
	}

	var jsonFiles []string

	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".json" {
			jsonFiles = append(jsonFiles, info.Name())
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

	for _, fileName := range jsonFiles {
		log.Println("Processing:", fileName)
		data, err := os.ReadFile(filepath.Join(dir, fileName))
		if err != nil {
			log.Printf("\033[31mError reading file %s: %v\033[0m\n", fileName, err)
			continue
		}

		var destinations []string
		if err := json.Unmarshal(data, &destinations); err != nil {
			log.Printf("\033[31mError parsing JSON %s: %v\033[0m\n", fileName, err)
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
