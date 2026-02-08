package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"

	"github.com/vishvananda/netlink"
)

const (
	TUNSETIFF     = 0x400454ca
	IFF_TUN       = 0x0001
	IFF_NO_PI     = 0x1000
	TUNSETPERSIST = 0x400454cb
)

type ifreq struct {
	ifrName  [16]byte
	ifrFlags uint16
}

// createTunInterface creates a TUN interface with the given name.
// If persistent is true, the interface survives after the process exits;
// the fd is closed and nil is returned.
// If persistent is false, the open *os.File is returned to the caller.
// The caller MUST keep it open — closing the last fd destroys the interface.
func createTunInterface(ifName string, persistent bool) (*os.File, error) {
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	ifr := ifreq{
		ifrFlags: IFF_TUN | IFF_NO_PI,
	}
	copy(ifr.ifrName[:], ifName)

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(TUNSETIFF), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		_ = file.Close()
		return nil, fmt.Errorf("ioctl TUNSETIFF for %s: %v", ifName, errno)
	}

	if persistent {
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(TUNSETPERSIST), 1)
		if errno != 0 {
			_ = file.Close()
			return nil, errno
		}
		log.Printf("Interface %s is now persistent", ifName)
		_ = file.Close()
		return nil, nil
	}

	log.Printf("Interface %s created (non-persistent, fd kept open)", ifName)
	return file, nil
}

// setIpTunInterface assigns an IP address and MTU to the TUN interface and brings it up.
func setIpTunInterface(ifName, gateway string, mtu int) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		log.Fatalf("interface not found: %v", err)
	}

	addr, err := netlink.ParseAddr(gateway + "/24")
	if err != nil {
		log.Fatalf("Failed to parse ip: %v", err)
	}

	err = netlink.AddrAdd(link, addr)
	if err != nil {
		if errors.Is(err, syscall.EEXIST) {
			log.Printf("IP %s are allready setuped on interface %s ", addr.IP, link.Attrs().Name)
		} else {
			log.Fatalf("failed to set up ip: %v", err)
		}
	}

	if mtu > 0 {
		if err := netlink.LinkSetMTU(link, mtu); err != nil {
			log.Fatalf("Failed to set MTU %d on interface %s: %v", mtu, ifName, err)
		}
	}

	err = netlink.LinkSetUp(link)
	if err != nil {
		log.Fatalf("Failed to up interface: %v", err)
	}
	return err
}
