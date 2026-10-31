package wireguard

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/wgkeeper/wgkeeper-node/internal/config"
)

// Linux routing tables as exposed by procfs.
const (
	procIPv4Routes = "/proc/net/route"
	procIPv6Routes = "/proc/net/ipv6_route"

	rtfUp     = 0x0001
	rtfReject = 0x0200
)

// resolveWANInterface returns the configured WAN interface, or the interface of
// the default route when none is configured.
func resolveWANInterface(configured string) (string, error) {
	if configured != "" {
		return configured, nil
	}
	return defaultRouteInterface(procIPv4Routes, procIPv6Routes)
}

// defaultRouteInterface returns the interface of the IPv4 default route with
// the lowest metric, falling back to the IPv6 one on IPv6-only hosts.
func defaultRouteInterface(ipv4Routes, ipv6Routes string) (string, error) {
	for _, src := range []struct {
		path  string
		parse func(io.Reader) (string, error)
	}{
		{ipv4Routes, parseIPv4DefaultRoute},
		{ipv6Routes, parseIPv6DefaultRoute},
	} {
		iface, err := defaultRouteFrom(src.path, src.parse)
		if err != nil {
			return "", err
		}
		if iface == "" {
			continue
		}
		if !config.IsSafeInterfaceName(iface) {
			return "", fmt.Errorf("default route interface %q has an unsupported name; set wireguard.routing.wan_interface", iface)
		}
		return iface, nil
	}
	return "", errors.New("no default route found to detect the WAN interface; set wireguard.routing.wan_interface")
}

func defaultRouteFrom(path string, parse func(io.Reader) (string, error)) (string, error) {
	// #nosec G304 -- fixed procfs paths (tests pass fixtures).
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("read routes: %w", err)
	}
	return parse(bytes.NewReader(data))
}

// parseIPv4DefaultRoute reads /proc/net/route:
// Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT.
func parseIPv4DefaultRoute(r io.Reader) (string, error) {
	return pickDefaultRoute(r, true, func(f []string) (iface string, flags, metric uint64, ok bool) {
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			return "", 0, 0, false
		}
		flags, err1 := strconv.ParseUint(f[3], 16, 32)
		metric, err2 := strconv.ParseUint(f[6], 10, 32)
		return f[0], flags, metric, err1 == nil && err2 == nil
	})
}

// parseIPv6DefaultRoute reads /proc/net/ipv6_route:
// dest destPrefix src srcPrefix nextHop metric refCnt use flags iface.
func parseIPv6DefaultRoute(r io.Reader) (string, error) {
	return pickDefaultRoute(r, false, func(f []string) (iface string, flags, metric uint64, ok bool) {
		if len(f) < 10 || strings.Trim(f[0], "0") != "" || f[1] != "00" {
			return "", 0, 0, false
		}
		metric, err1 := strconv.ParseUint(f[5], 16, 32)
		flags, err2 := strconv.ParseUint(f[8], 16, 32)
		return f[9], flags, metric, err1 == nil && err2 == nil
	})
}

func pickDefaultRoute(r io.Reader, hasHeader bool, parseLine func([]string) (string, uint64, uint64, bool)) (string, error) {
	sc := bufio.NewScanner(r)
	if hasHeader {
		sc.Scan()
	}
	best, bestMetric := "", uint64(0)
	for sc.Scan() {
		iface, flags, metric, ok := parseLine(strings.Fields(sc.Text()))
		if !ok || flags&rtfUp == 0 || flags&rtfReject != 0 || iface == "lo" {
			continue
		}
		if best == "" || metric < bestMetric {
			best, bestMetric = iface, metric
		}
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("read routes: %w", err)
	}
	return best, nil
}
