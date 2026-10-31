package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml"
)

// validNetworkInterface matches safe Linux network interface names: alphanumeric, hyphens, underscores, dots.
var validNetworkInterface = regexp.MustCompile(`^[a-zA-Z0-9\-_.]+$`)

const (
	// DefaultPeerStoreFile is where peers are persisted unless
	// wireguard.peer_store_file says otherwise. Peers are always persisted:
	// the interface is recreated on restart, so an in-memory store would drop
	// every peer while the orchestrator still believes they exist.
	DefaultPeerStoreFile = "/var/lib/wgkeeper/peers.db"

	errMsgRequired        = "%s is required"
	minAPIKeyLength       = 32
	minMetricsTokenLength = 32
)

type Config struct {
	Port         int
	APIKey       string
	WGInterface  string
	WGSubnet     string // IPv4 CIDR (optional if WGSubnet6 is set)
	WGServerIP   string // IPv4 server address (optional)
	WGSubnet6    string // IPv6 CIDR (optional if WGSubnet is set)
	WGServerIP6  string // IPv6 server address (optional)
	WGListenPort int
	WANInterface string
	// AllowPrivateNetworks lets peers reach private and shared address space
	// (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7) through the node.
	// Off by default: peers get internet access only.
	AllowPrivateNetworks bool
	PeerStoreFile        string // bbolt DB file the peer store is persisted to; always set

	// MetricsPort is the TCP port for the optional Prometheus /metrics
	// endpoint. Zero disables the endpoint entirely (no listener is created).
	// When non-zero, MetricsToken MUST be set (config validation enforces this).
	MetricsPort int

	// MetricsToken is the bearer token required for /metrics scraping. It is a
	// distinct secret from APIKey: compromise of the scrape token must not
	// grant peer-management access. Required when MetricsPort > 0.
	MetricsToken string
}

type wireguardRouting struct {
	WANInterface         string `yaml:"wan_interface"`
	AllowPrivateNetworks bool   `yaml:"allow_private_networks"`
}

type fileConfig struct {
	Server struct {
		Port string `yaml:"port"`

		// Removed in 1.4.0: TLS, IP filtering and proxy trust belong in the
		// reverse proxy. Still parsed so that an old config fails loudly
		// instead of silently running without the protection it asks for.
		TLSCert        string   `yaml:"tls_cert"`
		TLSKey         string   `yaml:"tls_key"`
		AllowedIPs     []string `yaml:"allowed_ips"`
		TrustedProxies []string `yaml:"trusted_proxies"`
	} `yaml:"server"`
	Auth struct {
		APIKey string `yaml:"api_key"`
	} `yaml:"auth"`
	WireGuard struct {
		Interface     string           `yaml:"interface"`
		Subnet        string           `yaml:"subnet"`
		ServerIP      string           `yaml:"server_ip"`
		Subnet6       string           `yaml:"subnet6"`
		ServerIP6     string           `yaml:"server_ip6"`
		ListenPort    int              `yaml:"listen_port"`
		Routing       wireguardRouting `yaml:"routing"`
		PeerStoreFile string           `yaml:"peer_store_file"`
	} `yaml:"wireguard"`
	Metrics struct {
		Port  int    `yaml:"port"`
		Token string `yaml:"token"`

		// Removed in 1.4.0 together with per-peer metrics; parsed only to
		// reject old configs with a clear error.
		PerPeer    *bool `yaml:"per_peer"`
		PerPeerMax *int  `yaml:"per_peer_max"`
	} `yaml:"metrics"`
}

func LoadConfig() (Config, error) {
	configPath := strings.TrimSpace(os.Getenv("NODE_CONFIG"))
	if configPath == "" {
		configPath = "config.yaml"
	}
	configPath = filepath.Clean(configPath)

	// #nosec G703 -- NODE_CONFIG is intentionally operator-controlled.
	info, err := os.Stat(configPath)
	if err == nil {
		if info.IsDir() {
			return Config{}, fmt.Errorf("config path is a directory: %s", configPath)
		}
		return loadConfigFile(configPath)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Config{}, fmt.Errorf("stat config: %w", err)
	}
	return Config{}, fmt.Errorf("config file not found: %s", configPath)
}

func loadConfigFile(path string) (Config, error) {
	// #nosec G304 G703 -- Reading the operator-selected config path is intended behavior.
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var fc fileConfig
	if err := yaml.Unmarshal(raw, &fc); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	portValue, apiKey, err := parseServerAndAuth(fc)
	if err != nil {
		return Config{}, err
	}
	wgSubnet, wgSubnet6, wgInterface, wgServerIP, wgServerIP6, wanInterface, wgListenPort, peerStoreFile, err := parseWireGuard(fc)
	if err != nil {
		return Config{}, err
	}
	metricsPort, metricsToken, err := parseMetrics(fc)
	if err != nil {
		return Config{}, err
	}
	return Config{
		Port:                 portValue,
		APIKey:               apiKey,
		WGInterface:          wgInterface,
		WGSubnet:             wgSubnet,
		WGServerIP:           wgServerIP,
		WGSubnet6:            wgSubnet6,
		WGServerIP6:          wgServerIP6,
		WGListenPort:         wgListenPort,
		WANInterface:         wanInterface,
		AllowPrivateNetworks: fc.WireGuard.Routing.AllowPrivateNetworks,
		PeerStoreFile:        peerStoreFile,
		MetricsPort:          metricsPort,
		MetricsToken:         metricsToken,
	}, nil
}

// parseMetrics validates the optional metrics block. Disabled by default
// (port == 0). When enabled, the token is mandatory and must meet the same
// minimum length as auth.api_key — refusing the unauthenticated configuration
// at startup is the main guarantee of this section.
func parseMetrics(fc fileConfig) (port int, token string, err error) {
	if fc.Metrics.PerPeer != nil || fc.Metrics.PerPeerMax != nil {
		return 0, "", fmt.Errorf("metrics.per_peer and metrics.per_peer_max were removed in 1.4.0; use GET /peers for per-peer traffic and handshakes")
	}
	port = fc.Metrics.Port
	token = strings.TrimSpace(fc.Metrics.Token)
	if port == 0 {
		// Endpoint disabled. Token is ignored — no need to validate it.
		return 0, "", nil
	}
	if port < 1 || port > 65535 {
		return 0, "", fmt.Errorf("metrics.port must be 0 (disabled) or a valid TCP port (1..65535)")
	}
	if len(token) < minMetricsTokenLength {
		return 0, "", fmt.Errorf("metrics.token must be at least %d characters when metrics.port is set; do not reuse auth.api_key", minMetricsTokenLength)
	}
	if token == fc.Auth.APIKey {
		return 0, "", fmt.Errorf("metrics.token must differ from auth.api_key (use a separate secret for the scrape endpoint)")
	}
	return port, token, nil
}

// MetricsEnabled reports whether the optional Prometheus /metrics endpoint is
// configured to start.
func (c Config) MetricsEnabled() bool {
	return c.MetricsPort > 0
}

// MetricsAddr returns the listen address for the metrics server. Bound to all
// interfaces inside the host/container; network-level isolation (Docker
// network, firewall) is the operator's responsibility.
func (c Config) MetricsAddr() string {
	return fmt.Sprintf(":%d", c.MetricsPort)
}

func parseServerAndAuth(fc fileConfig) (portValue int, apiKey string, err error) {
	if err := rejectRemovedServerKeys(fc); err != nil {
		return 0, "", err
	}
	portValue, err = parsePort("server.port", fc.Server.Port)
	if err != nil {
		return 0, "", err
	}
	apiKey, err = requireString("auth.api_key", fc.Auth.APIKey)
	if err != nil {
		return 0, "", err
	}
	if len(apiKey) < minAPIKeyLength {
		return 0, "", fmt.Errorf("auth.api_key must be at least %d characters", minAPIKeyLength)
	}
	return portValue, apiKey, nil
}

// rejectRemovedServerKeys fails on server options removed in 1.4.0. Ignoring
// them would leave a node that the operator believes is behind TLS or an IP
// allowlist serving plain, unfiltered HTTP.
func rejectRemovedServerKeys(fc fileConfig) error {
	const hint = "removed in 1.4.0; terminate TLS and filter clients in a reverse proxy such as Caddy or nginx (see README)"
	switch {
	case strings.TrimSpace(fc.Server.TLSCert) != "" || strings.TrimSpace(fc.Server.TLSKey) != "":
		return fmt.Errorf("server.tls_cert and server.tls_key were %s", hint)
	case len(fc.Server.AllowedIPs) > 0:
		return fmt.Errorf("server.allowed_ips was %s", hint)
	case len(fc.Server.TrustedProxies) > 0:
		return fmt.Errorf("server.trusted_proxies was %s", hint)
	}
	return nil
}

func parseWireGuard(fc fileConfig) (wgSubnet, wgSubnet6, wgInterface, wgServerIP, wgServerIP6, wanInterface string, wgListenPort int, peerStoreFile string, err error) {
	wgSubnet, err = optionalCIDR("wireguard.subnet", fc.WireGuard.Subnet)
	if err != nil {
		return "", "", "", "", "", "", 0, "", err
	}
	wgSubnet6, err = optionalCIDR("wireguard.subnet6", fc.WireGuard.Subnet6)
	if err != nil {
		return "", "", "", "", "", "", 0, "", err
	}
	if err := validateWireGuardSubnets(wgSubnet, wgSubnet6); err != nil {
		return "", "", "", "", "", "", 0, "", err
	}
	wgInterface, err = requireString("wireguard.interface", fc.WireGuard.Interface)
	if err != nil {
		return "", "", "", "", "", "", 0, "", err
	}
	wgListenPort = fc.WireGuard.ListenPort
	if err := requirePort("wireguard.listen_port", wgListenPort); err != nil {
		return "", "", "", "", "", "", 0, "", err
	}
	wgServerIP, err = optionalIPv4("wireguard.server_ip", fc.WireGuard.ServerIP)
	if err != nil {
		return "", "", "", "", "", "", 0, "", err
	}
	wgServerIP6, err = optionalIPv6("wireguard.server_ip6", fc.WireGuard.ServerIP6)
	if err != nil {
		return "", "", "", "", "", "", 0, "", err
	}
	wanInterface, err = optionalNetworkInterface("wireguard.routing.wan_interface", fc.WireGuard.Routing.WANInterface)
	if err != nil {
		return "", "", "", "", "", "", 0, "", err
	}
	peerStoreFile = parsePeerStoreFile(fc.WireGuard.PeerStoreFile)
	return wgSubnet, wgSubnet6, wgInterface, wgServerIP, wgServerIP6, wanInterface, wgListenPort, peerStoreFile, nil
}

// parsePeerStoreFile returns the bbolt path, DefaultPeerStoreFile when unset.
func parsePeerStoreFile(value string) string {
	if path := strings.TrimSpace(value); path != "" {
		return path
	}
	return DefaultPeerStoreFile
}

func validateWireGuardSubnets(wgSubnet, wgSubnet6 string) error {
	if wgSubnet == "" && wgSubnet6 == "" {
		return fmt.Errorf("at least one of wireguard.subnet or wireguard.subnet6 is required")
	}
	if wgSubnet != "" {
		if err := validateWireGuardSubnet4(wgSubnet); err != nil {
			return err
		}
	}
	if wgSubnet6 != "" {
		if err := validateWireGuardSubnet6(wgSubnet6); err != nil {
			return err
		}
	}
	return nil
}

func validateWireGuardSubnet4(wgSubnet string) error {
	_, ipNet, err := net.ParseCIDR(wgSubnet)
	if err != nil {
		return fmt.Errorf("wireguard.subnet must be a valid IPv4 CIDR: %w", err)
	}
	if ipNet.IP.To4() == nil {
		return fmt.Errorf("wireguard.subnet must be an IPv4 CIDR")
	}
	if ones, _ := ipNet.Mask.Size(); ones > 30 {
		return fmt.Errorf("wireguard.subnet prefix /%d is too long; maximum supported prefix is /30", ones)
	}
	return nil
}

func validateWireGuardSubnet6(wgSubnet6 string) error {
	_, ipNet, err := net.ParseCIDR(wgSubnet6)
	if err != nil {
		return fmt.Errorf("wireguard.subnet6 must be a valid IPv6 CIDR: %w", err)
	}
	if ipNet.IP.To4() != nil {
		return fmt.Errorf("wireguard.subnet6 must be an IPv6 CIDR")
	}
	if ones, _ := ipNet.Mask.Size(); ones > 126 {
		return fmt.Errorf("wireguard.subnet6 prefix /%d is too long; maximum supported prefix is /126", ones)
	}
	return nil
}

func (c Config) Addr() string {
	return fmt.Sprintf("0.0.0.0:%d", c.Port)
}

func requireString(field, value string) (string, error) {
	out := strings.TrimSpace(value)
	if out == "" {
		return "", fmt.Errorf(errMsgRequired, field)
	}
	return out, nil
}

// optionalNetworkInterface validates a Linux network interface name. Empty
// means "detect from the default route" (see wireguard.EnsureWireGuardConfig).
func optionalNetworkInterface(field, value string) (string, error) {
	out := strings.TrimSpace(value)
	if out == "" {
		return "", nil
	}
	if !IsSafeInterfaceName(out) {
		return "", fmt.Errorf("%s must be a valid network interface name (letters, digits, hyphens, underscores, dots only)", field)
	}
	return out, nil
}

// IsSafeInterfaceName reports whether name is a Linux interface name that is
// safe to interpolate into the iptables PostUp/PostDown rules.
func IsSafeInterfaceName(name string) bool {
	return validNetworkInterface.MatchString(name)
}

func parsePort(field, value string) (int, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return 0, fmt.Errorf(errMsgRequired, field)
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port <= 0 || port > 65535 {
		return 0, fmt.Errorf("%s must be a valid TCP port", field)
	}
	return port, nil
}

func requirePort(field string, port int) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("%s must be a valid UDP port", field)
	}
	return nil
}

func optionalCIDR(field, value string) (string, error) {
	out := strings.TrimSpace(value)
	if out == "" {
		return "", nil
	}
	_, ipNet, err := net.ParseCIDR(out)
	if err != nil {
		return "", fmt.Errorf("%s must be a valid CIDR", field)
	}
	// Return the canonical network string from the parser (e.g. "10.0.0.0/24")
	// rather than the raw input. This is a defense-in-depth measure: the canonical
	// form is guaranteed safe to interpolate into iptables PostUp/PostDown commands
	// even if a future code path skips the WANInterface regex check.
	return ipNet.String(), nil
}

func optionalIPv4(field, value string) (string, error) {
	out := strings.TrimSpace(value)
	if out == "" {
		return "", nil
	}
	parsed := net.ParseIP(out)
	if parsed == nil || parsed.To4() == nil {
		return "", fmt.Errorf("%s must be a valid IPv4 address", field)
	}
	return out, nil
}

func optionalIPv6(field, value string) (string, error) {
	out := strings.TrimSpace(value)
	if out == "" {
		return "", nil
	}
	parsed := net.ParseIP(out)
	if parsed == nil || parsed.To4() != nil {
		return "", fmt.Errorf("%s must be a valid IPv6 address", field)
	}
	return out, nil
}
