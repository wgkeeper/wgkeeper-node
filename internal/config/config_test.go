package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const msgExpectedNoError = "expected no error, got %v"

const (
	testPort         = "51821"
	testAPIKey       = "test-api-key-secure-key-longer!!" //nolint:gosec // test credential
	testWGSubnet4    = "10.0.0.0/24"
	testWGServerIP4  = "10.0.0.1"
	testWGSubnet6    = "fd00::/112"
	testWGServerIP6  = "fd00::1"
	testWANInterface = "eth0"
)

func writeConfigFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadConfigValid(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "51821"
auth:
  api_key: "test-api-key-secure-key-longer!!"
wireguard:
  interface: "wg0"
  subnet: "10.0.0.0/24"
  server_ip: "10.0.0.1"
  listen_port: 51820
  routing:
    wan_interface: "eth0"
`)
	t.Setenv("NODE_CONFIG", path)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf(msgExpectedNoError, err)
	}
	if cfg.Port != 51821 {
		t.Fatalf("expected port 51821, got %d", cfg.Port)
	}
	if cfg.APIKey != "test-api-key-secure-key-longer!!" {
		t.Fatalf("unexpected api key: %q", cfg.APIKey)
	}
	if cfg.WGInterface != "wg0" {
		t.Fatalf("unexpected interface: %q", cfg.WGInterface)
	}
	if cfg.WGListenPort != 51820 {
		t.Fatalf("unexpected listen port: %d", cfg.WGListenPort)
	}
}

func TestLoadConfigMissingAPIKey(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "51821"
auth:
  api_key: ""
wireguard:
  interface: "wg0"
  subnet: "10.0.0.0/24"
  listen_port: 51820
`)
	t.Setenv("NODE_CONFIG", path)

	if _, err := LoadConfig(); err == nil {
		t.Fatalf("expected error for missing api_key")
	}
}

func TestLoadConfigAPIKeyTooShort(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "51821"
auth:
  api_key: "too-short-key"
wireguard:
  interface: "wg0"
  subnet: "10.0.0.0/24"
  listen_port: 51820
`)
	t.Setenv("NODE_CONFIG", path)

	if _, err := LoadConfig(); err == nil {
		t.Fatalf("expected error for api_key shorter than %d characters", minAPIKeyLength)
	}
}

func TestLoadConfigInvalidPort(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "invalid"
auth:
  api_key: "test-api-key-secure-key-longer!!"
wireguard:
  interface: "wg0"
  subnet: "10.0.0.0/24"
  listen_port: 51820
`)
	t.Setenv("NODE_CONFIG", path)

	if _, err := LoadConfig(); err == nil {
		t.Fatalf("expected error for invalid port")
	}
}

func TestLoadConfigInvalidSubnet(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "51821"
auth:
  api_key: "test-api-key-secure-key-longer!!"
wireguard:
  interface: "wg0"
  subnet: "not-a-cidr"
  listen_port: 51820
  routing:
    wan_interface: "eth0"
`)
	t.Setenv("NODE_CONFIG", path)

	if _, err := LoadConfig(); err == nil {
		t.Fatalf("expected error for invalid subnet")
	}
}

func TestLoadConfigNoSubnet(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "51821"
auth:
  api_key: "test-api-key-secure-key-longer!!"
wireguard:
  interface: "wg0"
  listen_port: 51820
  routing:
    wan_interface: "eth0"
`)
	t.Setenv("NODE_CONFIG", path)

	if _, err := LoadConfig(); err == nil {
		t.Fatalf("expected error when neither subnet nor subnet6 is set")
	}
}

func TestLoadConfigRejectsRemovedServerKeys(t *testing.T) {
	cases := map[string]string{
		"tls_cert":        "  tls_cert: \"/etc/certs/server.pem\"\n",
		"tls_key":         "  tls_key: \"/etc/certs/server-key.pem\"\n",
		"allowed_ips":     "  allowed_ips:\n    - \"10.0.0.1\"\n",
		"trusted_proxies": "  trusted_proxies:\n    - \"172.18.0.0/16\"\n",
	}
	for key, serverLines := range cases {
		t.Run(key, func(t *testing.T) {
			path := writeConfigFile(t, `
server:
  port: "51821"
`+serverLines+`auth:
  api_key: "test-api-key-secure-key-longer!!"
wireguard:
  interface: "wg0"
  subnet: "10.0.0.0/24"
  listen_port: 51820
  routing:
    wan_interface: "eth0"
`)
			t.Setenv("NODE_CONFIG", path)

			_, err := LoadConfig()
			if err == nil {
				t.Fatalf("expected error for removed server.%s", key)
			}
			if !strings.Contains(err.Error(), "removed in 2.0.0") {
				t.Fatalf("error should explain the removal, got %v", err)
			}
		})
	}
}

func TestLoadConfigIPv6Only(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "`+testPort+`"
auth:
  api_key: "`+testAPIKey+`"
wireguard:
  interface: "wg0"
  subnet6: "`+testWGSubnet6+`"
  server_ip6: "`+testWGServerIP6+`"
  listen_port: 51820
  routing:
    wan_interface: "`+testWANInterface+`"
`)
	t.Setenv("NODE_CONFIG", path)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf(msgExpectedNoError, err)
	}
	if cfg.WGSubnet != "" {
		t.Fatalf("expected no IPv4 subnet, got %q", cfg.WGSubnet)
	}
	if cfg.WGSubnet6 != testWGSubnet6 {
		t.Fatalf("expected subnet6 %s, got %q", testWGSubnet6, cfg.WGSubnet6)
	}
	if cfg.WGServerIP6 != testWGServerIP6 {
		t.Fatalf("expected server_ip6 %s, got %q", testWGServerIP6, cfg.WGServerIP6)
	}
}

func TestLoadConfigInvalidListenPort(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "51821"
auth:
  api_key: "test-api-key-secure-key-longer!!"
wireguard:
  interface: "wg0"
  subnet: "10.0.0.0/24"
  listen_port: 70000
`)
	t.Setenv("NODE_CONFIG", path)

	if _, err := LoadConfig(); err == nil {
		t.Fatalf("expected error for invalid listen port")
	}
}

func TestLoadConfigInvalidServerIP(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "51821"
auth:
  api_key: "test-api-key-secure-key-longer!!"
wireguard:
  interface: "wg0"
  subnet: "10.0.0.0/24"
  server_ip: "not-an-ip"
  listen_port: 51820
`)
	t.Setenv("NODE_CONFIG", path)

	if _, err := LoadConfig(); err == nil {
		t.Fatalf("expected error for invalid server_ip")
	}
}

// TestLoadConfigMinimal checks that a config with only the API key and a
// subnet starts with the default ports, interface and peer store.
func TestLoadConfigMinimal(t *testing.T) {
	path := writeConfigFile(t, `
auth:
  api_key: "test-api-key-secure-key-longer!!"
wireguard:
  subnet: "10.0.0.0/24"
`)
	t.Setenv("NODE_CONFIG", path)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf(msgExpectedNoError, err)
	}
	if cfg.Port != DefaultAPIPort || cfg.WGInterface != DefaultInterface || cfg.WGListenPort != DefaultWireGuardPort {
		t.Fatalf("defaults not applied: port=%d iface=%q listen=%d", cfg.Port, cfg.WGInterface, cfg.WGListenPort)
	}
	if cfg.PeerStoreFile != DefaultPeerStoreFile {
		t.Fatalf("expected default peer store, got %q", cfg.PeerStoreFile)
	}
}

func TestLoadConfigInvalidInterfaceName(t *testing.T) {
	for _, name := range []string{"../../etc/x", "wg0;reboot", "a-very-long-interface-name"} {
		t.Run(name, func(t *testing.T) {
			path := writeConfigFile(t, `
auth:
  api_key: "test-api-key-secure-key-longer!!"
wireguard:
  interface: "`+name+`"
  subnet: "10.0.0.0/24"
`)
			t.Setenv("NODE_CONFIG", path)
			if _, err := LoadConfig(); err == nil {
				t.Fatalf("expected error for interface %q", name)
			}
		})
	}
}

// TestLoadConfigUnknownKeyRejected guards against typos silently dropping a
// setting, e.g. a misspelled allow_private_networks.
func TestLoadConfigUnknownKeyRejected(t *testing.T) {
	path := writeConfigFile(t, `
auth:
  api_key: "test-api-key-secure-key-longer!!"
wireguard:
  subnet: "10.0.0.0/24"
  routing:
    alow_private_networks: true
`)
	t.Setenv("NODE_CONFIG", path)
	_, err := LoadConfig()
	if err == nil || !strings.Contains(err.Error(), "alow_private_networks") {
		t.Fatalf("expected an unknown-field error naming the key, got %v", err)
	}
}

// TestLoadConfigParseErrorHidesSecrets checks that a YAML error doesn't echo
// the surrounding source lines, which would print the API key into the log.
func TestLoadConfigParseErrorHidesSecrets(t *testing.T) {
	path := writeConfigFile(t, `
auth:
  api_key: "super-secret-api-key-value-0123456789"
wireguard:
  subnet: "10.0.0.0/24"
  listen_port: not-a-number
`)
	t.Setenv("NODE_CONFIG", path)
	_, err := LoadConfig()
	if err == nil {
		t.Fatal("expected a parse error")
	}
	if strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("parse error leaks the config source: %v", err)
	}
}

func TestLoadConfigPeerStoreFile(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "51821"
auth:
  api_key: "test-api-key-secure-key-longer!!"
wireguard:
  interface: "wg0"
  subnet: "10.0.0.0/24"
  server_ip: "10.0.0.1"
  listen_port: 51820
  peer_store_file: "peers.db"
  routing:
    wan_interface: "eth0"
`)
	t.Setenv("NODE_CONFIG", path)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf(msgExpectedNoError, err)
	}
	if cfg.PeerStoreFile != "peers.db" {
		t.Fatalf("expected peer_store_file peers.db, got %q", cfg.PeerStoreFile)
	}
}

func TestLoadConfigWANInterfaceOptional(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "51821"
auth:
  api_key: "test-api-key-secure-key-longer!!"
wireguard:
  interface: "wg0"
  subnet: "10.0.0.0/24"
  listen_port: 51820
`)
	t.Setenv("NODE_CONFIG", path)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf(msgExpectedNoError, err)
	}
	if cfg.WANInterface != "" {
		t.Fatalf("expected empty WAN interface (detected at startup), got %q", cfg.WANInterface)
	}
}

func TestLoadConfigAllowPrivateNetworks(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "51821"
auth:
  api_key: "test-api-key-secure-key-longer!!"
wireguard:
  interface: "wg0"
  subnet: "10.0.0.0/24"
  listen_port: 51820
  routing:
    allow_private_networks: true
`)
	t.Setenv("NODE_CONFIG", path)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf(msgExpectedNoError, err)
	}
	if !cfg.AllowPrivateNetworks {
		t.Fatal("expected AllowPrivateNetworks=true")
	}
}

func TestLoadConfigPeerStoreFileDefault(t *testing.T) {
	path := writeSubnetConfig(t, testWGSubnet4, "")
	t.Setenv("NODE_CONFIG", path)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf(msgExpectedNoError, err)
	}
	if cfg.PeerStoreFile != DefaultPeerStoreFile {
		t.Fatalf("expected default peer store %q, got %q", DefaultPeerStoreFile, cfg.PeerStoreFile)
	}
}

// ---------- subnet size validation ----------

const subnetValidationBase = `
server:
  port: "51821"
auth:
  api_key: "test-api-key-secure-key-longer!!"
wireguard:
  interface: "wg0"
  listen_port: 51820
  routing:
    wan_interface: "eth0"
`

func writeSubnetConfig(t *testing.T, subnet, subnet6 string) string {
	t.Helper()
	content := subnetValidationBase
	if subnet != "" {
		content += "  subnet: " + `"` + subnet + `"` + "\n"
	}
	if subnet6 != "" {
		content += "  subnet6: " + `"` + subnet6 + `"` + "\n"
	}
	return writeConfigFile(t, content)
}

func TestLoadConfigSubnet32Rejected(t *testing.T) {
	path := writeSubnetConfig(t, "10.0.0.1/32", "")
	t.Setenv("NODE_CONFIG", path)
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected error for /32 IPv4 subnet (too small)")
	}
}

func TestLoadConfigSubnet31Rejected(t *testing.T) {
	path := writeSubnetConfig(t, "10.0.0.0/31", "")
	t.Setenv("NODE_CONFIG", path)
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected error for /31 IPv4 subnet (too small)")
	}
}

func TestLoadConfigSubnet30Valid(t *testing.T) {
	path := writeSubnetConfig(t, "10.0.0.0/30", "")
	t.Setenv("NODE_CONFIG", path)
	if _, err := LoadConfig(); err != nil {
		t.Fatalf("expected /30 IPv4 to be valid, got error: %v", err)
	}
}

func TestLoadConfigSubnet128IPv6Rejected(t *testing.T) {
	path := writeSubnetConfig(t, "", "fd00::1/128")
	t.Setenv("NODE_CONFIG", path)
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected error for /128 IPv6 subnet (too small)")
	}
}

func TestLoadConfigSubnet127IPv6Rejected(t *testing.T) {
	path := writeSubnetConfig(t, "", "fd00::/127")
	t.Setenv("NODE_CONFIG", path)
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected error for /127 IPv6 subnet (too small)")
	}
}

func TestLoadConfigSubnet126IPv6Valid(t *testing.T) {
	path := writeSubnetConfig(t, "", "fd00::/126")
	t.Setenv("NODE_CONFIG", path)
	if _, err := LoadConfig(); err != nil {
		t.Fatalf("expected /126 IPv6 to be valid, got error: %v", err)
	}
}

// ---------- Addr ----------

func TestConfigAddr(t *testing.T) {
	cfg := Config{Port: 8080}
	got := cfg.Addr()
	want := "0.0.0.0:8080"
	if got != want {
		t.Fatalf("Addr(): got %q, want %q", got, want)
	}
}

// ---------- LoadConfig error paths ----------

func TestLoadConfigFileNotFound(t *testing.T) {
	t.Setenv("NODE_CONFIG", "/tmp/wgkeeper-test-nonexistent-config.yaml")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected error for missing config file")
	}
}

func TestLoadConfigPathIsDirectory(t *testing.T) {
	t.Setenv("NODE_CONFIG", t.TempDir())
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected error when config path is a directory")
	}
}

func TestLoadConfigInvalidYAML(t *testing.T) {
	path := writeConfigFile(t, "{broken yaml: [")
	t.Setenv("NODE_CONFIG", path)
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

// ---------- validateWireGuardSubnet helpers ----------

func TestValidateWireGuardSubnet4RejectsIPv6(t *testing.T) {
	if validateWireGuardSubnet4("fd00::/64") == nil {
		t.Fatal("expected error for IPv6 CIDR in validateWireGuardSubnet4")
	}
}

func TestValidateWireGuardSubnet4PrefixTooLong(t *testing.T) {
	if validateWireGuardSubnet4("10.0.0.0/31") == nil {
		t.Fatal("expected error for /31 IPv4 subnet in validateWireGuardSubnet4")
	}
	if err := validateWireGuardSubnet4("10.0.0.0/30"); err != nil {
		t.Fatalf("expected /30 IPv4 to be valid in validateWireGuardSubnet4, got %v", err)
	}
}

func TestValidateWireGuardSubnet6RejectsIPv4(t *testing.T) {
	if validateWireGuardSubnet6("10.0.0.0/24") == nil {
		t.Fatal("expected error for IPv4 CIDR in validateWireGuardSubnet6")
	}
}

func TestLoadConfigNodeConfigWhitespace(t *testing.T) {
	// Whitespace-only NODE_CONFIG trims to "" → defaults to "config.yaml" which shouldn't exist in test dir.
	t.Setenv("NODE_CONFIG", "   ")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected error when NODE_CONFIG is whitespace and config.yaml does not exist")
	}
}

func TestOptionalIPv4WithIPv6Address(t *testing.T) {
	_, err := optionalIPv4("field", "fd00::1")
	if err == nil {
		t.Fatal("expected error for IPv6 address in optionalIPv4")
	}
}

func TestOptionalIPv6WithIPv4Address(t *testing.T) {
	_, err := optionalIPv6("field", "10.0.0.1")
	if err == nil {
		t.Fatal("expected error for IPv4 address in optionalIPv6")
	}
}

func TestParsePortZero(t *testing.T) {
	if _, err := parseAPIPort("0"); err == nil {
		t.Fatal("expected error for port 0")
	}
}

func TestParsePortMaxValid(t *testing.T) {
	port, err := parseAPIPort("65535")
	if err != nil || port != 65535 {
		t.Fatalf("expected port 65535, got %d, err: %v", port, err)
	}
}

func TestParsePortTooHigh(t *testing.T) {
	if _, err := parseAPIPort("65536"); err == nil {
		t.Fatal("expected error for port 65536")
	}
}

func TestRequirePortZero(t *testing.T) {
	if requirePort("field", 0) == nil {
		t.Fatal("expected error for port 0")
	}
}

func TestRequirePortValid(t *testing.T) {
	if err := requirePort("field", 51820); err != nil {
		t.Fatalf(msgExpectedNoError, err)
	}
}

func TestLoadConfigInvalidServerIP6(t *testing.T) {
	path := writeConfigFile(t, `
server:
  port: "51821"
auth:
  api_key: "test-api-key-secure-key-longer!!"
wireguard:
  interface: "wg0"
  subnet6: "fd00::/112"
  server_ip6: "10.0.0.1"
  listen_port: 51820
  routing:
    wan_interface: "eth0"
`)
	t.Setenv("NODE_CONFIG", path)
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected error for IPv4 address as server_ip6")
	}
}

func TestValidateWireGuardSubnet6PrefixTooLong(t *testing.T) {
	if validateWireGuardSubnet6("fd00::/127") == nil {
		t.Fatal("expected error for /127 IPv6 subnet in validateWireGuardSubnet6")
	}
	if err := validateWireGuardSubnet6("fd00::/126"); err != nil {
		t.Fatalf("expected /126 IPv6 to be valid in validateWireGuardSubnet6, got %v", err)
	}
}

// ---------- metrics: optional Prometheus endpoint ----------

const baseConfigForMetrics = `
server:
  port: "51821"
auth:
  api_key: "test-api-key-secure-key-longer!!"
wireguard:
  interface: "wg0"
  subnet: "10.0.0.0/24"
  server_ip: "10.0.0.1"
  listen_port: 51820
  routing:
    wan_interface: "eth0"
`

func TestLoadConfigMetricsDisabledByDefault(t *testing.T) {
	path := writeConfigFile(t, baseConfigForMetrics)
	t.Setenv("NODE_CONFIG", path)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf(msgExpectedNoError, err)
	}
	if cfg.MetricsEnabled() {
		t.Errorf("metrics should be disabled when metrics block is absent")
	}
	if cfg.MetricsPort != 0 {
		t.Errorf("expected MetricsPort=0 by default, got %d", cfg.MetricsPort)
	}
}

func TestLoadConfigMetricsEnabledRequiresToken(t *testing.T) {
	path := writeConfigFile(t, baseConfigForMetrics+`
metrics:
  port: 9090
`)
	t.Setenv("NODE_CONFIG", path)

	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected error: metrics.port set without metrics.token")
	}
}

func TestLoadConfigMetricsTokenTooShort(t *testing.T) {
	path := writeConfigFile(t, baseConfigForMetrics+`
metrics:
  port: 9090
  token: "short"
`)
	t.Setenv("NODE_CONFIG", path)

	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected error: metrics.token below minimum length")
	}
}

func TestLoadConfigMetricsTokenMustDifferFromAPIKey(t *testing.T) {
	path := writeConfigFile(t, baseConfigForMetrics+`
metrics:
  port: 9090
  token: "test-api-key-secure-key-longer!!"
`)
	t.Setenv("NODE_CONFIG", path)

	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected error: metrics.token must differ from auth.api_key")
	}
}

func TestLoadConfigMetricsValid(t *testing.T) {
	path := writeConfigFile(t, baseConfigForMetrics+`
metrics:
  port: 9090
  token: "metrics-bearer-token-32chars-min!"
`)
	t.Setenv("NODE_CONFIG", path)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf(msgExpectedNoError, err)
	}
	if !cfg.MetricsEnabled() {
		t.Error("metrics should be enabled")
	}
	if cfg.MetricsPort != 9090 {
		t.Errorf("expected MetricsPort=9090, got %d", cfg.MetricsPort)
	}
	if cfg.MetricsAddr() != ":9090" {
		t.Errorf("expected MetricsAddr=:9090, got %q", cfg.MetricsAddr())
	}
}

func TestLoadConfigRejectsRemovedPerPeerMetrics(t *testing.T) {
	for name, block := range map[string]string{
		"per_peer":     "  per_peer: false\n",
		"per_peer_max": "  per_peer_max: 500\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := writeConfigFile(t, baseConfigForMetrics+`
metrics:
  port: 9090
  token: "metrics-bearer-token-32chars-min!"
`+block)
			t.Setenv("NODE_CONFIG", path)
			_, err := LoadConfig()
			if err == nil || !strings.Contains(err.Error(), "removed in 2.0.0") {
				t.Fatalf("expected removal error for metrics.%s, got %v", name, err)
			}
		})
	}
}

func TestLoadConfigMetricsInvalidPort(t *testing.T) {
	for _, port := range []int{-1, 65536, 70000} {
		t.Run("port", func(t *testing.T) {
			path := writeConfigFile(t, baseConfigForMetrics+`
metrics:
  port: `+itoa(port)+`
  token: "metrics-bearer-token-32chars-min!"
`)
			t.Setenv("NODE_CONFIG", path)
			if _, err := LoadConfig(); err == nil {
				t.Fatalf("expected error for invalid metrics.port=%d", port)
			}
		})
	}
}

// itoa avoids pulling fmt into the test for a single conversion.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [11]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// TestConfigExampleLoads keeps config.example.yaml valid under strict key
// checking once its placeholder API key is replaced.
func TestConfigExampleLoads(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	content := strings.Replace(string(raw), "REPLACE_WITH_32+_RANDOM_CHARS", testAPIKey, 1)
	t.Setenv("NODE_CONFIG", writeConfigFile(t, content))
	if _, err := LoadConfig(); err != nil {
		t.Fatalf("config.example.yaml does not load: %v", err)
	}
}
