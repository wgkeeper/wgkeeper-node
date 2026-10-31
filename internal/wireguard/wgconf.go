package wireguard

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/wgkeeper/wgkeeper-node/internal/config"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// EnsureWireGuardConfig writes the wg-quick config for the interface from cfg
// on every start, so changes to config.yaml (subnets, listen port, WAN
// interface) reach the interface instead of being shadowed by a file written
// on the first start. The server private key is the one thing kept from an
// existing file: a new key would change the public key every client uses.
func EnsureWireGuardConfig(cfg config.Config) (string, error) {
	confPath := defaultConfigPath(cfg.WGInterface)
	exists, err := checkExistingConfig(confPath)
	if err != nil {
		return "", err
	}
	var previous []byte
	var privateKey wgtypes.Key
	if exists {
		// #nosec G304 -- path derived from the configured interface name.
		previous, err = os.ReadFile(confPath)
		if err != nil {
			return "", fmt.Errorf("read wireguard config: %w", err)
		}
		privateKey, err = privateKeyFromConfig(previous)
		if err != nil {
			return "", fmt.Errorf("%s: %w; fix the PrivateKey line, or delete the file to generate a new server key (every client then needs a new config)", confPath, err)
		}
	} else {
		privateKey, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			return "", fmt.Errorf("generate private key: %w", err)
		}
	}
	addressLines, err := buildAddressLines(cfg)
	if err != nil {
		return "", err
	}
	wan, err := resolveWANInterface(cfg.WANInterface)
	if err != nil {
		return "", err
	}
	if cfg.WANInterface == "" {
		slog.Info("detected WAN interface from the default route", "iface", wan)
	}
	cfg.WANInterface = wan
	content := []byte(buildConfigContent(privateKey.String(), addressLines, cfg.WGListenPort, cfg))
	if exists && bytes.Equal(previous, content) {
		return confPath, nil
	}
	if err := os.MkdirAll(filepath.Dir(confPath), 0o700); err != nil {
		return "", fmt.Errorf("create wireguard config dir: %w", err)
	}
	if err := writeFileAtomic(confPath, content); err != nil {
		return "", fmt.Errorf("write wireguard config: %w", err)
	}
	if exists {
		slog.Info("WireGuard config updated from config.yaml", "path", confPath)
	}
	return confPath, nil
}

// privateKeyFromConfig returns the [Interface] PrivateKey of a wg-quick config.
func privateKeyFromConfig(data []byte) (wgtypes.Key, error) {
	for _, line := range strings.Split(string(data), "\n") {
		name, value, ok := strings.Cut(line, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "PrivateKey") {
			continue
		}
		key, err := wgtypes.ParseKey(strings.TrimSpace(value))
		if err != nil {
			return wgtypes.Key{}, fmt.Errorf("invalid PrivateKey: %w", err)
		}
		return key, nil
	}
	return wgtypes.Key{}, errors.New("no PrivateKey found")
}

// writeFileAtomic replaces path with data (mode 0600) via a temp file and
// rename, so a crash never leaves wg-quick a truncated config or a lost key.
func writeFileAtomic(path string, data []byte) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, os.Remove(tmp.Name()))
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err = tmp.Sync(); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// checkExistingConfig returns (true, nil) if config file already exists and is a file; (false, nil) if not exist; (false, err) on error.
func checkExistingConfig(confPath string) (bool, error) {
	info, err := os.Stat(confPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("stat wireguard config: %w", err)
	}
	if info.IsDir() {
		return false, fmt.Errorf("wireguard config path is a directory: %s", confPath)
	}
	return true, nil
}

func buildAddressLines(cfg config.Config) ([]string, error) {
	var lines []string
	if cfg.WGSubnet != "" {
		addr, err := addressLineFromSubnet4(cfg.WGSubnet, cfg.WGServerIP)
		if err != nil {
			return nil, err
		}
		lines = append(lines, addr)
	}
	if cfg.WGSubnet6 != "" {
		addr, err := addressLineFromSubnet6(cfg.WGSubnet6, cfg.WGServerIP6)
		if err != nil {
			return nil, err
		}
		lines = append(lines, addr)
	}
	return lines, nil
}

func addressLineFromSubnet4(subnetStr, serverIP string) (string, error) {
	_, subnet, err := net.ParseCIDR(subnetStr)
	if err != nil {
		return "", fmt.Errorf("invalid WG_SUBNET: %w", err)
	}
	if subnet.IP.To4() == nil {
		return "", errors.New("wireguard.subnet must be IPv4")
	}
	ip, err := resolveServerIP4(subnet, serverIP)
	if err != nil {
		return "", err
	}
	maskOnes, _ := subnet.Mask.Size()
	return fmt.Sprintf("%s/%d", ip.String(), maskOnes), nil
}

func addressLineFromSubnet6(subnetStr, serverIP string) (string, error) {
	_, subnet, err := net.ParseCIDR(subnetStr)
	if err != nil {
		return "", fmt.Errorf("invalid WG_SUBNET6: %w", err)
	}
	if subnet.IP.To4() != nil {
		return "", errors.New("wireguard.subnet6 must be IPv6")
	}
	ip, err := resolveServerIP6(subnet, serverIP)
	if err != nil {
		return "", err
	}
	maskOnes, _ := subnet.Mask.Size()
	return fmt.Sprintf("%s/%d", ip.String(), maskOnes), nil
}

func buildConfigContent(privateKey string, addressLines []string, listenPort int, cfg config.Config) string {
	var sb strings.Builder
	_, _ = fmt.Fprintf(&sb, "[Interface]\nPrivateKey = %s\n", privateKey)
	for _, a := range addressLines {
		_, _ = fmt.Fprintf(&sb, "Address = %s\n", a)
	}
	_, _ = fmt.Fprintf(&sb, "ListenPort = %d\n", listenPort)
	postUp, postDown := buildRoutingRules(cfg)
	if len(postUp) > 0 {
		sb.WriteString("PostUp = " + strings.Join(postUp, "; ") + "\n")
		sb.WriteString("PostDown = " + strings.Join(postDown, "; ") + "\n")
	}
	return sb.String()
}

func buildRoutingRules(cfg config.Config) (postUp, postDown []string) {
	wanInterface := strings.TrimSpace(cfg.WANInterface)
	if wanInterface == "" {
		return nil, nil
	}
	if cfg.WGSubnet != "" {
		postUp = append(postUp,
			fmt.Sprintf("iptables -A FORWARD -i %%i -o %s -s %s -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT", wanInterface, cfg.WGSubnet),
			fmt.Sprintf("iptables -A FORWARD -i %s -o %%i -d %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", wanInterface, cfg.WGSubnet),
			fmt.Sprintf("iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE", cfg.WGSubnet, wanInterface))
		postDown = append(postDown,
			fmt.Sprintf("iptables -D FORWARD -i %%i -o %s -s %s -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT", wanInterface, cfg.WGSubnet),
			fmt.Sprintf("iptables -D FORWARD -i %s -o %%i -d %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", wanInterface, cfg.WGSubnet),
			fmt.Sprintf("iptables -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE", cfg.WGSubnet, wanInterface))
	}
	if cfg.WGSubnet6 != "" {
		postUp = append(postUp,
			fmt.Sprintf("ip6tables -A FORWARD -i %%i -o %s -s %s -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT", wanInterface, cfg.WGSubnet6),
			fmt.Sprintf("ip6tables -A FORWARD -i %s -o %%i -d %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", wanInterface, cfg.WGSubnet6),
			fmt.Sprintf("ip6tables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE", cfg.WGSubnet6, wanInterface))
		postDown = append(postDown,
			fmt.Sprintf("ip6tables -D FORWARD -i %%i -o %s -s %s -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT", wanInterface, cfg.WGSubnet6),
			fmt.Sprintf("ip6tables -D FORWARD -i %s -o %%i -d %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", wanInterface, cfg.WGSubnet6),
			fmt.Sprintf("ip6tables -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE", cfg.WGSubnet6, wanInterface))
	}
	return postUp, postDown
}

func defaultConfigPath(iface string) string {
	if iface == "" {
		iface = "wg0"
	}
	if os.Geteuid() == 0 {
		return filepath.Join("/etc/wireguard", iface+".conf")
	}
	return filepath.Join("wireguard", iface+".conf")
}
