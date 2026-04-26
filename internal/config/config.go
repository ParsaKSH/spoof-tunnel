package config

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

// Config holds all tunnel configuration, loadable from JSON or CLI flags.
type Config struct {
	Mode string `json:"mode"`

	// Local mode
	Listen      string `json:"listen,omitempty"`
	Remote      string `json:"remote,omitempty"`
	RemotePort  int    `json:"remote_port,omitempty"`
	RecvPort    int    `json:"recv_port,omitempty"`
	SpoofIP     string `json:"spoof_ip,omitempty"`
	SpoofPort   int    `json:"spoof_port,omitempty"`
	PeerSpoofIP string `json:"peer_spoof_ip,omitempty"`

	// Remote mode
	ListenPort int    `json:"listen_port,omitempty"`
	Forward    string `json:"forward,omitempty"`
	ClientIP   string `json:"client_ip,omitempty"`
	ClientPort int    `json:"client_port,omitempty"`

	// Multi-IP spoof
	SpoofIPFile string `json:"spoof_ip_file,omitempty"`

	// Transport selection per direction
	SendTransport string `json:"send_transport,omitempty"` // "tcp", "udp", "icmp", "icmpv6"
	RecvTransport string `json:"recv_transport,omitempty"` // "tcp", "udp", "icmp", "icmpv6"
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

// LoadIPListFile reads a text file with one IPv4 address per line.
func LoadIPListFile(path string) ([]net.IP, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open IP list %s: %w", path, err)
	}
	defer f.Close()

	var ips []net.IP
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ip := net.ParseIP(line)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP at %s:%d: %q", path, lineNum, line)
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("IPv6 not supported at %s:%d: %q", path, lineNum, line)
		}
		ips = append(ips, ip4)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read IP list %s: %w", path, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("IP list file %s is empty", path)
	}
	return ips, nil
}

func (c *Config) MergeLocal(listen, remote string, remotePort, recvPort int, spoofIP string, spoofPort int, peerSpoofIP, spoofIPFile, sendTransport, recvTransport string) (
	oListen, oRemote string, oRemotePort, oRecvPort int, oSpoofIP string, oSpoofPort int, oPeerSpoofIP, oSpoofIPFile, oSendTransport, oRecvTransport string,
) {
	oListen = firstStr(listen, c.Listen, "127.0.0.1:5000")
	oRemote = firstStr(remote, c.Remote, "")
	oRemotePort = firstInt(remotePort, c.RemotePort, 8090)
	oRecvPort = firstInt(recvPort, c.RecvPort, 5001)
	oSpoofIP = firstStr(spoofIP, c.SpoofIP, "")
	oSpoofPort = firstInt(spoofPort, c.SpoofPort, 443)
	oPeerSpoofIP = firstStr(peerSpoofIP, c.PeerSpoofIP, "")
	oSpoofIPFile = firstStr(spoofIPFile, c.SpoofIPFile, "")
	oSendTransport = firstStr(sendTransport, c.SendTransport, "")
	oRecvTransport = firstStr(recvTransport, c.RecvTransport, "")
	return
}

func (c *Config) MergeRemote(listenPort int, forward, clientIP string, clientPort int, spoofIP string, spoofPort int, peerSpoofIP string, spoofIPFile, sendTransport, recvTransport string) (
	oListenPort int, oForward, oClientIP string, oClientPort int, oSpoofIP string, oSpoofPort int, oPeerSpoofIP string, oSpoofIPFile, oSendTransport, oRecvTransport string,
) {
	oListenPort = firstInt(listenPort, c.ListenPort, 8090)
	oForward = firstStr(forward, c.Forward, "127.0.0.1:51820")
	oClientIP = firstStr(clientIP, c.ClientIP, "")
	oClientPort = firstInt(clientPort, c.ClientPort, 5001)
	oSpoofIP = firstStr(spoofIP, c.SpoofIP, "")
	oSpoofPort = firstInt(spoofPort, c.SpoofPort, 8090)
	oPeerSpoofIP = firstStr(peerSpoofIP, c.PeerSpoofIP, "")
	oSpoofIPFile = firstStr(spoofIPFile, c.SpoofIPFile, "")
	oSendTransport = firstStr(sendTransport, c.SendTransport, "")
	oRecvTransport = firstStr(recvTransport, c.RecvTransport, "")
	return
}

func firstStr(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func firstInt(values ...int) int {
	for _, v := range values {
		if v != 0 {
			return v
		}
	}
	return 0
}
