package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/ParsaKSH/spoof-tunnel/internal/config"
	"github.com/ParsaKSH/spoof-tunnel/internal/relay"
	"github.com/spf13/cobra"
)

var Version = "3.0.0"

func main() {
	root := &cobra.Command{
		Use:     "spoof",
		Short:   "Spoofed UDP relay tunnel (Rust transport)",
		Version: Version,
	}

	root.AddCommand(localCmd())
	root.AddCommand(remoteCmd())
	root.AddCommand(runCmd())

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func runCmd() *cobra.Command {
	var configFile string

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run from config file (mode determined by config)",
		Run: func(cmd *cobra.Command, args []string) {
			requireRoot()
			cfg, err := config.Load(configFile)
			if err != nil {
				log.Fatalf("load config: %v", err)
			}
			if cfg == nil {
				log.Fatalf("config file not found: %s", configFile)
			}

			switch cfg.Mode {
			case "local":
				runLocal(cfg.Listen, cfg.Remote, cfg.RemotePort, cfg.RecvPort,
					cfg.SpoofIP, cfg.SpoofPort, cfg.PeerSpoofIP, cfg.SpoofIPFile,
					cfg.SendTransport, cfg.RecvTransport)
			case "remote":
				runRemote(cfg.ListenPort, cfg.Forward, cfg.ClientIP, cfg.ClientPort,
					cfg.SpoofIP, cfg.SpoofPort, cfg.PeerSpoofIP,
					cfg.SpoofIPFile, cfg.SendTransport, cfg.RecvTransport)
			default:
				log.Fatalf("unknown mode in config: %q", cfg.Mode)
			}
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "config.json", "path to config file")
	return cmd
}

func localCmd() *cobra.Command {
	var (
		listen        string
		remoteAddr    string
		remotePort    int
		recvPort      int
		spoofIP       string
		spoofPort     int
		peerSpoofIP   string
		spoofIPFile   string
		sendTransport string
		recvTransport string
		configFile    string
	)

	cmd := &cobra.Command{
		Use:   "local",
		Short: "Run in local (client) mode: UDP → spoofed packets to server",
		Run: func(cmd *cobra.Command, args []string) {
			requireRoot()

			var fileCfg *config.Config
			if configFile != "" {
				c, err := config.Load(configFile)
				if err != nil {
					log.Fatalf("load config: %v", err)
				}
				if c != nil {
					fileCfg = c
				}
			}

			if fileCfg != nil {
				listen, remoteAddr, remotePort, recvPort, spoofIP, spoofPort, peerSpoofIP, spoofIPFile, sendTransport, recvTransport =
					fileCfg.MergeLocal(listen, remoteAddr, remotePort, recvPort, spoofIP, spoofPort, peerSpoofIP, spoofIPFile, sendTransport, recvTransport)
			}

			if remoteAddr == "" {
				log.Fatal("--remote is required")
			}
			if spoofIP == "" && spoofIPFile == "" {
				log.Fatal("--spoof-ip or --spoof-ip-file is required")
			}

			runLocal(listen, remoteAddr, remotePort, recvPort, spoofIP, spoofPort, peerSpoofIP, spoofIPFile, sendTransport, recvTransport)
		},
	}

	cmd.Flags().StringVarP(&listen, "listen", "l", "127.0.0.1:5000", "UDP listen address for app")
	cmd.Flags().StringVarP(&remoteAddr, "remote", "r", "", "server IP")
	cmd.Flags().IntVarP(&remotePort, "remote-port", "p", 8090, "server port")
	cmd.Flags().IntVar(&recvPort, "recv-port", 5001, "port for incoming packets from server")
	cmd.Flags().StringVarP(&spoofIP, "spoof-ip", "s", "", "spoofed source IP (single)")
	cmd.Flags().IntVar(&spoofPort, "spoof-port", 443, "spoofed source port")
	cmd.Flags().StringVar(&peerSpoofIP, "peer-spoof-ip", "", "expected source IP of server packets")
	cmd.Flags().StringVar(&spoofIPFile, "spoof-ip-file", "", "file with spoof IPs (one per line, round-robin)")
	cmd.Flags().StringVar(&sendTransport, "send-transport", "", "send transport: tcp, udp, icmp, icmpv6 (default: tcp)")
	cmd.Flags().StringVar(&recvTransport, "recv-transport", "", "recv transport: tcp, udp, icmp, icmpv6 (default: udp)")
	cmd.Flags().StringVarP(&configFile, "config", "c", "", "path to config file (CLI flags override)")

	return cmd
}

func remoteCmd() *cobra.Command {
	var (
		listenPort    int
		forward       string
		clientIP      string
		clientPort    int
		spoofIP       string
		spoofPort     int
		peerSpoofIP   string
		spoofIPFile   string
		sendTransport string
		recvTransport string
		configFile    string
	)

	cmd := &cobra.Command{
		Use:   "remote",
		Short: "Run in remote (server) mode: spoofed packets → UDP forward",
		Run: func(cmd *cobra.Command, args []string) {
			requireRoot()

			var fileCfg *config.Config
			if configFile != "" {
				c, err := config.Load(configFile)
				if err != nil {
					log.Fatalf("load config: %v", err)
				}
				if c != nil {
					fileCfg = c
				}
			}

			if fileCfg != nil {
				listenPort, forward, clientIP, clientPort, spoofIP, spoofPort, peerSpoofIP, spoofIPFile, sendTransport, recvTransport =
					fileCfg.MergeRemote(listenPort, forward, clientIP, clientPort, spoofIP, spoofPort, peerSpoofIP, spoofIPFile, sendTransport, recvTransport)
			}

			if clientIP == "" {
				log.Fatal("--client-ip is required")
			}
			if spoofIP == "" && spoofIPFile == "" {
				log.Fatal("--spoof-ip or --spoof-ip-file is required")
			}

			runRemote(listenPort, forward, clientIP, clientPort, spoofIP, spoofPort, peerSpoofIP, spoofIPFile, sendTransport, recvTransport)
		},
	}

	cmd.Flags().IntVarP(&listenPort, "listen-port", "l", 8090, "port for incoming packets")
	cmd.Flags().StringVarP(&forward, "forward", "f", "127.0.0.1:51820", "UDP address to forward to")
	cmd.Flags().StringVar(&clientIP, "client-ip", "", "client's real IP")
	cmd.Flags().IntVar(&clientPort, "client-port", 5001, "client's recv port")
	cmd.Flags().StringVarP(&spoofIP, "spoof-ip", "s", "", "spoofed source IP (single)")
	cmd.Flags().IntVar(&spoofPort, "spoof-port", 8090, "spoofed source port")
	cmd.Flags().StringVar(&peerSpoofIP, "peer-spoof-ip", "", "expected source IP of client packets")
	cmd.Flags().StringVar(&spoofIPFile, "spoof-ip-file", "", "file with spoof IPs (one per line, round-robin)")
	cmd.Flags().StringVar(&sendTransport, "send-transport", "", "send transport: tcp, udp, icmp, icmpv6 (default: udp)")
	cmd.Flags().StringVar(&recvTransport, "recv-transport", "", "recv transport: tcp, udp, icmp, icmpv6 (default: tcp)")
	cmd.Flags().StringVarP(&configFile, "config", "c", "", "path to config file (CLI flags override)")

	return cmd
}

func loadSpoofIPs(spoofIP, spoofIPFile string) ([]net.IP, error) {
	if spoofIPFile != "" {
		ips, err := config.LoadIPListFile(spoofIPFile)
		if err != nil {
			return nil, err
		}
		log.Printf("loaded %d spoof IPs from %s", len(ips), spoofIPFile)
		return ips, nil
	}
	ip := net.ParseIP(spoofIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid spoof-ip: %s", spoofIP)
	}
	return []net.IP{ip}, nil
}

func runLocal(listen, remoteAddr string, remotePort, recvPort int, spoofIP string, spoofPort int, peerSpoofIP, spoofIPFile, sendTransport, recvTransport string) {
	rIP := net.ParseIP(remoteAddr)
	if rIP == nil {
		log.Fatalf("invalid remote IP: %s", remoteAddr)
	}

	spoofIPs, err := loadSpoofIPs(spoofIP, spoofIPFile)
	if err != nil {
		log.Fatalf("load spoof IPs: %v", err)
	}

	var psIP net.IP
	if peerSpoofIP != "" {
		psIP = net.ParseIP(peerSpoofIP)
		if psIP == nil {
			log.Fatalf("invalid peer-spoof-ip: %s", peerSpoofIP)
		}
	}

	if listen == "" {
		listen = "127.0.0.1:5000"
	}
	if sendTransport == "" {
		sendTransport = "tcp"
	}
	if recvTransport == "" {
		recvTransport = "udp"
	}

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	cfg := relay.LocalConfig{
		ListenAddr:    listen,
		RemoteIP:      rIP,
		RemotePort:    uint16(remotePort),
		RecvPort:      uint16(recvPort),
		SpoofIPs:      spoofIPs,
		SpoofPort:     uint16(spoofPort),
		PeerSpoofIP:   psIP,
		SendTransport: sendTransport,
		RecvTransport: recvTransport,
	}

	l, err := relay.NewLocal(cfg)
	if err != nil {
		log.Fatalf("init local relay: %v", err)
	}

	fmt.Println("═══════════ Spoof Tunnel v" + Version + " (local) ═══════════")
	fmt.Println("═══════════ Rust Transport Engine ═══════════")
	fmt.Println("═══════════ Developed by https://github.com/ParsaKSH ═══════════")
	fmt.Printf("  Listen:      %s (UDP)\n", listen)
	fmt.Printf("  Remote:      %s:%d\n", remoteAddr, remotePort)
	fmt.Printf("  Recv port:   %d\n", recvPort)
	fmt.Printf("  Spoof IPs:   %d (round-robin)\n", len(spoofIPs))
	fmt.Printf("  Spoof port:  %d\n", spoofPort)
	fmt.Printf("  Send:        %s\n", sendTransport)
	fmt.Printf("  Recv:        %s\n", recvTransport)
	fmt.Println()

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		up, down := l.Stats()
		log.Printf("shutting down (up=%d down=%d)", up, down)
		l.Close()
		os.Exit(0)
	}()

	l.Run()
}

func runRemote(listenPort int, forward, clientIP string, clientPort int, spoofIP string, spoofPort int, peerSpoofIP string, spoofIPFile, sendTransport, recvTransport string) {
	cIP := net.ParseIP(clientIP)
	if cIP == nil {
		log.Fatalf("invalid client-ip: %s", clientIP)
	}

	spoofIPs, err := loadSpoofIPs(spoofIP, spoofIPFile)
	if err != nil {
		log.Fatalf("load spoof IPs: %v", err)
	}

	var psIP net.IP
	if peerSpoofIP != "" {
		psIP = net.ParseIP(peerSpoofIP)
		if psIP == nil {
			log.Fatalf("invalid peer-spoof-ip: %s", peerSpoofIP)
		}
	}

	if sendTransport == "" {
		sendTransport = "udp"
	}
	if recvTransport == "" {
		recvTransport = "tcp"
	}

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	cfg := relay.RemoteConfig{
		ListenPort:    uint16(listenPort),
		ForwardAddr:   forward,
		ClientIP:      cIP,
		ClientPort:    uint16(clientPort),
		SpoofIPs:      spoofIPs,
		SpoofPort:     uint16(spoofPort),
		PeerSpoofIP:   psIP,
		SendTransport: sendTransport,
		RecvTransport: recvTransport,
	}

	r, err := relay.NewRemote(cfg)
	if err != nil {
		log.Fatalf("init remote relay: %v", err)
	}

	fmt.Println("═══════════ Spoof Tunnel v" + Version + " (remote) ═══════════")
	fmt.Println("═══════════ Rust Transport Engine ═══════════")
	fmt.Println("═══════════ Developed by https://github.com/ParsaKSH ═══════════")
	fmt.Printf("  Listen:      port %d\n", listenPort)
	fmt.Printf("  Forward:     %s (UDP)\n", forward)
	fmt.Printf("  Client:      %s:%d\n", clientIP, clientPort)
	fmt.Printf("  Spoof IPs:   %d (round-robin)\n", len(spoofIPs))
	fmt.Printf("  Spoof port:  %d\n", spoofPort)
	fmt.Printf("  Send:        %s\n", sendTransport)
	fmt.Printf("  Recv:        %s\n", recvTransport)
	fmt.Println()

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		up, down := r.Stats()
		log.Printf("shutting down (up=%d down=%d)", up, down)
		r.Close()
		os.Exit(0)
	}()

	r.Run()
}

func requireRoot() {
	if os.Geteuid() != 0 {
		log.Fatal("must run as root (raw sockets require CAP_NET_RAW)")
	}
}
