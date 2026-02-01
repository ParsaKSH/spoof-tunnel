package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/ParsaKSH/spooftunnel/internal/config"
	"github.com/ParsaKSH/spooftunnel/internal/crypto"
	"github.com/ParsaKSH/spooftunnel/internal/tunnel"
)

var (
	configPath = flag.String("config", "config.json", "path to config file")
	genKeys    = flag.Bool("generate-keys", false, "generate new key pair and exit")
	version    = flag.Bool("version", false, "show version and exit")
)

// Build info (set via ldflags)
var (
	Version   = "1.0.0"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

func main() {
	flag.Parse()

	// Handle version
	if *version {
		fmt.Printf("spoof-tunnel %s\n", Version)
		fmt.Printf("  Build time: %s\n", BuildTime)
		fmt.Printf("  Git commit: %s\n", GitCommit)
		fmt.Printf("  Go version: %s\n", runtime.Version())
		fmt.Printf("  OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
		return
	}

	// Handle key generation
	if *genKeys {
		generateKeys()
		return
	}

	// Check for root privileges (required for raw sockets)
	if os.Geteuid() != 0 {
		log.Println("Warning: Running without root privileges. Raw sockets may fail.")
		log.Println("         Run with: sudo ./spoof -config config.json")
	}

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Setup logging
	setupLogging(cfg)

	log.Printf("=== Spoof Tunnel %s ===", Version)
	log.Printf("Mode: %s", cfg.Mode)
	log.Printf("Transport: %s", cfg.Transport.Type)
	if cfg.Transport.Type == config.TransportICMP {
		log.Printf("ICMP Mode: %s", cfg.Transport.ICMPMode)
	}

	// Initialize crypto
	keyPair, err := crypto.ParsePrivateKey(cfg.Crypto.PrivateKey)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}

	peerPubKey, err := crypto.ParsePublicKey(cfg.Crypto.PeerPublicKey)
	if err != nil {
		log.Fatalf("Failed to parse peer public key: %v", err)
	}

	// Compute shared secret
	sharedSecret, err := crypto.ComputeSharedSecret(keyPair.PrivateKey, peerPubKey)
	if err != nil {
		log.Fatalf("Failed to compute shared secret: %v", err)
	}

	// Derive session keys
	isInitiator := cfg.Mode == config.ModeClient
	sendKey, recvKey, err := crypto.DeriveSessionKeys(sharedSecret, isInitiator)
	if err != nil {
		log.Fatalf("Failed to derive session keys: %v", err)
	}

	// Create cipher
	cipher, err := crypto.NewCipher(sendKey, recvKey)
	if err != nil {
		log.Fatalf("Failed to create cipher: %v", err)
	}

	log.Printf("Crypto initialized successfully")
	log.Printf("Local public key: %s", keyPair.PublicKeyBase64())

	// Setup signal handler
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Run based on mode
	switch cfg.Mode {
	case config.ModeClient:
		runClient(cfg, cipher, sigCh)
	case config.ModeServer:
		runServer(cfg, cipher, sigCh)
	}
}

func runClient(cfg *config.Config, cipher *crypto.Cipher, sigCh chan os.Signal) {
	log.Printf("Starting client mode...")
	log.Printf("SOCKS5 proxy: %s", cfg.GetListenAddr())
	log.Printf("Server: %s", cfg.GetServerAddr())
	log.Printf("Spoof source IP: %s", cfg.Spoof.SourceIP)
	if cfg.Spoof.PeerSpoofIP != "" {
		log.Printf("Expected server spoof IP: %s", cfg.Spoof.PeerSpoofIP)
	}

	client, err := tunnel.NewClient(cfg, cipher)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Start client in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- client.Start()
	}()

	// Wait for signal or error
	select {
	case sig := <-sigCh:
		log.Printf("Received signal: %v", sig)
	case err := <-errCh:
		if err != nil {
			log.Printf("Client error: %v", err)
		}
	}

	// Shutdown
	log.Println("Shutting down client...")
	client.Stop()

	// Print stats
	sent, received := client.Stats()
	log.Printf("Stats: sent=%d bytes, received=%d bytes", sent, received)
}

func runServer(cfg *config.Config, cipher *crypto.Cipher, sigCh chan os.Signal) {
	log.Printf("Starting server mode...")
	log.Printf("Listening on port: %d", cfg.Listen.Port)
	log.Printf("Spoof source IP: %s", cfg.Spoof.SourceIP)
	if cfg.Spoof.PeerSpoofIP != "" {
		log.Printf("Expected client spoof IP: %s", cfg.Spoof.PeerSpoofIP)
	}

	server, err := tunnel.NewServer(cfg, cipher)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()

	// Wait for signal or error
	select {
	case sig := <-sigCh:
		log.Printf("Received signal: %v", sig)
	case err := <-errCh:
		if err != nil {
			log.Printf("Server error: %v", err)
		}
	}

	// Shutdown
	log.Println("Shutting down server...")
	server.Stop()

	// Print stats
	sent, received, sessions := server.Stats()
	log.Printf("Stats: sent=%d bytes, received=%d bytes, active_sessions=%d", sent, received, sessions)
}

func generateKeys() {
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate keys: %v", err)
	}

	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    GENERATED KEY PAIR                          ║")
	fmt.Println("╠════════════════════════════════════════════════════════════════╣")
	fmt.Printf("║ Private Key: %-50s ║\n", keyPair.PrivateKeyBase64())
	fmt.Printf("║ Public Key:  %-50s ║\n", keyPair.PublicKeyBase64())
	fmt.Println("╠════════════════════════════════════════════════════════════════╣")
	fmt.Println("║ INSTRUCTIONS:                                                  ║")
	fmt.Println("║ 1. Add private_key to YOUR config.json                         ║")
	fmt.Println("║ 2. Share public_key with your PEER                             ║")
	fmt.Println("║ 3. Add peer's public_key to your peer_public_key               ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
}

func setupLogging(cfg *config.Config) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	if cfg.Logging.File != "" {
		f, err := os.OpenFile(cfg.Logging.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("Warning: could not open log file: %v", err)
		} else {
			log.SetOutput(f)
		}
	}
}
