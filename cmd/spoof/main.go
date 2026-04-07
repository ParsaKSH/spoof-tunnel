package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/ParsaKSH/spooftunnel/internal/config"
	"github.com/ParsaKSH/spooftunnel/internal/crypto"
	"github.com/ParsaKSH/spooftunnel/internal/tunnel"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	Version    = "1.0.0"
	ConfigFile = "config.json"
	blue       = color.New(color.FgBlue).SprintFunc()
	red        = color.New(color.FgRed).SprintFunc()
	yellow     = color.New(color.FgYellow).SprintFunc()
	green      = color.New(color.FgGreen).SprintFunc()
)

var mainCmd = &cobra.Command{
	Use:     "spoof",
	Version: Version,
	Run: func(cmd *cobra.Command, args []string) {
		if os.Geteuid() != 0 {
			log.Println(yellow("Warning: Running without root privileges. Raw sockets may fail."))
			log.Println("Run with: sudo ./spoof -c client-config.json")
			log.Printf("")
		}

		cfg, err := config.Load(ConfigFile)
		if err != nil {
			log.Printf(red("Failed to load config"))
			log.Printf(red(err))
			return
		}

		log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
		if cfg.Logging.File != "" {
			f, err := os.OpenFile(cfg.Logging.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Printf(yellow("Failed to load config"))
				log.Printf(yellow(err))
			} else {
				log.SetOutput(f)
			}
		}

		keyPair, err := crypto.ParsePrivateKey(cfg.Crypto.PrivateKey)
		if err != nil {
			log.Printf(red("Failed to parse private key"))
			log.Printf(red(err))
			return
		}

		peerPubKey, err := crypto.ParsePublicKey(cfg.Crypto.PeerPublicKey)
		if err != nil {
			log.Printf(red("Failed to parse peer public key"))
			log.Printf(red(err))
			return
		}

		sharedSecret, err := crypto.ComputeSharedSecret(keyPair.PrivateKey, peerPubKey)
		if err != nil {
			log.Printf(red("Failed to compute shared secret"))
			log.Printf(red(err))
			return
		}

		isInitiator := cfg.Mode == config.ModeClient
		sendKey, recvKey, err := crypto.DeriveSessionKeys(sharedSecret, isInitiator)
		if err != nil {
			log.Printf(red("Failed to derive session keys"))
			log.Printf(red(err))
			return
		}

		cipher, err := crypto.NewCipher(sendKey, recvKey)
		if err != nil {
			log.Printf(red("Failed to create cipher"))
			log.Printf(red(err))
			return
		}

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

		fmt.Println()
		fmt.Println(green("============ Spoof Tunnel " + Version + " ============"))
		fmt.Printf("%-30s %s\n", "Mode:", cfg.Mode)
		fmt.Printf("%-30s %s\n", "Transport:", cfg.Transport.Type)
		fmt.Printf("%-30s %s\n", "Local public key:", keyPair.PublicKeyBase64())
		if cfg.Transport.Type == config.TransportICMP {
			fmt.Printf("%-30s %s\n", "ICMP Mode:", blue(cfg.Transport.ICMPMode))
		}

		switch cfg.Mode {
		case config.ModeClient:
			runClient(cfg, cipher, sigCh)
		case config.ModeServer:
			runServer(cfg, cipher, sigCh)
		}
	},
}

func main() {
	mainCmd.DisableSuggestions = false
	mainCmd.CompletionOptions.DisableDefaultCmd = true
	mainCmd.SetHelpCommand(&cobra.Command{})

	mainCmd.Flags().StringVarP(
		&ConfigFile,
		"config",
		"c",
		ConfigFile,
		"config file",
	)

	if err := mainCmd.Execute(); err != nil {
		panic(err)
	}
}

func runClient(cfg *config.Config, cipher *crypto.Cipher, sigCh chan os.Signal) {
	fmt.Printf("%-30s %s\n", "Server:", cfg.GetServerAddr())
	fmt.Printf("%-30s %s\n", "Spoof source IP:", cfg.Spoof.SourceIP)
	if cfg.Spoof.PeerSpoofIP != "" {
		fmt.Printf("%-30s %s\n", "Expected server spoof IP:", cfg.Spoof.PeerSpoofIP)
	}
	fmt.Println()
	for _, inb := range cfg.Inbounds {
		switch inb.Type {
		case config.InboundSocks:
			fmt.Printf("%-30s %s\n", "Inbound [socks]:", inb.Listen)
		case config.InboundRelay:
			fmt.Printf("%-30s %s\n", "Inbound [relay]:", inb.Listen)
		case config.InboundForward:
			fmt.Printf("%-30s %s → %s\n", "Inbound [forward]:", inb.Listen, inb.Target)
		}
	}
	fmt.Println()
	log.Printf(blue("Starting client mode..."))

	fmt.Println()
	log.Printf(blue("Starting client mode..."))

	client, err := tunnel.NewClient(cfg, cipher)
	if err != nil {
		log.Printf(red("Failed to create client"))
		log.Printf(red(err))
		return
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
	fmt.Printf("%-30s %d\n", "Listening on port:", cfg.Listen.Port)
	fmt.Printf("%-30s %s\n", "Spoof source IP:", cfg.Spoof.SourceIP)
	if cfg.Spoof.PeerSpoofIP != "" {
		fmt.Printf("%-30s %s\n", "Expected client spoof IP:", cfg.Spoof.PeerSpoofIP)
	}

	fmt.Println()
	log.Printf(blue("Starting server mode..."))

	server, err := tunnel.NewServer(cfg, cipher)
	if err != nil {
		log.Printf(red("Failed to create server"))
		log.Printf(red(err))
		return
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
