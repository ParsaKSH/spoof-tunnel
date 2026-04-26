package relay

import (
	"fmt"
	"log"
	"os/exec"
	"runtime"
)

// suppressICMPEchoReply disables kernel automatic ICMP echo replies.
// This prevents the kernel from responding to ICMP echo request packets
// that we want to handle ourselves.
func suppressICMPEchoReply() bool {
	switch runtime.GOOS {
	case "linux":
		err := exec.Command("sysctl", "-w", "net.ipv4.icmp_echo_ignore_all=1").Run()
		if err != nil {
			log.Printf("[warn] failed to suppress ICMP echo replies: %v", err)
			return false
		}
		log.Printf("[info] suppressed kernel ICMP echo replies (sysctl net.ipv4.icmp_echo_ignore_all=1)")
		return true
	case "freebsd", "openbsd":
		err := exec.Command("sysctl", "net.inet.icmp.bmcastecho=0").Run()
		if err != nil {
			log.Printf("[warn] failed to suppress ICMP echo replies on %s: %v", runtime.GOOS, err)
			return false
		}
		log.Printf("[info] suppressed kernel ICMP echo replies (sysctl net.inet.icmp.bmcastecho=0)")
		return true
	default:
		log.Printf("[warn] ICMP echo reply suppression not supported on %s", runtime.GOOS)
		return false
	}
}

// restoreICMPEchoReply re-enables kernel automatic ICMP echo replies.
func restoreICMPEchoReply() {
	switch runtime.GOOS {
	case "linux":
		err := exec.Command("sysctl", "-w", "net.ipv4.icmp_echo_ignore_all=0").Run()
		if err != nil {
			log.Printf("[warn] failed to restore ICMP echo replies: %v", err)
			return
		}
		log.Printf("[info] restored kernel ICMP echo replies (sysctl net.ipv4.icmp_echo_ignore_all=0)")
	case "freebsd", "openbsd":
		err := exec.Command("sysctl", "net.inet.icmp.bmcastecho=1").Run()
		if err != nil {
			log.Printf("[warn] failed to restore ICMP echo replies on %s: %v", runtime.GOOS, err)
			return
		}
		log.Printf("[info] restored kernel ICMP echo replies")
	}
}

// formatBytes formats byte count to human-readable string.
func formatBytes(b uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case b >= GB:
		return fmt.Sprintf("%.2f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.2f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.2f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
