package firewall

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
)

var privateIPBlocks = []*net.IPNet{
	{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
	{IP: net.IPv4(172, 16, 0, 0), Mask: net.CIDRMask(12, 32)},
	{IP: net.IPv4(192, 168, 0, 0), Mask: net.CIDRMask(16, 32)},
	{IP: net.IPv4(127, 0, 0, 1), Mask: net.CIDRMask(32, 32)},
	{IP: net.IPv4(169, 254, 0, 0), Mask: net.CIDRMask(16, 32)},
}

func IsLocalIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, ipNet := range privateIPBlocks {
		if ipNet.Contains(parsedIP) {
			return true
		}
	}
	return false
}

func ensureUFWEnabled() error {
	ufwPath, err := exec.LookPath("ufw")
	if err != nil {
		return fmt.Errorf("ufw not found in PATH")
	}

	cmd := exec.Command(ufwPath, "status")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to check UFW status: %s", err)
	}

	if !strings.Contains(string(output), "Status: active") {
		log.Println("UFW is inactive, enabling it now...")
		enableCmd := exec.Command(ufwPath, "enable")
		if _, err := enableCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to enable UFW: %s", err)
		}
		log.Println("UFW enabled successfully.")
	}
	return nil
}

func BlockIP(ip string) {
	var firewallEngine = os.Getenv("FIREWALL_ENGINE")

	if firewallEngine == "ufw" {
		if err := ensureUFWEnabled(); err != nil {
			log.Printf(err.Error())
		} else {
			blockIPUsingUfw(ip, firewallEngine)
		}
	} else {
		blockIPUsingIptables(ip, firewallEngine)
	}

}

func blockIPUsingUfw(ip string, fwEngine string) {
	ufwPath, err := exec.LookPath("ufw")
	if err != nil {
		log.Println("ufw not found in PATH")
		return
	}

	cmd := exec.Command(ufwPath, "insert", "1", "deny", "from", ip)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("error blocking IP %s: %s, %s", ip, err, string(output))
		return
	}
	log.Printf("Blocked IP %s using %s", ip, fwEngine)
}

func blockIPUsingIptables(ip string, fwEngine string) {
	iptablesPath, ip6tablesPath, netfilterPath, err := getIptablesPaths()
	if err != nil {
		log.Println(err)
		return
	}

	if net.ParseIP(ip).To4() != nil {
		blockIP(ip, iptablesPath, fwEngine)
	} else {
		blockIP(ip, ip6tablesPath, fwEngine)
	}

	saveIptablesRules(netfilterPath)
}

// Fungsi untuk mendapatkan path dari iptables, ip6tables, dan netfilter-persistent
func getIptablesPaths() (string, string, string, error) {
	iptablesPath, err := exec.LookPath("iptables")
	if err != nil {
		return "", "", "", fmt.Errorf("iptables not found in PATH")
	}

	ip6tablesPath, err := exec.LookPath("ip6tables")
	if err != nil {
		return "", "", "", fmt.Errorf("ip6tables not found in PATH")
	}

	netfilterPath, err := exec.LookPath("netfilter-persistent")
	if err != nil {
		return "", "", "", fmt.Errorf("netfilter-persistent not found in PATH")
	}

	return iptablesPath, ip6tablesPath, netfilterPath, nil
}

// Fungsi untuk memeriksa dan memblokir IP jika belum diblokir
func blockIP(ip, iptablesPath, fwEngine string) {
	checkCmd := exec.Command("sh", "-c", fmt.Sprintf("%s -C INPUT -s %s -j DROP", iptablesPath, ip))
	if err := checkCmd.Run(); err == nil {
		log.Printf("IP %s is already blocked", ip)
		return
	}

	blockCmd := exec.Command("sh", "-c", fmt.Sprintf("%s -A INPUT -s %s -j DROP", iptablesPath, ip))
	if err := blockCmd.Run(); err != nil {
		log.Printf("Failed to block IP %s using %s, error: %v", ip, fwEngine, err)
	} else {
		log.Printf("Blocked IP %s using %s", ip, fwEngine)
	}
}

// Fungsi untuk menyimpan aturan iptables
func saveIptablesRules(netfilterPath string) {
	saveCmd := exec.Command(netfilterPath, "save")
	if err := saveCmd.Run(); err != nil {
		log.Printf("Failed to save iptables rules: %v", err)
	}
}

func GetWhitelistedIPs() map[string]bool {
	whitelist := make(map[string]bool)
	whitelistEnv := os.Getenv("WHITELIST_IP")

	if whitelistEnv != "" {
		ips := strings.Split(whitelistEnv, ",")
		for _, ip := range ips {
			whitelist[strings.TrimSpace(ip)] = true
		}
	}

	return whitelist
}
