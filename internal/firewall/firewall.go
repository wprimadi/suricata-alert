package firewall

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
)

func IsLocalIP(ip string) bool {
	privateIPBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.1/32",
		"169.254.0.0/16",
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, cidr := range privateIPBlocks {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("Error parsing CIDR %s: %v", cidr, err)
			continue
		}
		if ipNet.Contains(parsedIP) {
			return true
		}
	}
	return false
}

func ensureUFWEnabled() error {
	cmd := exec.Command("ufw", "status")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to check UFW status: %s", err)
	}

	if !strings.Contains(string(output), "Status: active") {
		log.Println("UFW is inactive, enabling it now...")
		enableCmd := exec.Command("ufw", "enable")
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
	cmd := exec.Command("ufw", "deny", "from", ip)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("error blocking IP %s: %s, %s", ip, err, string(output))
		return
	}
	log.Printf("Blocked IP %s using %s", ip, fwEngine)
}

func blockIPUsingIptables(ip string, fwEngine string) {
	checkIPv4 := "iptables -C INPUT -s {IP} -j DROP"
	blockIPv4 := "iptables -A INPUT -s {IP} -j DROP"
	checkIPv6 := "ip6tables -C INPUT -s {IP} -j DROP"
	blockIPv6 := "ip6tables -A INPUT -s {IP} -j DROP"

	if net.ParseIP(ip).To4() != nil {
		checkCmd := exec.Command("sh", "-c", strings.Replace(checkIPv4, "{IP}", ip, -1))
		if err := checkCmd.Run(); err == nil {
			log.Printf("IPv4 %s is already blocked", ip)
			return
		}

		cmd := exec.Command("sh", "-c", strings.Replace(blockIPv4, "{IP}", ip, -1))
		if err := cmd.Run(); err != nil {
			log.Printf("Failed to block IPv4 %s using %s, error: %v", ip, fwEngine, err)
		} else {
			log.Printf("Blocked IPv4 %s using %s", ip, fwEngine)
		}
	} else {
		checkCmd := exec.Command("sh", "-c", strings.Replace(checkIPv6, "{IP}", ip, -1))
		if err := checkCmd.Run(); err == nil {
			log.Printf("IPv6 %s is already blocked", ip)
			return
		}

		cmd := exec.Command("sh", "-c", strings.Replace(blockIPv6, "{IP}", ip, -1))
		if err := cmd.Run(); err != nil {
			log.Printf("Failed to block IPv6 %s using %s, error: %v", ip, fwEngine, err)
		} else {
			log.Printf("Blocked IPv6 %s using %s", ip, fwEngine)
		}
	}

	saveCmd := exec.Command("sudo", "netfilter-persistent", "save")
	if err := saveCmd.Run(); err != nil {
		log.Printf("Gagal menyimpan aturan iptables: %v", err)
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
