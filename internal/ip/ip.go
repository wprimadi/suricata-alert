package ip

import (
	"log"
	"net"
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

func BlockIP(ip string) {
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
			log.Printf("Failed to block IPv4: %s, error: %v", ip, err)
		} else {
			log.Printf("Blocked IPv4: %s", ip)
		}
	} else {
		checkCmd := exec.Command("sh", "-c", strings.Replace(checkIPv6, "{IP}", ip, -1))
		if err := checkCmd.Run(); err == nil {
			log.Printf("IPv6 %s is already blocked", ip)
			return
		}

		cmd := exec.Command("sh", "-c", strings.Replace(blockIPv6, "{IP}", ip, -1))
		if err := cmd.Run(); err != nil {
			log.Printf("Failed to block IPv6: %s, error: %v", ip, err)
		} else {
			log.Printf("Blocked IPv6: %s", ip)
		}
	}
}
