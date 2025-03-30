package monitor

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"time"

	"suricata-alert/internal/firewall"
	"suricata-alert/internal/telegram"
)

type SuricataAlert struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	Alert     struct {
		Category  string `json:"category"`
		Signature string `json:"signature"`
		Severity  int    `json:"severity"`
	} `json:"alert"`
	SrcIP  string `json:"src_ip"`
	DestIP string `json:"dest_ip"`
}

// TailFile continuously reads the Suricata log file
func TailFile(hostname string, filePath string, severity int) {
	for {
		file, err := os.Open(filePath)
		if err != nil {
			log.Println("Error opening file:", err)
			time.Sleep(2 * time.Second)
			continue
		}

		if err := tailLoop(file, filePath, hostname, severity); err != nil {
			log.Println("Error in tail loop:", err)
		}

		file.Close()
	}
}

func tailLoop(file *os.File, filePath, hostname string, severity int) error {
	reader := bufio.NewReader(file)
	file.Seek(0, io.SeekEnd)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				if isLogRotated(filePath) {
					log.Println("Log file rotated, reopening...")
					return nil
				}
				time.Sleep(time.Second)
				continue
			}
			return fmt.Errorf("error reading file: %w", err)
		}

		processLogLine(hostname, line, severity)
	}
}

func isLogRotated(filePath string) bool {
	stat, _ := os.Stat(filePath)
	return stat == nil || stat.Size() < fileSize(filePath)
}

func fileSize(filePath string) int64 {
	stat, err := os.Stat(filePath)
	if err != nil {
		return 0
	}
	return stat.Size()
}

func processLogLine(hostname, line string, severity int) {
	var alert SuricataAlert

	if err := json.Unmarshal([]byte(line), &alert); err != nil {
		return
	}

	if alert.EventType != "alert" || alert.Alert.Severity > severity {
		return
	}

	if shouldIgnoreAlert(alert.SrcIP) {
		return
	}

	if shouldBlockIP(alert.SrcIP) {
		firewall.BlockIP(alert.SrcIP)
	}

	log.Println("New Alert:", alert.Alert.Signature)
	telegram.SendAlert(hostname, alert.Alert.Category, alert.Alert.Signature, alert.Alert.Severity, alert.SrcIP, alert.DestIP, alert.Timestamp)
}

func shouldIgnoreAlert(ip string) bool {
	if firewall.IsLocalIP(ip) {
		ignoreLocalIP, err := strconv.ParseBool(os.Getenv("IGNORE_LOCAL_IP"))
		if err != nil {
			log.Println("Invalid value for IGNORE_LOCAL_IP, defaulting to false. ", err)
			return false
		}
		if ignoreLocalIP {
			log.Println("Ignored Telegram alert notification, source IP is local IP")
			return true
		}
	}

	if firewall.GetWhitelistedIPs()[ip] {
		log.Printf("IP %s is whitelisted, skipping Telegram alert\n", ip)
		return true
	}

	return false
}

func shouldBlockIP(ip string) bool {
	enableBlocking, err := strconv.ParseBool(os.Getenv("ENABLE_FIREWALL_BLOCKING"))
	if err != nil {
		log.Println("Invalid value for ENABLE_FIREWALL_BLOCKING, defaulting to false. ", err)
		return false
	}
	return enableBlocking
}
