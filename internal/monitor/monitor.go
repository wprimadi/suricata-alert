package monitor

import (
	"bufio"
	"encoding/json"
	"errors"
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

		reader := bufio.NewReader(file)
		defer file.Close()

		file.Seek(0, io.SeekEnd)

		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				if errors.Is(err, io.EOF) {
					stat, _ := os.Stat(filePath)
					if stat == nil || stat.Size() < fileSize(filePath) {
						log.Println("Log file rotated, reopening...")
						break
					}
					time.Sleep(time.Second)
					continue
				}
				log.Println("Error reading file:", err)
				break
			}

			processLogLine(hostname, line, severity)
		}
	}
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
