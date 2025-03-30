package monitor

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"suricata-alert/internal/ip"
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
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatal("Error opening file:", err)
	}
	defer file.Close()

	file.Seek(0, os.SEEK_END)
	reader := bufio.NewReader(file)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			time.Sleep(time.Second)
			continue
		}

		line = strings.TrimSpace(line)
		var alert SuricataAlert
		var sendAlert bool = false

		if err := json.Unmarshal([]byte(line), &alert); err == nil {
			if alert.EventType == "alert" && alert.Alert.Severity <= severity {
				if ip.IsLocalIP(alert.SrcIP) {
					ignoreLocalIP, err := strconv.ParseBool(os.Getenv("IGNORE_LOCAL_IP"))
					if err != nil {
						sendAlert = true
						log.Println("Invalid value for IGNORE_LOCAL_IP, defaulting to false. ", err)
					} else {
						if ignoreLocalIP {
							sendAlert = false
							log.Println("Ignored Telegram alert notification, source IP is local IP")
						} else {
							sendAlert = true
						}
					}
				} else {
					enableBlocking, err := strconv.ParseBool(os.Getenv("ENABLE_FIREWALL_BLOCKING"))
					if err != nil {
						log.Println("Invalid value for ENABLE_FIREWALL_BLOCKING, defaulting to false. ", err)
					}

					if enableBlocking {
						ip.BlockIP(alert.SrcIP)
					}

					sendAlert = true
				}

				if sendAlert {
					log.Println("New Alert:", alert.Alert.Signature)
					telegram.SendAlert(hostname, alert.Alert.Category, alert.Alert.Signature, alert.Alert.Severity, alert.SrcIP, alert.DestIP, alert.Timestamp)
				}
			}
		}
	}
}
