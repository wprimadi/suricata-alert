package monitor

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"strings"
	"time"

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
		if err := json.Unmarshal([]byte(line), &alert); err == nil {
			if alert.EventType == "alert" && alert.Alert.Severity <= severity {
				log.Println("New Alert:", alert.Alert.Signature)
				telegram.SendAlert(hostname, alert.Alert.Category, alert.Alert.Signature, alert.Alert.Severity, alert.SrcIP, alert.DestIP, alert.Timestamp)
			}
		}
	}
}
