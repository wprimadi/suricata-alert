package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
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

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

func sendTelegramMessage(message string) error {
	telegramBotToken := os.Getenv("TELEGRAM_BOT_TOKEN")
	telegramChatID := os.Getenv("TELEGRAM_CHAT_ID")

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", telegramBotToken)
	data := fmt.Sprintf(`{"chat_id": "%s", "text": "%s"}`, telegramChatID, message)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(data)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func tailFile(filePath string) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "Unknown"
	}

	severityThreshold, err := strconv.Atoi(os.Getenv("SEVERITY_THRESHOLD"))
	if err != nil {
		severityThreshold = 2
	}

	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
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
			if alert.EventType == "alert" && alert.Alert.Severity <= severityThreshold {
				fmt.Println(line)

				message := fmt.Sprintf("🚨 SECURITY ALERT! 🚨\n\n🖥️ %s\n\n⚠️ Category: %s\n🔴 Signature: %s\nPriority: %d\n💀 Source: %s\n🎯 Destination: %s\n🕒 Timestamp: %s",
					hostname, alert.Alert.Category, alert.Alert.Signature, alert.Alert.Severity, alert.SrcIP, alert.DestIP, alert.Timestamp)
				err := sendTelegramMessage(message)
				if err != nil {
					log.Fatal(err.Error())
				}
			}
		}
	}
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}

	fmt.Println("Starting Suricata Telegram Alert...")
	eveFilePath := os.Getenv("EVE_FILE_PATH")
	if fileExists(eveFilePath) {
		tailFile(eveFilePath)
	} else {
		log.Fatal("Eve file does not exists")
		os.Exit(1)
	}
}
