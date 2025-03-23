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
	"sync"

	"github.com/fsnotify/fsnotify"
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

func sendTelegramMessage(message string) {
	telegramBotToken := os.Getenv("TELEGRAM_BOT_TOKEN")
	telegramChatID := os.Getenv("TELEGRAM_CHAT_ID")

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", telegramBotToken)
	data := fmt.Sprintf(`{"chat_id": "%s", "text": "%s"}`, telegramChatID, message)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(data)))
	if err != nil {
		log.Println("Error creating request:", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error sending message to Telegram:", err)
		return
	}
	defer resp.Body.Close()
}

func processAlert(line string, severityThreshold int, hostname string, wg *sync.WaitGroup) {
	defer wg.Done()

	var alert SuricataAlert
	if err := json.Unmarshal([]byte(line), &alert); err == nil {
		if alert.EventType == "alert" && alert.Alert.Severity <= severityThreshold {
			message := fmt.Sprintf("🚨 SECURITY ALERT! 🚨\n\n🖥️ %s\n\n⚠️ Category: %s\n🔴 Signature: %s\nPriority: %d\n💀 Source: %s\n🎯 Destination: %s\n🕒 Timestamp: %s",
				hostname, alert.Alert.Category, alert.Alert.Signature, alert.Alert.Severity, alert.SrcIP, alert.DestIP, alert.Timestamp)
			sendTelegramMessage(message)
		}
	}
}

func watchFile(filePath string) {
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
		log.Fatal("Error opening file:", err)
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	var wg sync.WaitGroup

	// Inisialisasi file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal("Error creating watcher:", err)
	}
	defer watcher.Close()

	err = watcher.Add(filePath)
	if err != nil {
		log.Fatal("Error watching file:", err)
	}

	log.Println("Monitoring Suricata alerts...")
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&fsnotify.Write == fsnotify.Write {
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						break
					}
					wg.Add(1)
					go processAlert(line, severityThreshold, hostname, &wg)
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Println("Watcher error:", err)
		}
	}
	wg.Wait()
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file:", err)
	}
	eveFilePath := os.Getenv("EVE_FILE_PATH")
	if eveFilePath == "" {
		log.Fatal("EVE_FILE_PATH is not set in the environment")
	}

	if _, err := os.Stat(eveFilePath); os.IsNotExist(err) {
		log.Fatal("Eve log file does not exist")
	}

	watchFile(eveFilePath)
}
