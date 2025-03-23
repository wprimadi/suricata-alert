package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

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

func sendTelegramMessage(message string) error {
	telegramBotToken := os.Getenv("TELEGRAM_BOT_TOKEN")
	telegramChatID := os.Getenv("TELEGRAM_CHAT_ID")

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", telegramBotToken)
	data := fmt.Sprintf(`{"chat_id": "%s", "text": "%s"}`, telegramChatID, message)

	req, err := http.NewRequest("POST", url, strings.NewReader(data))
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
		processLine(strings.TrimSpace(line))
	}
}

func processLine(line string) {
	var alert SuricataAlert
	if err := json.Unmarshal([]byte(line), &alert); err == nil {
		if alert.EventType == "alert" {
			message := fmt.Sprintf("🚨 SECURITY ALERT! 🚨\n\n⚠️ Category: %s\n🔴 Signature: %s\nPriority: %d\n💀 Source: %s\n🎯 Destination: %s\n🕒 Timestamp: %s",
				alert.Alert.Category, alert.Alert.Signature, alert.Alert.Severity, alert.SrcIP, alert.DestIP, alert.Timestamp)
			sendTelegramMessage(message)
		}
	}
}

func watchFile(filePath string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	done := make(chan bool)
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write {
					tailFile(filePath)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("error:", err)
			}
		}
	}()

	if err := watcher.Add(filePath); err != nil {
		log.Fatal(err)
	}
	<-done
}

func main() {
	_ = godotenv.Load()
	eveFilePath := os.Getenv("EVE_FILE_PATH")
	if _, err := os.Stat(eveFilePath); os.IsNotExist(err) {
		log.Fatal("Eve file does not exist")
	}
	tailFile(eveFilePath)
	watchFile(eveFilePath)
}
