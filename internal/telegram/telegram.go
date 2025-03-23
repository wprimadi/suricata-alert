package telegram

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
)

type TelegramMessage struct {
	ChatID string `json:"chat_id"`
	Text   string `json:"text"`
}

// SendAlert sends an alert to Telegram
func SendAlert(hostname string, category string, signature string, severity int, source string, destination string, timestamp string) {
	telegramBotToken := os.Getenv("TELEGRAM_BOT_TOKEN")
	telegramChatID := os.Getenv("TELEGRAM_CHAT_ID")
	if telegramBotToken == "" || telegramChatID == "" {
		log.Println("Telegram bot token or chat ID is missing")
		return
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", telegramBotToken)
	message := TelegramMessage{
		ChatID: telegramChatID,
		Text:   fmt.Sprintf("🚨 SECURITY ALERT! 🚨\n\n🖥️ %s\n\n⚠️ Category: %s\n🔴 Signature: %s\n⚡ Severity: %d\n💀 Source: %s\n🎯 Destination: %s\n🕒 Timestamp: %s", hostname, category, signature, severity, source, destination, timestamp),
	}
	data, _ := json.Marshal(message)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		log.Println("Error creating request:", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error sending alert:", err)
		return
	}
	defer resp.Body.Close()

	log.Println("Alert sent successfully")
}
