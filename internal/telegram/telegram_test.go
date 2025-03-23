package telegram

import (
	"encoding/json"
	"testing"
)

func TestSendAlertMessageFormat(t *testing.T) {
	message := TelegramMessage{
		ChatID: "123456",
		Text:   "Test Alert Message",
	}

	data, err := json.Marshal(message)
	if err != nil {
		t.Fatalf("Failed to marshal Telegram message: %v", err)
	}

	expected := `{"chat_id":"123456","text":"Test Alert Message"}`
	if string(data) != expected {
		t.Errorf("Expected %s, got %s", expected, string(data))
	}
}
