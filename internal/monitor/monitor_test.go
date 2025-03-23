package monitor

import (
	"encoding/json"
	"testing"
)

func TestParseSuricataAlert(t *testing.T) {
	jsonData := `{"timestamp":"2024-10-20T12:34:56Z","event_type":"alert","alert":{"category":"Test Category","signature":"Test Signature","severity":2},"src_ip":"192.168.1.1","dest_ip":"192.168.1.2"}`

	var alert SuricataAlert
	err := json.Unmarshal([]byte(jsonData), &alert)
	if err != nil {
		t.Fatalf("Failed to parse Suricata alert: %v", err)
	}

	if alert.Alert.Signature != "Test Signature" {
		t.Errorf("Expected signature 'Test Signature', got '%s'", alert.Alert.Signature)
	}
}
