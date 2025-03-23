package logger

import "testing"

func TestInitLogger(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Logger initialization panicked: %v", r)
		}
	}()
	InitLogger()
}
