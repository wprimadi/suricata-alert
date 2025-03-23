package logger

import (
	"log"
	"os"
)

// InitLogger initializes the logger
func InitLogger() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}
