// File: main.go
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"suricata-alert/internal/config"
	"suricata-alert/internal/logger"
	"suricata-alert/internal/monitor"
)

func main() {
	// Load configuration
	if err := config.LoadEnv(); err != nil {
		log.Fatal("Error loading environment variables: ", err)
	}

	// Initialize logger
	logger.InitLogger()
	log.Println("Starting Suricata Alert Bot...")

	// Start monitoring Suricata logs
	eveFilePath := os.Getenv("EVE_FILE_PATH")
	if eveFilePath == "" {
		log.Fatal("EVE_FILE_PATH is not set in environment variables")
	}

	go monitor.TailFile(eveFilePath)

	// Graceful shutdown
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	log.Println("Shutting down...")
}
