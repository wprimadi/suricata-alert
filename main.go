// File: main.go
package main

import (
	"log"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"suricata-alert/internal/config"
	permission "suricata-alert/internal/linux_permission"
	"suricata-alert/internal/logger"
	"suricata-alert/internal/monitor"
)

func main() {
	// Initialize logger
	logger.InitLogger()
	log.Println("Starting Suricata Alert...")

	log.Printf("Checking operating system: %s", runtime.GOOS)
	if strings.ToLower(runtime.GOOS) == "linux" {
		isRoot, err := permission.CheckLinuxRootPermission()
		if err != nil {
			log.Fatal("Error checking for operating system user permission: ", err)
		}

		if !isRoot {
			log.Fatal("Sorry, this program requires root privileges to run. Please execute it with sudo or as the root user.")
		}
	}

	// Load configuration
	if err := config.LoadEnv(); err != nil {
		log.Fatal("Error loading environment variables: ", err)
	}

	// Get current OS hostname
	hostname, err := os.Hostname()
	if err != nil {
		log.Fatal(err.Error())
	}

	// Start monitoring Suricata logs
	eveFilePath := os.Getenv("EVE_FILE_PATH")
	if eveFilePath == "" {
		log.Fatal("EVE_FILE_PATH is not set in environment variables")
	}

	severity, err := strconv.Atoi(os.Getenv("SEVERITY_THRESHOLD"))
	if err != nil {
		log.Fatal(err.Error())
	}

	go monitor.TailFile(hostname, eveFilePath, severity)

	// Graceful shutdown
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	log.Println("Shutting down...")
}
