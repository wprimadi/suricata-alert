# Suricata Alert

![Go Version](https://img.shields.io/github/go-mod/go-version/wprimadi/suricata-alert) 
![License](https://img.shields.io/github/license/wprimadi/suricata-alert) 
![Stars](https://img.shields.io/github/stars/wprimadi/suricata-alert?style=social) 
![Last Commit](https://img.shields.io/github/last-commit/wprimadi/suricata-alert) 
![Go Report Card](https://goreportcard.com/badge/github.com/wprimadi/suricata-alert) 
![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=wprimadi_suricata-alert&metric=alert_status) 
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-blue) 

Suricata Alert is a Go-based tool that monitors Suricata's `eve.json` log file and sends security alerts to a Telegram chat when an event meets the configured severity threshold. It also supports optional IP blocking via firewall rules.

## Features
- Monitors Suricata's `eve.json` file in real time
- Filters alerts based on severity
- Sends notifications to Telegram
- Ignores alerts from local IP addresses (configurable)
- Blocks source IPs that trigger alerts (except local IPs)
- Ensures blocked IPs persist across reboots

## Requirements
- Go 1.18+
- Suricata installed and generating `eve.json`
- A Telegram bot and chat ID
- Firewall tools (`iptables`/`ip6tables`) for IP blocking

## Installation

1. Clone the repository:
   ```sh
   git clone https://github.com/wprimadi/suricata-alert.git
   cd suricata-alert
   ```
2. Build the application:
   ```sh
   go build -o suricata-alert
   ```
3. Ensures blocked IPs persist across reboots
   ```sh
   sudo apt update && sudo apt install -y iptables-persistent netfilter-persistent
   sudo systemctl enable netfilter-persistent
   sudo systemctl restart netfilter-persistent
   ```
4. Create a `.env` file in the project root:
   ```ini
   EVE_FILE_PATH=/var/log/suricata/eve.json
   SEVERITY_THRESHOLD=2
   TELEGRAM_BOT_TOKEN=YOUR_TELEGRAM_BOT_TOKEN_HERE
   TELEGRAM_CHAT_ID=YOUR_TELEGRAM_CHAT_ID_HERE
   IGNORE_LOCAL_IP=true
   ENABLE_FIREWALL_BLOCKING=true
   ```

## Usage

⚠️ This application requires root privileges to modify firewall rules.
You can run it directly using `sudo`:
```sh
sudo ./suricata-alert
```
Or set it up as a systemd service (recommended):
1. Create a systemd service file:
   ```sh
   sudo nano /etc/systemd/system/suricata-alert.service
   ```
   Add the following:
   ```ini
   [Unit]
   Description=Suricata Alert Service
   After=network.target

   [Service]
   Type=simple
   ExecStart=/path/to/suricata-alert
   Restart=always
   User=root

   [Install]
   WantedBy=multi-user.target
   ```
   (Replace `/path/to/suricata-alert` with the actual path of the binary.)
2. Enable and start the service:
   ```sh
   sudo systemctl daemon-reload
   sudo systemctl enable suricata-alert
   sudo systemctl start suricata-alert
   ```
3. Check service status:
   ```sh
   sudo systemctl status suricata-alert
   ```
The program will monitor `eve.json` for new alerts and send notifications to Telegram if the severity is below or equal to the configured threshold. If `IGNORE_LOCAL_IP` is enabled, alerts from local IPs will be ignored. If `ENABLE_FIREWALL_BLOCKING` is enabled, source IPs causing alerts will be blocked via `iptables` or `ip6tables`.

## Persistent IP Blocking

To ensure that blocked IPs remain after a system reboot, the tool automatically saves iptables rules using:
```sh
sudo netfilter-persistent save
```
You can manually verify the saved rules with:
```sh
sudo iptables -L -v -n
```
In case you need to restore saved rules after a reboot:
```sh
sudo netfilter-persistent reload
```

## Environment Variables
| Variable                   | Description                                                     |
|----------------------------|-----------------------------------------------------------------|
| `EVE_FILE_PATH`            | Path to Suricata's `eve.json` log file                          |
| `SEVERITY_THRESHOLD`       | Maximum severity level to trigger alerts                        |
| `TELEGRAM_BOT_TOKEN`       | Telegram bot API token                                          |
| `TELEGRAM_CHAT_ID`         | Telegram chat ID where alerts are sent                          |
| `IGNORE_LOCAL_IP`          | If `true`, local IP alerts are ignored                          |
| `ENABLE_FIREWALL_BLOCKING` | If `true`, source IPs causing alerts are blocked                |
| `FIREWALL_ENGINE`          | Firewall engine to use: `iptables` or `ufw`                     |
| `WHITELIST_IP`             | Comma-separated list of IPs that will not be blocked or alerted |

### Firewall Engine Options

The `FIREWALL_ENGINE` environment variable allows you to choose the firewall method:
- `iptables` (default): Uses `iptables` rules to block IPs.
- `ufw`: Uses Uncomplicated Firewall (UFW) to block IPs.
If you use `ufw`, ensure it is installed and active:
```sh
sudo apt install ufw -y
sudo ufw enable
```

## License
This project is licensed under the MIT License.

## Author
Developed by Wahyu Primadi (@wprimadi).
