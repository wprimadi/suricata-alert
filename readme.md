# Suricata Alert

Suricata Alert is a Go-based tool that monitors Suricata's `eve.json` log file and sends security alerts to a Telegram chat when an event meets the configured severity threshold.

## Features
- Monitors Suricata's `eve.json` file in real time
- Filters alerts based on severity
- Sends notifications to Telegram

## Requirements
- Go 1.18+
- Suricata installed and generating `eve.json`
- A Telegram bot and chat ID

## Installation

1. Clone the repository:
   ```sh
   git clone https://github.com/yourusername/suricata-alert.git
   cd suricata-alert
   ```
2. Build the application:
   ```sh
   go build -o suricata-alert
   ```
3. Create a `.env` file in the project root:
   ```ini
   EVE_FILE_PATH=/var/log/suricata/eve.json
   SEVERITY_THRESHOLD=2
   TELEGRAM_BOT_TOKEN=YOUR_TELEGRAM_BOT_TOKEN_HERE
   TELEGRAM_CHAT_ID=YOUR_TELEGRAM_CHAT_ID_HERE
   ```

## Usage

Run the application:
```sh
./suricata-alert
```
The program will monitor `eve.json` for new alerts and send notifications to Telegram if the severity is below or equal to the configured threshold.

## Environment Variables
| Variable             | Description                                |
|----------------------|--------------------------------------------|
| `EVE_FILE_PATH`     | Path to Suricata's `eve.json` log file     |
| `SEVERITY_THRESHOLD`| Maximum severity level to trigger alerts   |
| `TELEGRAM_BOT_TOKEN`| Telegram bot API token                    |
| `TELEGRAM_CHAT_ID`  | Telegram chat ID where alerts are sent     |

## License
This project is licensed under the MIT License.

## Author
Developed by Wahyu Primadi (@wprimadi).

