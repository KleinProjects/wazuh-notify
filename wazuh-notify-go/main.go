package main

import (
	"strings"
	"wazuh-notify/log"
	"wazuh-notify/notification"
	"wazuh-notify/ntfy"
	"wazuh-notify/services"
	"wazuh-notify/slack"
)

func main() {
	inputParams := services.InitNotify()

	for _, target := range strings.Split(inputParams.General.Targets, ", ") {
		switch target {
		case "discord":
			log.Log(target)
			notification.SendDiscord(inputParams)
		case "ntfy":
			log.Log(target)
			ntfy.SendNtfy(inputParams)
		case "slack":
			log.Log(target)
			slack.SendSlack(inputParams)
		}
	}
	log.CloseLogFile()
}
