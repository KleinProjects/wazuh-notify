package main

import (
	"strings"
	"wazuh-notify/log"
	"wazuh-notify/notification"
	"wazuh-notify/services"
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
			notification.SendNtfy(inputParams)
		case "slack":
			log.Log(target)
			notification.SendSlack(inputParams)
		}
	}
	log.CloseLogFile()
}
