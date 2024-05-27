package main

import (
	"strings"
	"wazuh-notify/discord"
	"wazuh-notify/log"
	"wazuh-notify/ntfy"
	"wazuh-notify/services"
	"wazuh-notify/slack"
)

func main() {
	configParams := services.ReadConfig()

	inputParams := services.ParseFlags(configParams)

	Params := services.ParseWazuhInput(inputParams)

	for _, target := range strings.Split(Params.General.Targets, ", ") {
		switch target {
		case "discord":
			log.Log(target)
			discord.SendDiscord(Params)
		case "ntfy":
			log.Log(target)
			ntfy.SendNtfy(Params)
		case "slack":
			log.Log(target)
			slack.SendSlack(Params)
		}
	}
	log.CloseLogFile()
}
