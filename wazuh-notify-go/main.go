package main

import (
	"strings"
	"wazuh-notify/services"
	"wazuh-notify/services/log"
	"wazuh-notify/targets/discord"
	"wazuh-notify/targets/ntfy"
	"wazuh-notify/targets/slack"
)

func main() {
	//Read config file and .env
	configParams := services.ReadConfig()
	//Parse command line flags
	inputParams := services.ParseFlags(configParams)
	//Parse wazuh input data from stdin
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
