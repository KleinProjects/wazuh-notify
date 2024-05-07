package main

import (
	"strings"
	"wazuh-notify/notification"
	"wazuh-notify/types"
)

var inputParams types.Params

func main() {
	initNotify()
	for _, target := range strings.Split(inputParams.Targets, ",") {
		switch target {
		case "discord":
			notification.SendDiscord(inputParams)
		case "ntfy":
			notification.SendNtfy(inputParams)
		}
	}
}
