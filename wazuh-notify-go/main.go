package main

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"wazuh-notify/notification"
	"wazuh-notify/types"
)

var inputParams types.Params
var wazuhData types.WazuhMessage

func main() {
	initNotify()

	reader := bufio.NewReader(os.Stdin)

	json.NewDecoder(reader).Decode(&wazuhData) //todo for later

	text, _ := reader.ReadString('\n') //todo for testing
	inputParams.Message = text

	for _, target := range strings.Split(inputParams.Targets, ",") {
		switch target {
		case "discord":
			notification.SendDiscord(inputParams)
		case "ntfy":
			notification.SendNtfy(inputParams)
		}
	}
}
