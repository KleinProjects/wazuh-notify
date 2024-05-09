package services

import (
	"bufio"
	"encoding/json"
	"flag"
	"github.com/joho/godotenv"
	"gopkg.in/yaml.v2"
	"os"
	"wazuh-notify/log"
	"wazuh-notify/types"
)

var inputParams types.Params
var configParams types.Params
var wazuhData types.WazuhMessage

func InitNotify() types.Params {
	err := godotenv.Load()
	if err != nil {
		log.Log("env failed to load")
	} else {
		log.Log("env loaded")
	}

	wazuhInput()

	yamlFile, err := os.ReadFile("./config.yaml")
	yaml.Unmarshal(yamlFile, &configParams)

	log.Log("yaml loaded")

	flag.StringVar(&inputParams.Url, "url", "", "is the webhook URL of the Discord server. It is stored in .env.")
	flag.StringVar(&inputParams.Click, "click", configParams.Click, "is a link (URL) that can be followed by tapping/clicking inside the message. Default is https://google.com.")
	flag.IntVar(&inputParams.Priority, "priority", 0, "is the priority of the message, ranging from 1 (highest), to 5 (lowest). Default is 5.")
	flag.StringVar(&inputParams.Sender, "sender", configParams.Sender, "is the sender of the message, either an app name or a person. The default is \"Security message\".")
	flag.StringVar(&inputParams.Tags, "tags", "", "is an arbitrary strings of tags (keywords), seperated by a \",\" (comma). Default is \"informational,testing,hard-coded\".")
	flag.StringVar(&inputParams.Targets, "targets", "", "is a list of targets to send notifications to. Default is \"discord\".")

	flag.Parse()

	log.Log("yaml loaded")
	inputParams.Targets = configParams.Targets

	return inputParams
}

func wazuhInput() {
	reader := bufio.NewReader(os.Stdin)

	json.NewDecoder(reader).Decode(&wazuhData)

	mapPriority()

	inputParams.WazuhMessage = wazuhData
}
