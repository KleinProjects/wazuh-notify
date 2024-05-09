package main

import (
	"flag"
	"github.com/joho/godotenv"
	"gopkg.in/yaml.v2"
	"log"
	"os"
	"wazuh-notify/types"
)

var configParams types.Params

func initNotify() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf(".env not found: %v", err)
		return
	}

	yamlFile, err := os.ReadFile("./config.yaml")
	yaml.Unmarshal(yamlFile, &configParams)

	flag.StringVar(&inputParams.Server, "server", "", "is the webhook URL of the Discord server. It is stored in .env.")
	flag.StringVar(&inputParams.Click, "click", configParams.Click, "is a link (URL) that can be followed by tapping/clicking inside the message. Default is https://google.com.")
	flag.StringVar(&inputParams.Destination, "destination", "", "is the destination (actually the originator) of the message, either an app name or a person. Default is \"Wazuh (IDS)\"")
	flag.StringVar(&inputParams.Message, "message", "", "is the text of the message to be sent. Default is \"Test message\", but may include --tags and/or --click.")
	flag.IntVar(&inputParams.Priority, "priority", 0, "is the priority of the message, ranging from 1 (highest), to 5 (lowest). Default is 5.")
	flag.StringVar(&inputParams.Sender, "sender", configParams.Sender, "is the sender of the message, either an app name or a person. The default is \"Security message\".")
	flag.StringVar(&inputParams.Tags, "tags", "", "is an arbitrary strings of tags (keywords), seperated by a \",\" (comma). Default is \"informational,testing,hard-coded\".")
	flag.StringVar(&inputParams.Targets, "targets", "", "is a list of targets to send notifications to. Default is \"discord\".")

	flag.Parse()
	inputParams.Targets = configParams.Targets
}
