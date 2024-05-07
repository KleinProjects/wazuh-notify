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

	flag.StringVar(&inputParams.Server, "server", "", "is the webhook URL of the Discord server. It is stored in .env.")
	flag.StringVar(&inputParams.Click, "click", "", "is a link (URL) that can be followed by tapping/clicking inside the message. Default is https://google.com.")
	flag.StringVar(&inputParams.Destination, "destination", "", "is the destination (actually the originator) of the message, either an app name or a person. Default is \"Wazuh (IDS)\"")
	flag.StringVar(&inputParams.Message, "message", "", "is the text of the message to be sent. Default is \"Test message\", but may include --tags and/or --click.")
	flag.IntVar(&inputParams.Priority, "priority", 0, "is the priority of the message, ranging from 1 (highest), to 5 (lowest). Default is 5.")
	flag.StringVar(&inputParams.Sender, "sender", "", "is the sender of the message, either an app name or a person. The default is \"Security message\".")
	flag.StringVar(&inputParams.Tags, "tags", "", "is an arbitrary strings of tags (keywords), seperated by a \",\" (comma). Default is \"informational,testing,hard-coded\".")
	flag.StringVar(&inputParams.Targets, "targets", "", "is a list of targets to send notifications to. Default is \"discord\".")

	flag.Parse()

	yamlFile, err := os.ReadFile("./config.yaml")
	yaml.Unmarshal(yamlFile, &configParams)

	if inputParams.Server == "" {
		inputParams.Server = configParams.Server
	}
	if inputParams.Click == "" {
		inputParams.Click = configParams.Click
	}
	if inputParams.Destination == "" {
		inputParams.Destination = configParams.Destination
	}
	if inputParams.Message == "" {
		inputParams.Message = configParams.Message
	}
	if inputParams.Priority == 0 {
		inputParams.Priority = configParams.Priority
	}
	if inputParams.Sender == "" {
		inputParams.Sender = configParams.Sender
	}
	if inputParams.Tags == "" {
		inputParams.Tags = configParams.Tags
	}
	if inputParams.Targets == "" {
		inputParams.Targets = configParams.Targets
	}
}
