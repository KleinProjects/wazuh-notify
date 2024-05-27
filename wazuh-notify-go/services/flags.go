package services

import (
	"flag"
	"wazuh-notify/log"
	"wazuh-notify/types"
)

func ParseFlags(params types.Params) types.Params {

	flag.StringVar(&params.Url, "url", "", "is the webhook URL of the Discord server. It is stored in .env.")
	flag.StringVar(&params.General.Click, "click", params.General.Click, "is a link (URL) that can be followed by tapping/clicking inside the message. Default is https://google.com.")
	flag.IntVar(&params.Priority, "priority", 0, "is the priority of the message, ranging from 1 (highest), to 5 (lowest). Default is 5.")
	flag.StringVar(&params.General.Sender, "sender", params.General.Sender+" Golang", "is the sender of the message, either an app name or a person. The default is \"Security message\".")
	flag.StringVar(&params.Tags, "tags", "", "is an arbitrary strings of tags (keywords), seperated by a \",\" (comma). Default is \"informational,testing,hard-coded\".")
	flag.StringVar(&params.General.Targets, "targets", params.General.Targets, "is a list of targets to send notifications to. Default is \"discord\".")

	flag.Parse()

	log.Log("params loaded")

	return params
}
