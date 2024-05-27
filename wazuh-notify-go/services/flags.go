package services

import (
	"flag"
	"wazuh-notify/services/log"
	"wazuh-notify/types"
)

func ParseFlags(params types.Params) types.Params {
	//Set command line flags
	flag.StringVar(&params.General.Click, "click", params.General.Click, "is a link (URL) that can be followed by tapping/clicking inside the message. Default is https://google.com.")
	flag.StringVar(&params.General.Sender, "sender", params.General.Sender+" Golang", "is the sender of the message, either an app name or a person. The default is \"Security message\".")
	flag.StringVar(&params.General.Targets, "targets", params.General.Targets, "is a list of targets to send notifications to. Default is \"discord\".")
	//Get flag values
	flag.Parse()

	log.Log("flags loaded")

	return params
}
