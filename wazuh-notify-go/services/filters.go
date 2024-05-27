package services

import (
	"os"
	"strings"
	"wazuh-notify/log"
)

func Filter() {
	for _, rule := range strings.Split(inputParams.General.ExcludedRules, ",") {
		if rule == inputParams.WazuhMessage.Parameters.Alert.Rule.ID {
			log.Log("rule excluded")
			log.CloseLogFile()
			os.Exit(0)
		}
	}
	for _, agent := range strings.Split(inputParams.General.ExcludedAgents, ",") {
		if agent == inputParams.WazuhMessage.Parameters.Alert.Agent.ID {
			log.Log("agent excluded")
			log.CloseLogFile()
			os.Exit(0)
		}
	}
}
