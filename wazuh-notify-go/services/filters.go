package services

import (
	"os"
	"strings"
	"wazuh-notify/log"
)

func Filter() {
	for _, rule := range strings.Split(inputParams.ExcludedRules, ",") {
		if rule == inputParams.WazuhMessage.Parameters.Alert.Rule.ID {
			log.Log("rule excluded")
			log.CloseLogFile()
			os.Exit(0)
		}
	}
	for _, agent := range strings.Split(inputParams.ExcludedAgents, ",") {
		if agent == inputParams.WazuhMessage.Parameters.Alert.Agent.ID {
			log.Log("agent excluded")
			log.CloseLogFile()
			os.Exit(0)
		}
	}
}
