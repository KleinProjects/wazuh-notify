package services

import (
	"os"
	"strings"
	"wazuh-notify/services/log"
	"wazuh-notify/types"
)

func Filter(params types.Params) {
	for _, rule := range strings.Split(params.General.ExcludedRules, ",") {
		if rule == params.WazuhMessage.Parameters.Alert.Rule.ID {
			log.Log("rule excluded")
			log.CloseLogFile()
			os.Exit(0)
		}
	}
	for _, agent := range strings.Split(params.General.ExcludedAgents, ",") {
		if agent == params.WazuhMessage.Parameters.Alert.Agent.ID {
			log.Log("agent excluded")
			log.CloseLogFile()
			os.Exit(0)
		}
	}
}
