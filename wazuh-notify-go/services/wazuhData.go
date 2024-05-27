package services

import (
	"bufio"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"wazuh-notify/log"
	"wazuh-notify/types"
)

func ParseWazuhInput(params types.Params) types.Params {

	var wazuhData types.WazuhMessage

	reader := bufio.NewReader(os.Stdin)

	json.NewDecoder(reader).Decode(&wazuhData)

	params.Tags += strings.Join(wazuhData.Parameters.Alert.Rule.Groups, ",")

	params.WazuhMessage = wazuhData

	for i := range params.PriorityMap {
		if slices.Contains(params.PriorityMap[i].ThreatMap, wazuhData.Parameters.Alert.Rule.Level) {
			if params.WazuhMessage.Parameters.Alert.Rule.Firedtimes%params.PriorityMap[i].NotifyThreshold != 0 {
				log.Log("threshold not met")
				log.CloseLogFile()
				os.Exit(0)
			}
			params.Color = params.PriorityMap[i].Color
			if params.WazuhMessage.Parameters.Alert.Rule.Firedtimes >= params.PriorityMap[i].MentionThreshold {
				params.Mention = "@here"
			}
			params.Priority = 5 - i
		}
	}

	log.Log("Wazuh data loaded")

	Filter(params)

	return params
}
