package services

import (
	"bufio"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"wazuh-notify/services/log"
	"wazuh-notify/types"
)

func ParseWazuhInput(params types.Params) types.Params {

	var wazuhData types.WazuhMessage
	//Read stdin
	reader := bufio.NewReader(os.Stdin)
	//Decode stdin to wazuhData
	json.NewDecoder(reader).Decode(&wazuhData)
	//Parse tags
	params.Tags += strings.Join(wazuhData.Parameters.Alert.Rule.Groups, ",")

	params.WazuhMessage = wazuhData
	//Map priority and color based on config
	for i := range params.PriorityMap {
		if slices.Contains(params.PriorityMap[i].ThreatMap, wazuhData.Parameters.Alert.Rule.Level) {
			//Check notify threshold
			if params.WazuhMessage.Parameters.Alert.Rule.Firedtimes%params.PriorityMap[i].NotifyThreshold != 0 {
				log.Log("threshold not met")
				log.CloseLogFile()
				os.Exit(0)
			}
			//Set color based on config map
			params.Color = params.PriorityMap[i].Color
			//Check mention threshold
			if params.WazuhMessage.Parameters.Alert.Rule.Firedtimes >= params.PriorityMap[i].MentionThreshold {
				params.Mention = "@here"
			}
			params.Priority = 5 - i
		}
	}

	log.Log("Wazuh data loaded")
	//Filter messages based on rules defined in config
	Filter(params)

	return params
}
