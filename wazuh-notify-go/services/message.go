package services

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"wazuh-notify/types"
)

func BuildMessage(params types.Params, target string, emphasis string) string {

	if slices.Contains(strings.Split(params.General.FullAlert, ","), target) {
		fullAlert, _ := json.MarshalIndent(params.WazuhMessage, "", "  ")
		fullAlertString := strings.ReplaceAll(string(fullAlert), `"`, "")
		fullAlertString = strings.ReplaceAll(fullAlertString, "{", "")
		fullAlertString = strings.ReplaceAll(fullAlertString, "}", "")
		fullAlertString = strings.ReplaceAll(fullAlertString, "[", "")
		fullAlertString = strings.ReplaceAll(fullAlertString, "]", "")
		fullAlertString = strings.ReplaceAll(fullAlertString, " ,", "")

		return "\n\n ```" +
			fullAlertString +
			"```\n\n"
	} else {
		return "\n\n" +
			fmt.Sprintf("%sTimestamp:%s ", emphasis, emphasis) + time.Now().Format(time.DateTime) + "\n" +
			fmt.Sprintf("%sAgent:%s ", emphasis, emphasis) + params.WazuhMessage.Parameters.Alert.Agent.Name + "\n" +
			fmt.Sprintf("%sEvent id:%s ", emphasis, emphasis) + params.WazuhMessage.Parameters.Alert.Rule.ID + "\n" +
			fmt.Sprintf("%sRule:%s ", emphasis, emphasis) + params.WazuhMessage.Parameters.Alert.Rule.Description + "\n" +
			fmt.Sprintf("%sDescription:%s ", emphasis, emphasis) + params.WazuhMessage.Parameters.Alert.FullLog + "\n" +
			fmt.Sprintf("%sThreat level:%s ", emphasis, emphasis) + strconv.Itoa(params.WazuhMessage.Parameters.Alert.Rule.Level) + "\n" +
			fmt.Sprintf("%sTimes fired:%s ", emphasis, emphasis) + strconv.Itoa(params.WazuhMessage.Parameters.Alert.Rule.Firedtimes) +
			"\n\n" +
			fmt.Sprintf("%sPriority:%s ", emphasis, emphasis) + strconv.Itoa(params.Priority) + "\n"

	}
}
