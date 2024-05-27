package notification

import (
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"wazuh-notify/types"
)

func SendNtfy(params types.Params) {

	var payload string

	if slices.Contains(strings.Split(params.General.FullAlert, ","), "discord") {
		fullAlert, _ := json.MarshalIndent(params.WazuhMessage, "", "  ")
		fullAlertString := strings.ReplaceAll(string(fullAlert), `"`, "")
		fullAlertString = strings.ReplaceAll(fullAlertString, "{", "")
		fullAlertString = strings.ReplaceAll(fullAlertString, "}", "")
		fullAlertString = strings.ReplaceAll(fullAlertString, "[", "")
		fullAlertString = strings.ReplaceAll(fullAlertString, "]", "")
		fullAlertString = strings.ReplaceAll(fullAlertString, " ,", "")

		payload = "\n\n ```" +
			fullAlertString +
			"```"
	} else {
		payload = time.Now().Format(time.RFC3339) + "\n\n" +
			"**Agent:** " + params.WazuhMessage.Parameters.Alert.Agent.Name + "\n" +
			"**Event id:** " + params.WazuhMessage.Parameters.Alert.Rule.ID + "\n" +
			"**Description:** " + params.WazuhMessage.Parameters.Alert.Rule.Description + "\n" +
			"**Threat level:** " + strconv.Itoa(params.WazuhMessage.Parameters.Alert.Rule.Level) + "\n" +
			"**Times fired:** " + strconv.Itoa(params.WazuhMessage.Parameters.Alert.Rule.Firedtimes) + "\n"
	}

	req, _ := http.NewRequest("POST", os.Getenv("NTFY_URL"), strings.NewReader(payload))
	req.Header.Set("Content-Type", "text/markdown")

	if params.General.Sender != "" {
		req.Header.Add("Title", params.General.Sender)
	}
	if params.Tags != "" {
		req.Header.Add("Tags", params.Tags)
	}
	if params.General.Click != "" {
		req.Header.Add("Click", params.General.Click)
	}
	if params.Priority != 0 {
		req.Header.Add("Priority", strconv.Itoa(params.Priority))
	}

	http.DefaultClient.Do(req)
}
