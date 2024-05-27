package notification

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"wazuh-notify/types"
)

func SendDiscord(params types.Params) {

	var embedDescription string

	if slices.Contains(strings.Split(params.General.FullAlert, ","), "discord") {
		fullAlert, _ := json.MarshalIndent(params.WazuhMessage, "", "  ")
		fullAlertString := strings.ReplaceAll(string(fullAlert), `"`, "")
		fullAlertString = strings.ReplaceAll(fullAlertString, "{", "")
		fullAlertString = strings.ReplaceAll(fullAlertString, "}", "")
		fullAlertString = strings.ReplaceAll(fullAlertString, "[", "")
		fullAlertString = strings.ReplaceAll(fullAlertString, "]", "")
		fullAlertString = strings.ReplaceAll(fullAlertString, " ,", "")

		embedDescription = "\n\n ```" +
			fullAlertString +
			"```\n\n" +
			"Priority: " + strconv.Itoa(params.Priority) + "\n" +
			"Tags: " + params.Tags + "\n\n" +
			params.General.Click
	} else {
		embedDescription = "\n\n" +
			"**Timestamp: **" + time.Now().Format(time.DateTime) + "\n" +
			"**Agent:** " + params.WazuhMessage.Parameters.Alert.Agent.Name + "\n" +
			"**Event id:** " + params.WazuhMessage.Parameters.Alert.Rule.ID + "\n" +
			"**Rule:** " + params.WazuhMessage.Parameters.Alert.Rule.Description + "\n" +
			"**Description: **" + params.WazuhMessage.Parameters.Alert.FullLog + "\n" +
			"**Threat level:** " + strconv.Itoa(params.WazuhMessage.Parameters.Alert.Rule.Level) + "\n" +
			"**Times fired:** " + strconv.Itoa(params.WazuhMessage.Parameters.Alert.Rule.Firedtimes) +
			"\n\n" +
			"**Priority:** " + strconv.Itoa(params.Priority) + "\n" +
			"**Tags:** " + params.Tags + "\n\n" +
			params.General.Click
	}

	message := types.DiscordMessage{
		Username: params.General.Sender,
		Content:  params.Mention,
		Embeds: []types.Embed{
			{
				Title:       params.General.Sender,
				Description: embedDescription,
				Color:       params.Color,
			},
		},
	}

	payload := new(bytes.Buffer)

	err := json.NewEncoder(payload).Encode(message)
	if err != nil {
		return
	}

	_, err = http.Post(os.Getenv("DISCORD_URL"), "application/json", payload)
	if err != nil {
		log.Fatalf("An Error Occured %v", err)
	}
}
