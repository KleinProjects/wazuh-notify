package notification

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"wazuh-notify/types"
)

func SendDiscord(params types.Params) {
	embedDescription := "\n\n" +
		"**Agent:** " + params.WazuhMessage.Parameters.Alert.Agent.Name + "\n" +
		"**Event id:** " + params.WazuhMessage.Parameters.Alert.Rule.ID + "\n" +
		"**Description:** " + params.WazuhMessage.Parameters.Alert.Rule.Description + "\n" +
		"**Threat level:** " + strconv.Itoa(params.WazuhMessage.Parameters.Alert.Rule.Level) + "\n" +
		"**Times fired:** " + strconv.Itoa(params.WazuhMessage.Parameters.Alert.Rule.Firedtimes) +
		"\n\n" +
		"Priority: " + strconv.Itoa(params.Priority) + "\n" +
		"Tags: " + params.Tags + "\n\n" +
		params.Click

	message := types.Message{
		Username: params.Sender,
		Embeds: []types.Embed{
			{
				Title:       params.Sender,
				Description: embedDescription,
			},
		},
	}

	payload := new(bytes.Buffer)

	err := json.NewEncoder(payload).Encode(message)
	if err != nil {
		return
	}

	_, err = http.Post(os.Getenv("DISCORD_WEBHOOK"), "application/json", payload)
	if err != nil {
		log.Fatalf("An Error Occured %v", err)
	}
}
