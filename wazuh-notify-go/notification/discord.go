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
	"wazuh-notify/types"
)

func SendDiscord(params types.Params) {

	var embedDescription string

	if slices.Contains(strings.Split(params.FullMessage, ","), "discord") {
		fullMessage, _ := json.MarshalIndent(params.WazuhMessage, "", "  ")
		fullMessageString := strings.ReplaceAll(string(fullMessage), `"`, "")
		fullMessageString = strings.ReplaceAll(fullMessageString, "{", "")
		fullMessageString = strings.ReplaceAll(fullMessageString, "}", "")
		fullMessageString = strings.ReplaceAll(fullMessageString, "[", "")
		fullMessageString = strings.ReplaceAll(fullMessageString, "]", "")
		fullMessageString = strings.ReplaceAll(fullMessageString, " ,", "")

		embedDescription = "\n\n ```" +
			fullMessageString +
			"```\n\n" +
			"Priority: " + strconv.Itoa(params.Priority) + "\n" +
			"Tags: " + params.Tags + "\n\n" +
			params.Click
	} else {
		embedDescription = "\n\n" +
			"**Agent:** " + params.WazuhMessage.Parameters.Alert.Agent.Name + "\n" +
			"**Event id:** " + params.WazuhMessage.Parameters.Alert.Rule.ID + "\n" +
			"**Rule:** " + params.WazuhMessage.Parameters.Alert.Rule.Description + "\n" +
			"**Description: **" + params.WazuhMessage.Parameters.Alert.FullLog + "\n" +
			"**Threat level:** " + strconv.Itoa(params.WazuhMessage.Parameters.Alert.Rule.Level) + "\n" +
			"**Times fired:** " + strconv.Itoa(params.WazuhMessage.Parameters.Alert.Rule.Firedtimes) +
			"\n\n" +
			"Priority: " + strconv.Itoa(params.Priority) + "\n" +
			"Tags: " + params.Tags + "\n\n" +
			params.Click
	}

	message := types.Message{
		Username: params.Sender,
		Content:  params.Mention,
		Embeds: []types.Embed{
			{
				Title:       params.Sender,
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
