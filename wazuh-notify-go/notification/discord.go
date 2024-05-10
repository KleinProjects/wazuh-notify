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
			"**Description:** " + params.WazuhMessage.Parameters.Alert.Rule.Description + "\n" +
			"**Threat level:** " + strconv.Itoa(params.WazuhMessage.Parameters.Alert.Rule.Level) + "\n" +
			"**Times fired:** " + strconv.Itoa(params.WazuhMessage.Parameters.Alert.Rule.Firedtimes) +
			"\n\n" +
			"Priority: " + strconv.Itoa(params.Priority) + "\n" +
			"Tags: " + params.Tags + "\n\n" +
			params.Click
	}

	var color int

	switch params.Priority {
	case 1:
		color = 0x339900
	case 2:
		color = 0x99cc33
	case 3:
		color = 0xffcc00
	case 4:
		color = 0xff9966
	case 5:
		color = 0xcc3300
	}

	message := types.Message{
		Username: params.Sender,
		Embeds: []types.Embed{
			{
				Title:       params.Sender,
				Description: embedDescription,
				Color:       color,
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
