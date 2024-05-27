package notification

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"wazuh-notify/services"
	"wazuh-notify/types"
)

func SendDiscord(params types.Params) {

	embedDescription := services.BuildMessage(params, "discord", params.MarkdownEmphasis.Discord) +
		"**Tags:** " + params.Tags + "\n\n" +
		params.General.Click

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
