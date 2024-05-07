package notification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"wazuh-notify/types"
)

func SendDiscord(params types.Params) {
	embedDescription := fmt.Sprintf("\n\n %s \n\nPriority: %x\nTags: %s\n\n%s",
		params.Message,
		params.Priority,
		params.Tags,
		params.Click,
	)

	message := types.Message{
		Username: params.Sender,
		Embeds: []types.Embed{
			{
				Title:       params.Destination,
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
