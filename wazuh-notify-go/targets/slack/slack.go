package slack

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"wazuh-notify/services"
	"wazuh-notify/types"
)

func SendSlack(params types.Params) {
	//Build message
	message := SlackMessage{
		Text: services.BuildMessage(params, "slack", params.MarkdownEmphasis.Slack) +
			"*Tags:* " + params.Tags + "\n\n" +
			params.General.Click,
	}

	payload := new(bytes.Buffer)
	//Parse message to json
	err := json.NewEncoder(payload).Encode(message)
	if err != nil {
		return
	}
	//Send message to webhook
	_, err = http.Post(os.Getenv("SLACK_URL"), "application/json", payload)
	if err != nil {
		log.Fatalf("An Error Occured %v", err)
	}
}
