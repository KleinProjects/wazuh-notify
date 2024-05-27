package notification

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"wazuh-notify/services"
	"wazuh-notify/types"
)

func SendSlack(params types.Params) {

	message := types.SlackMessage{
		Text: services.BuildMessage(params, "slack", params.MarkdownEmphasis.Slack) +
			"*Priority:* " + strconv.Itoa(params.Priority) + "\n" +
			"*Tags:* " + params.Tags + "\n\n" +
			params.General.Click,
	}

	payload := new(bytes.Buffer)

	err := json.NewEncoder(payload).Encode(message)
	if err != nil {
		return
	}

	_, err = http.Post(os.Getenv("SLACK_URL"), "application/json", payload)
	if err != nil {
		log.Fatalf("An Error Occured %v", err)
	}
}
