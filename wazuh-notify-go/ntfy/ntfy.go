package ntfy

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"wazuh-notify/services"
	"wazuh-notify/types"
)

func SendNtfy(params types.Params) {

	req, _ := http.NewRequest(
		"POST",
		os.Getenv("NTFY_URL"),
		strings.NewReader("&nbsp;"+services.BuildMessage(params, "ntfy", params.MarkdownEmphasis.Ntfy)))

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
