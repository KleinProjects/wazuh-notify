package services

import (
	"bufio"
	"encoding/json"
	"flag"
	"github.com/BurntSushi/toml"
	"github.com/joho/godotenv"
	"os"
	"path"
	"slices"
	"strings"
	"wazuh-notify/log"
	"wazuh-notify/types"
)

var inputParams types.Params
var configParams types.Params
var wazuhData types.WazuhMessage

func InitNotify() types.Params {
	BaseFilePath, _ := os.Executable()
	BaseDirPath := path.Dir(BaseFilePath)

	log.OpenLogFile(BaseDirPath)

	err := godotenv.Load(path.Join(BaseDirPath, "../../etc/.env"))
	if err != nil {
		log.Log("env failed to load")
		godotenv.Load(path.Join(BaseDirPath, ".env"))
	} else {
		log.Log("env loaded")
	}

	tomlFile, err := os.ReadFile(path.Join(BaseDirPath, "../../etc/wazuh-notify-config.toml"))
	if err != nil {
		log.Log("toml failed to load")
		tomlFile, err = os.ReadFile(path.Join(BaseDirPath, "wazuh-notify-config.toml"))
	}
	err = toml.Unmarshal(tomlFile, &configParams)
	if err != nil {
		print(err)
	}

	log.Log("yaml loaded")
	configParamString, _ := json.Marshal(configParams)
	log.Log(string(configParamString))

	flag.StringVar(&inputParams.Url, "url", "", "is the webhook URL of the Discord server. It is stored in .env.")
	flag.StringVar(&inputParams.General.Click, "click", configParams.General.Click, "is a link (URL) that can be followed by tapping/clicking inside the message. Default is https://google.com.")
	flag.IntVar(&inputParams.Priority, "priority", 0, "is the priority of the message, ranging from 1 (highest), to 5 (lowest). Default is 5.")
	flag.StringVar(&inputParams.General.Sender, "sender", configParams.General.Sender, "is the sender of the message, either an app name or a person. The default is \"Security message\".")
	flag.StringVar(&inputParams.Tags, "tags", "", "is an arbitrary strings of tags (keywords), seperated by a \",\" (comma). Default is \"informational,testing,hard-coded\".")
	flag.StringVar(&inputParams.General.Targets, "targets", "", "is a list of targets to send notifications to. Default is \"discord\".")

	flag.Parse()

	log.Log("params loaded")
	inputParamString, _ := json.Marshal(inputParams)
	log.Log(string(inputParamString))

	inputParams.General.Targets = configParams.General.Targets
	inputParams.General.FullAlert = configParams.General.FullAlert
	inputParams.General.ExcludedAgents = configParams.General.ExcludedAgents
	inputParams.General.ExcludedRules = configParams.General.ExcludedRules
	inputParams.PriorityMap = configParams.PriorityMap

	wazuhInput()

	return inputParams
}

func wazuhInput() {
	reader := bufio.NewReader(os.Stdin)

	json.NewDecoder(reader).Decode(&wazuhData)

	inputParams.Tags += strings.Join(wazuhData.Parameters.Alert.Rule.Groups, ",")

	inputParams.WazuhMessage = wazuhData

	for i, _ := range configParams.PriorityMap {
		if slices.Contains(configParams.PriorityMap[i].ThreatMap, wazuhData.Parameters.Alert.Rule.Level) {
			inputParams.Color = inputParams.PriorityMap[i].Color
			if inputParams.WazuhMessage.Parameters.Alert.Rule.Firedtimes >= inputParams.PriorityMap[i].MentionThreshold {
				inputParams.Mention = "@here"
			}
			inputParams.Priority = 5 - i
		}
	}

	Filter()

	log.Log("Wazuh data loaded")
	inputParamString, _ := json.Marshal(inputParams)
	log.Log(string(inputParamString))
}
