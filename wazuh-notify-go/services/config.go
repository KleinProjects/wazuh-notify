package services

import (
	"github.com/BurntSushi/toml"
	"github.com/joho/godotenv"
	"os"
	"path"
	"wazuh-notify/services/log"
	"wazuh-notify/types"
)

func ReadConfig() types.Params {

	var configParams types.Params

	baseFilePath, _ := os.Executable()
	baseDirPath := path.Dir(baseFilePath)

	log.OpenLogFile(baseDirPath)

	err := godotenv.Load(path.Join(baseDirPath, "../../etc/.env"))
	if err != nil {
		log.Log("env failed to load")
		godotenv.Load(path.Join(baseDirPath, ".env"))
	} else {
		log.Log("env loaded")
	}

	tomlFile, err := os.ReadFile(path.Join(baseDirPath, "../../etc/wazuh-notify-config.toml"))
	if err != nil {
		log.Log("toml failed to load")
		tomlFile, err = os.ReadFile(path.Join(baseDirPath, "wazuh-notify-config.toml"))
	}
	err = toml.Unmarshal(tomlFile, &configParams)
	if err != nil {
		print(err)
	} else {
		log.Log("yaml loaded")
	}

	return configParams
}
