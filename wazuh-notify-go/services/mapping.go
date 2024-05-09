package services

import "slices"

func mapPriority() {
	if slices.Contains(configParams.Priority1, wazuhData.Parameters.Alert.Rule.Level) {
		inputParams.Priority = wazuhData.Parameters.Alert.Rule.Level
	}
	if slices.Contains(configParams.Priority2, wazuhData.Parameters.Alert.Rule.Level) {
		inputParams.Priority = wazuhData.Parameters.Alert.Rule.Level
	}
	if slices.Contains(configParams.Priority3, wazuhData.Parameters.Alert.Rule.Level) {
		inputParams.Priority = wazuhData.Parameters.Alert.Rule.Level
	}
	if slices.Contains(configParams.Priority4, wazuhData.Parameters.Alert.Rule.Level) {
		inputParams.Priority = wazuhData.Parameters.Alert.Rule.Level
	}
	if slices.Contains(configParams.Priority5, wazuhData.Parameters.Alert.Rule.Level) {
		inputParams.Priority = wazuhData.Parameters.Alert.Rule.Level
	}
}
