package services

import "slices"

func mapPriority() int {
	if slices.Contains(configParams.Priority1, wazuhData.Parameters.Alert.Rule.Level) {
		return 1
	}
	if slices.Contains(configParams.Priority2, wazuhData.Parameters.Alert.Rule.Level) {
		return 2
	}
	if slices.Contains(configParams.Priority3, wazuhData.Parameters.Alert.Rule.Level) {
		return 3
	}
	if slices.Contains(configParams.Priority4, wazuhData.Parameters.Alert.Rule.Level) {
		return 4
	}
	if slices.Contains(configParams.Priority5, wazuhData.Parameters.Alert.Rule.Level) {
		return 5
	}
	return 0
}
