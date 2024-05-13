package services

import "slices"

func mapPriority() int {
	if slices.Contains(configParams.PriorityMaps[4].ThreatMap, wazuhData.Parameters.Alert.Rule.Level) {
		return 1
	}
	if slices.Contains(configParams.PriorityMaps[3].ThreatMap, wazuhData.Parameters.Alert.Rule.Level) {
		return 2
	}
	if slices.Contains(configParams.PriorityMaps[2].ThreatMap, wazuhData.Parameters.Alert.Rule.Level) {
		return 3
	}
	if slices.Contains(configParams.PriorityMaps[1].ThreatMap, wazuhData.Parameters.Alert.Rule.Level) {
		return 4
	}
	if slices.Contains(configParams.PriorityMaps[0].ThreatMap, wazuhData.Parameters.Alert.Rule.Level) {
		return 5
	}
	return 0
}
