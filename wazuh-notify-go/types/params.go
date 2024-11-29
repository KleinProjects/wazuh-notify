package types

type Params struct {
	General          General `toml:"general"`
	Url              string
	Priority         int
	Tags             string
	Color            int
	Mention          string
	WazuhMessage     WazuhMessage
	PriorityMap      []PriorityMap    `toml:"priority_map"`
	MarkdownEmphasis MarkdownEmphasis `toml:"markdown_emphasis"`
}

type General struct {
	Targets             string   `toml:"targets"`
	FullAlert           string   `toml:"full_alert"`
	ExcludedRules       string   `toml:"excluded_rules"`
	ExcludedAgents      string   `toml:"excluded_agents"`
	Sender              string   `toml:"sender"`
	Click               string   `toml:"click"`
	ExcludedDescription []string `toml:"exclude_descriptions"`
}
type PriorityMap struct {
	ThreatMap        []int `toml:"threat_map"`
	MentionThreshold int   `toml:"mention_threshold"`
	NotifyThreshold  int   `toml:"notify_threshold"`
	Color            int   `toml:"color"`
}
type MarkdownEmphasis struct {
	Slack   string `toml:"slack"`
	Ntfy    string `toml:"ntfy"`
	Discord string `toml:"discord"`
}
