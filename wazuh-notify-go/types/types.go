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
	Targets        string `toml:"targets"`
	FullAlert      string `toml:"full_alert"`
	ExcludedRules  string `toml:"excluded_rules"`
	ExcludedAgents string `toml:"excluded_agents"`
	Sender         string `toml:"sender"`
	Click          string `toml:"click"`
}
type PriorityMap struct {
	ThreatMap        []int `toml:"threat_map"`
	MentionThreshold int   `toml:"mention_threshold"`
	Color            int   `toml:"color"`
}
type MarkdownEmphasis struct {
	Slack   string `toml:"slack"`
	Ntfy    string `toml:"ntfy"`
	Discord string `toml:"discord"`
}

type Message struct {
	Username  string  `json:"username,omitempty"`
	AvatarUrl string  `json:"avatar_url,omitempty"`
	Content   string  `json:"content,omitempty"`
	Embeds    []Embed `json:"embeds,omitempty"`
}

type Embed struct {
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Color       int    `json:"color,omitempty"`
}
