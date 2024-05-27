package types

type Params struct {
	Url            string
	Sender         string `yaml:"sender,omitempty"`
	Priority       int
	Tags           string
	Click          string `yaml:"click,omitempty"`
	Targets        string `yaml:"targets,omitempty"`
	FullAlert      string `yaml:"full_message,omitempty"`
	ExcludedRules  string `yaml:"excluded_rules,omitempty"`
	ExcludedAgents string `yaml:"excluded_agents,omitempty"`
	Color          int
	Mention        string
	WazuhMessage   WazuhMessage
	PriorityMaps   []PriorityMap `yaml:"priority_map"`
}

type PriorityMap struct {
	ThreatMap        []int `yaml:"threat_map"`
	MentionThreshold int   `yaml:"mention_threshold"`
	Color            int   `yaml:"color"`
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
