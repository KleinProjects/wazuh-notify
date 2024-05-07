package types

type Params struct {
	Server      string `yaml:"discord_server"`
	Sender      string `yaml:"discord_sender"`
	Destination string `yaml:"discord_destination"`
	Priority    int    `yaml:"discord_priority"`
	Message     string `yaml:"discord_message"`
	Tags        string `yaml:"discord_tags"`
	Click       string `yaml:"discord_click"`
	Targets     string `yaml:"targets"`
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
	Color       string `json:"color,omitempty"`
}
