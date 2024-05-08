package types

type Params struct {
	Server      string
	Sender      string `yaml:"sender,omitempty"`
	Destination string
	Priority    int
	Message     string
	Tags        string
	Click       string `yaml:"click,omitempty"`
	Targets     string `yaml:"targets,omitempty"`
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
