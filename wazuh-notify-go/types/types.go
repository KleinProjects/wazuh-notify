package types

type Params struct {
	Url          string
	Sender       string `yaml:"sender,omitempty"`
	Priority     int
	Tags         string
	Click        string `yaml:"click,omitempty"`
	Targets      string `yaml:"targets,omitempty"`
	WazuhMessage WazuhMessage
	Priority1    []int `yaml:"priority_1"`
	Priority2    []int `yaml:"priority_2"`
	Priority3    []int `yaml:"priority_3"`
	Priority4    []int `yaml:"priority_4"`
	Priority5    []int `yaml:"priority_5"`
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
