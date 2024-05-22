package types

type WazuhMessage struct {
	Version    int        `json:"version"`
	Origin     Origin     `json:"origin"`
	Command    string     `json:"command"`
	Parameters Parameters `json:"parameters"`
}

type Origin struct {
	Name   string `json:"name"`
	Module string `json:"module"`
}

type Parameters struct {
	ExtraArgs []interface{} `json:"extra_args"`
	Alert     Alert         `json:"alert"`
	Program   string        `json:"program"`
}

type Alert struct {
	Timestamp string  `json:"timestamp"`
	Rule      Rule    `json:"rule"`
	Agent     Agent   `json:"agent"`
	Manager   Manager `json:"manager"`
	ID        string  `json:"id"`
	FullLog   string  `json:"full_log"`
	Decoder   Decoder `json:"decoder"`
	Data      Data    `json:"data"`
	Location  string  `json:"location"`
}

type Rule struct {
	Level       int      `json:"level"`
	Description string   `json:"description"`
	ID          string   `json:"id"`
	Mitre       Mitre    `json:"mitre"`
	Info        string   `json:"info"`
	Firedtimes  int      `json:"firedtimes"`
	Mail        bool     `json:"mail"`
	Groups      []string `json:"groups"`
	PciDss      []string `json:"pci_dss"`
	Gdpr        []string `json:"gdpr"`
	Nist80053   []string `json:"nist_800_53"`
	Tsc         []string `json:"tsc"`
}

type Mitre struct {
	ID        []string `json:"id"`
	Tactic    []string `json:"tactic"`
	Technique []string `json:"technique"`
}

type Agent struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Manager struct {
	Name string `json:"name"`
}

type Decoder struct {
	Name string `json:"name"`
}

type Data struct {
	Protocol string `json:"protocol"`
	Srcip    string `json:"srcip"`
	ID       string `json:"id"`
	URL      string `json:"url"`
}
