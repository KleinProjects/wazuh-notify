package log

import (
	"os"
	"time"
)

var f, _ = os.OpenFile("active-responses.log", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)

func Log(message string) {
	if _, err := f.WriteString("\n" + time.Now().Format(time.DateTime) + message); err != nil {
		panic(err)
	}
}
