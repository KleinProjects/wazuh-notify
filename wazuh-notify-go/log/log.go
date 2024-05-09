package log

import (
	"os"
	"path"
	"time"
)

var logFile *os.File

func OpenLogFile(BasePath string) {
	logFile, _ = os.OpenFile(path.Join(BasePath, "../../logs/active-responses.log"), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	_, err := logFile.WriteString(
		"\n#######################################\n## START ##" +
			"\n" + time.Now().String() +
			"\n#######################################\n",
	)
	if err != nil {
		panic(err)
	}
}

func Log(message string) {
	if _, err := logFile.WriteString("\n" + message + ": " + time.Now().String()); err != nil {
		panic(err)
	}
}
