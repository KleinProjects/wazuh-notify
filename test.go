package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("hier")
	os.Stderr.Write([]byte("hier2"))
}
