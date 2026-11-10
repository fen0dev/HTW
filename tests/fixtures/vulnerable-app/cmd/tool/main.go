// Test fixture: intentionally unsafe code for exercising the SAST scanners.
package main

import (
	"crypto/md5"
	"fmt"
	"os"
	"os/exec"
)

func main() {
	if len(os.Args) < 2 {
		return
	}
	out, _ := exec.Command("sh", "-c", os.Args[1]).Output()
	fmt.Printf("%x %s\n", md5.Sum(out), out)
}
