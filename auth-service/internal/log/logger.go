package log

import (
	"log"
)

func Infof(format string, args ...any)  { log.Printf("[INFO] "+format, args...) }
func Errorf(format string, args ...any) { log.Printf("[ERROR] "+format, args...) }
