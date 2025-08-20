package helper

import (
	"crypto/sha256"
	"encoding/hex"
)

func Hash8(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}
