package auth

import (
	"crypto/sha256"
	"encoding/hex"
)

// actionTokenKey creates the stable database key for one-time verification and
// reset tokens. The bearer token itself is never persisted by framework stores.
func actionTokenKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
