package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Pseudonymize generuje nieodwracalny, deterministyczny hash HMAC dla pól wyszukiwarkowych (np. NIP/Email).
// Pozwala na wyszukiwanie rekordów w bazie bez konieczności przechowywania odszyfrowanych danych osobowych.
func Pseudonymize(value string, salt string) string {
	if value == "" {
		return ""
	}
	h := hmac.New(sha256.New, []byte(salt))
	h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))
}
