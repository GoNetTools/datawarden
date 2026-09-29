// Level 1: a value reaches a sink in the function it arrives in.
package scenarios

import (
	"crypto/sha256"
	"log"
	"strings"
)

// S01: a parameter logged as it arrives.
func s01DirectParam(email string) {
	// ruleid: log.go.stdlib
	log.Println("signup", email)
}

// S02: a local variable named for what it holds.
func s02LocalVariable(raw string) {
	phoneNumber := strings.TrimSpace(raw)
	// ruleid: log.go.stdlib
	log.Printf("otp sent to %s", phoneNumber)
}

// S03: values that are not personal data, and names that only look like it.
func s03NotPersonal(orderID string, itemCount int, emailEnabled bool, phoneFormatter string) {
	// ok: log.go.stdlib
	log.Println("order", orderID, "items", itemCount)
	// ok: log.go.stdlib
	log.Println("email notifications", emailEnabled)
	// ok: log.go.stdlib
	log.Println("format", phoneFormatter)
}

// S04: a credential logged.
func s04Credential(username, password string) {
	// ruleid: log.go.stdlib
	log.Printf("login %s/%s", username, password)
}

func maskEmail(email string) string {
	if at := strings.IndexByte(email, '@'); at > 0 {
		return email[:1] + "***" + email[at:]
	}
	return "***"
}

// S05: masked before it is logged.
func s05Masked(email string) {
	// ok: log.go.stdlib
	log.Println("reset link sent to", maskEmail(email))
}

// S06: a hash of personal data still identifies the person.
func s06HashedPersonal(email string) {
	digest := sha256.Sum256([]byte(email))
	// ruleid: log.go.stdlib
	log.Printf("lookup key %x", digest)
}

// S07: a hashed password is safe to log.
func s07HashedCredential(password string) {
	digest := sha256.Sum256([]byte(password))
	// ok: log.go.stdlib
	log.Printf("password fingerprint %x", digest)
}
