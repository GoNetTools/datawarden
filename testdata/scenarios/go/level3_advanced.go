// Level 3: collections, closures, errors, consent checks, sanitizers and
// objects that keep what their constructor was given.
package scenarios

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"strings"
)

type Member struct {
	Name  string
	Email string
}

// S15: a collection built in a loop.
func s15Collection(members []Member) {
	var emails []string
	for _, m := range members {
		emails = append(emails, m.Email)
	}
	// ruleid: log.go.stdlib
	log.Println("newsletter to", strings.Join(emails, ","))
}

// S16: a closure captures the value.
func s16Closure(phoneNumber string, codes []string) {
	send := func(code string) {
		// ruleid: log.go.stdlib
		log.Println("sms", phoneNumber, code)
	}
	for _, c := range codes {
		send(c)
	}
}

func lookupAccount(email string) error {
	return fmt.Errorf("no account for %s", email)
}

// S17: the value travels in an error.
func s17Error(email string) {
	if err := lookupAccount(email); err != nil {
		// ruleid: log.go.stdlib
		log.Println(err)
	}
}

type ConsentStore interface{ HasAnalyticsConsent() bool }

// S18: analytics sent only after a consent check. Reported with the check;
// accepted when policy.consent_guarded lists network.
func s18ConsentGuarded(email string, consents ConsentStore) {
	if !consents.HasAnalyticsConsent() {
		return
	}
	// ruleid: net.go.http_body
	_, _ = http.Post("https://events.tracker.example/track", "text/plain", bytes.NewBufferString(email))
}

func isMasked(v string) bool { return strings.Contains(v, "***") }

// S19: logged only when a check says it is already masked.
func s19Sanitizer(email string) {
	if isMasked(email) {
		// ok: log.go.stdlib
		log.Println("contact", email)
	}
}

type Session struct {
	userID      string
	accessToken string
}

func NewSession(userID, token string) *Session {
	return &Session{userID: userID, accessToken: token}
}

// S20: the constructor stores the value, another method logs it.
func (s *Session) Debug() {
	// ruleid: log.go.stdlib
	log.Printf("session user=%s token=%s", s.userID, s.accessToken)
}

func s20ConstructorField(userID, token string) {
	NewSession(userID, token).Debug()
}
