// Package api is the shop's HTTP API. It is vulnerable by design: every
// "LEAK" comment marks personal data reaching a place it should not, and
// every "SAFE" comment marks a look-alike a scanner must not report.
package api

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"

	"example.com/vulnshop/model"
	"github.com/getsentry/sentry-go"
)

// Server serves the API.
type Server struct {
	DB *sql.DB
}

// Signup registers a customer.
func (s *Server) Signup(w http.ResponseWriter, r *http.Request) {
	var c model.Customer
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// SAFE: storing the customer in our own database is the purpose (first party).
	_, _ = s.DB.Exec("INSERT INTO customers (full_name, email, phone_number) VALUES ($1, $2, $3)", c.FullName, c.Email, c.Contact)

	// LEAK: email to the application log.
	log.Printf("new signup: %s", c.Email)
	// LEAK: email to Sentry.
	sentry.ConfigureScope(func(scope *sentry.Scope) {
		scope.SetUser(sentry.User{ID: fmt.Sprint(c.ID), Email: c.Email})
	})
	// LEAK: date of birth to Sentry as a message.
	sentry.CaptureMessage("age check failed, dob=" + c.DateOfBirth)
	// LEAK: phone number sent to an SMS vendor.
	sendOTP(c.Contact)
	// LEAK: CCCD, three calls deep before it is printed.
	audit(c.CCCD)

	// SAFE: identifiers, nickname and the pii:"-" note.
	log.Printf("customer id=%d nickname=%s note=%s", c.ID, c.Nickname, c.Note)
	// SAFE: masked before logging.
	log.Println("welcome mail sent to", maskEmail(c.Email))
	w.WriteHeader(http.StatusCreated)
}

// Login checks credentials.
func (s *Server) Login(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	// LEAK: failed-login log with the email address.
	slog.Warn("login failed", "user", email)
	// LEAK: client IP address sent to a third-party geo lookup.
	_, _ = http.Get("https://geo.partner.example/lookup?ip=" + r.RemoteAddr)
	w.WriteHeader(http.StatusUnauthorized)
}

// Charge takes a card payment.
func (s *Server) Charge(p model.Payment) error {
	if err := declined(p); err != nil {
		// LEAK: card number wrapped into an error, then logged.
		wrapped := fmt.Errorf("charge failed for card %s: %w", p.CardNumber, err)
		log.Println(wrapped)
		return wrapped
	}
	// SAFE: order id and amount only.
	log.Printf("order %d charged %d VND", p.OrderID, p.AmountVND)
	return nil
}

// Export writes a CSV for the marketing team.
func (s *Server) Export(c model.Customer) error {
	// LEAK: email and phone written to a world-readable temp file.
	row := c.Email + "," + c.Contact + "\n"
	return os.WriteFile("/tmp/marketing-export.csv", []byte(row), 0o644)
}

// Support shows the support widget's contact card.
func (s *Server) Support(ci model.ContactInfo) {
	// LEAK: the contact card (email and phone) printed to stdout.
	fmt.Printf("support card: %s / %s\n", ci.Email, ci.Phone)
	// LEAK: a SHA-256 of a phone number is still personal data: phone
	// numbers are few enough to enumerate every hash.
	sum := sha256.Sum256([]byte(ci.Phone))
	log.Printf("support lookup key %s", hex.EncodeToString(sum[:]))
	// SAFE: only the length of the email.
	log.Printf("email length %d", len(ci.Email))
}

// Welcome sends the welcome mail in the background.
func (s *Server) Welcome(c model.Customer) {
	go func() {
		// LEAK: full name logged from a goroutine.
		log.Printf("sending welcome mail to %s", c.FullName)
	}()
}

func sendOTP(phone string) {
	form := url.Values{"to": {phone}, "body": {"Your code is 123456"}}
	_, _ = http.PostForm("https://sms.vendor.example/v1/send", form)
}

func audit(id string) { record("signup", id) }

func record(event, subject string) { writeAudit(event + ":" + subject) }

func writeAudit(line string) { fmt.Println("audit", line) }

func declined(p model.Payment) error {
	if p.AmountVND > 50_000_000 {
		return fmt.Errorf("amount over limit")
	}
	return nil
}

func maskEmail(e string) string {
	at := strings.IndexByte(e, '@')
	if at < 1 {
		return "***"
	}
	return e[:1] + "***" + e[at:]
}
