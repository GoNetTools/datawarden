// Level 4: dynamic dispatch, callbacks kept in fields, deep objects,
// multi-layer pipelines, device storage and ordering.
package scenarios

import (
	"bytes"
	"database/sql"
	"log"
	"net/http"
	"net/url"
	"os"
)

// Notifier has two implementations; one of them logs what it sends.
type Notifier interface{ Notify(to, body string) }

type smsNotifier struct{}

func (smsNotifier) Notify(to, body string) {
	// ruleid: log.go.stdlib
	log.Printf("sms to=%s body=%s", to, body)
}

type pushNotifier struct{ sent int }

func (p *pushNotifier) Notify(to, body string) { p.sent++ }

// S21: the value reaches the sink through an interface call.
func s21Dispatch(n Notifier, phoneNumber string) {
	n.Notify(phoneNumber, "your code is ready")
}

// EventBus keeps a subscriber and runs it when an event is published.
type EventBus struct{ onSignup func(email string) }

func (b *EventBus) Subscribe(f func(string)) { b.onSignup = f }
func (b *EventBus) Publish(email string)     { b.onSignup(email) }

// S22: a callback kept in a field runs later with the value.
func s22StoredCallback(bus *EventBus, emailAddress string) {
	bus.Subscribe(func(e string) {
		// ruleid: log.go.stdlib
		log.Println("welcome mail queued for", e)
	})
	bus.Publish(emailAddress)
}

type Contact struct{ HomeAddress string }
type Customer struct{ Contact Contact }
type Order struct {
	ID       string
	Customer Customer
}

// S23: a value three fields deep.
func s23DeepField(o Order) {
	// ruleid: net.go.http_form
	_, _ = http.PostForm("https://shipping.partner.example/labels", url.Values{"to": {o.Customer.Contact.HomeAddress}})
	// ok: net.go.http_form
	_, _ = http.PostForm("https://shipping.partner.example/status", url.Values{"order": {o.ID}})
}

// A request handler, a service and a repository: the date of birth read
// from the form is stored and sent to a partner.
type profileRepo struct{ db *sql.DB }

func (r *profileRepo) save(userID, dateOfBirth string) {
	// ruleid: storage.go.sql
	_, _ = r.db.Exec("UPDATE profiles SET dob = $1 WHERE id = $2", dateOfBirth, userID)
}

type profileService struct{ repo *profileRepo }

func (s *profileService) update(userID, dob string) {
	s.repo.save(userID, dob)
	// ruleid: net.go.http_body
	_, _ = http.Post("https://age-check.partner.example/v1", "text/plain", bytes.NewBufferString(dob))
}

// S24: request → service → repository and partner.
func s24Pipeline(svc *profileService, r *http.Request) {
	svc.update(r.FormValue("user_id"), r.FormValue("date_of_birth"))
}

// S25: a session token persisted on the device.
func s25DeviceStorage(sessionToken string) {
	// ruleid: storage.go.file
	_ = os.WriteFile(".session", []byte(sessionToken), 0o600)
}

// S26: an object logged before the value is added to it, then after.
func s26Ordering(email string) {
	payload := map[string]string{"source": "web"}
	// ok: log.go.stdlib
	log.Println("payload", payload)
	payload["email"] = email
	// ruleid: log.go.stdlib
	log.Println("payload", payload)
}
