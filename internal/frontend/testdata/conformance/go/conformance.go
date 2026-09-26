// Frontend conformance programs for Go. Every language implements the same
// scenarios (see TestFrontendConformance in internal/app).
package conformance

import (
	"fmt"
	"log"
	"strings"
)

type User struct {
	ID      int64
	Email   string
	Contact string
}

func (u *User) ContactEmail() string { return u.Email }

// scenario: param
func param(email string) {
	// ruleid: log.go.stdlib
	log.Println(email)
}

// scenario: local
func local(email string) {
	x := email
	// ruleid: log.go.stdlib
	log.Println(x)
}

// scenario: concat
func concat(email string) {
	msg := "signup " + email
	// ruleid: log.go.stdlib
	log.Println(msg)
}

// scenario: field
func field(u *User) {
	// ruleid: log.go.stdlib
	log.Println(u.Email)
}

// scenario: getter
func getter(u *User) {
	// ruleid: log.go.stdlib
	log.Println(u.ContactEmail())
}

// scenario: key
func key(value string) {
	payload := map[string]string{"email": value}
	// ruleid: log.go.stdlib
	log.Println(payload)
}

func logIt(v string) {
	// ruleid: log.go.stdlib
	log.Println(v)
}

// scenario: call-arg
func callArg(email string) {
	logIt(email)
}

func normalize(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// scenario: call-return
func callReturn(email string) {
	// ruleid: log.go.stdlib
	log.Println(normalize(email))
}

// scenario: closure
func closure(email string, items []string) {
	for _, it := range items {
		func() {
			// ruleid: log.go.stdlib
			log.Println(it, email)
		}()
	}
}

// scenario: field-store
func fieldStore(phoneNumber string) {
	u := &User{}
	u.Contact = phoneNumber
	// ruleid: log.go.stdlib
	log.Println(u.Contact)
}

// scenario: collection
func collection(email string) {
	var xs []string
	xs = append(xs, email)
	// ruleid: log.go.stdlib
	log.Println(xs)
}

// scenario: object
func object(u User) {
	// ruleid: log.go.stdlib
	log.Printf("%+v", u)
}

func maskEmail(e string) string {
	if at := strings.IndexByte(e, '@'); at > 0 {
		return e[:1] + "***" + e[at:]
	}
	return "***"
}

// scenario: masked
func masked(email string) {
	// ok: log.go.stdlib
	log.Println(maskEmail(email))
}

// scenario: not-pii
func notPII(u *User, orderID int64, count int) {
	// ok: log.go.stdlib
	log.Println(u.ID, orderID, count)
}

// scenario: negative-context
func negativeContext(phoneCount int, emailTemplate string) {
	// ok: log.go.stdlib
	log.Println(phoneCount, emailTemplate)
}

// scenario: overwritten
func overwritten(email string) {
	x := email
	x = "anonymous"
	// ok: log.go.stdlib
	log.Println(x)
}

// scenario: remasked
func remasked(email string) {
	email = maskEmail(email)
	// ok: log.go.stdlib
	log.Println(email)
}

// scenario: branch-merge
func branchMerge(email string, verbose bool) {
	x := "anonymous"
	if verbose {
		x = email
	}
	// ruleid: log.go.stdlib
	log.Println(x)
}

// scenario: loop-carried
func loopCarried(email string, items []string) {
	x := "anonymous"
	for range items {
		// ruleid: log.go.stdlib
		log.Println(x)
		x = email
	}
}

// scenario: mutated-later
func mutatedLater(email string) {
	var xs []string
	// ok: log.go.stdlib
	log.Println(xs)
	xs = append(xs, email)
	_ = xs
}

// scenario: early-return
func earlyReturn(email string, invalid bool) {
	x := "anonymous"
	if invalid {
		x = email
		// ruleid: log.go.stdlib
		log.Println(x)
		return
	}
	// ok: log.go.stdlib
	log.Println(x)
}

// scenario: break-exit
func breakExit(email string, items []string) {
	x := "anonymous"
	for _, it := range items {
		if it == "" {
			x = email
			break
		}
	}
	// ruleid: log.go.stdlib
	log.Println(x)
}

// scenario: continue-skip
func continueSkip(email string, items []string) {
	for _, it := range items {
		x := "anonymous"
		if it == "" {
			x = email
			continue
		}
		// ok: log.go.stdlib
		log.Println(x)
	}
}

// scenario: snapshot
func snapshot(email string) {
	items := map[string]string{}
	msg := fmt.Sprint("items=", len(items))
	items["email"] = email
	// ok: log.go.stdlib
	log.Println(msg)
}

const verboseLogging = false

// scenario: constant-condition
func constantCondition(email string) {
	if verboseLogging {
		// ok: log.go.stdlib
		log.Println(email)
	}
}

// scenario: field-across-methods
type mailbox struct{ addr string }

func newMailbox(email string) *mailbox { return &mailbox{addr: email} }

func (m *mailbox) announce() {
	// ruleid: log.go.stdlib
	log.Println("sending to", m.addr)
}

func fieldAcrossMethods(email string) { newMailbox(email).announce() }

// scenario: dynamic-dispatch
type channel interface{ deliver(to string) }

type smsChannel struct{}

func (smsChannel) deliver(to string) {
	// ruleid: log.go.stdlib
	log.Println("sms", to)
}

func deliverThrough(c channel, email string) { c.deliver(email) }

// scenario: exception
func exception(email string) {
	err := fmt.Errorf("unknown user %s", email)
	// ruleid: log.go.stdlib
	log.Println(err)
}

// scenario: lambda-variable
func lambdaVariable(email string) {
	show := func(v string) {
		// ruleid: log.go.stdlib
		log.Println(v)
	}
	show(email)
}
