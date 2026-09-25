// Language constructs the Go frontend must lower. Unlike the shared
// scenarios in conformance.go, these are specific to Go.
package conformance

import (
	"errors"
	"fmt"
	"log"
	"strings"
)

var lastEmail string

type notifier interface{ notify(to string) }

type smsNotifier struct{}

func (smsNotifier) notify(to string) {
	// Known gap: calls through a Go interface are not followed into their
	// implementations (see README, Accuracy and limits).
	// todoruleid: log.go.stdlib
	log.Println("sms to", to)
}

func ifElse(email string, verbose bool) {
	if verbose {
		// ruleid: log.go.stdlib
		log.Println("verbose", email)
	} else {
		// ok: log.go.stdlib
		log.Println("quiet")
	}
}

func switchStmt(email string, kind int) {
	switch kind {
	case 1:
		// ruleid: log.go.stdlib
		log.Println(email)
	default:
		// ok: log.go.stdlib
		log.Println("none")
	}
}

func loops(emails []string, byID map[int]string) {
	for _, e := range emails {
		// ruleid: log.go.stdlib
		log.Println(e)
	}
	for id, email := range byID {
		// ruleid: log.go.stdlib
		log.Println(id, email)
	}
}

func deferred(email string) {
	// ruleid: log.go.stdlib
	defer log.Println("done", email)
}

func goroutine(email string) {
	go func() {
		// ruleid: log.go.stdlib
		log.Println(email)
	}()
}

func sprintf(email string) {
	msg := fmt.Sprintf("user=%s", email)
	// ruleid: log.go.stdlib
	log.Println(msg)
}

func builder(email string) {
	var b strings.Builder
	b.WriteString(email)
	// ruleid: log.go.stdlib
	log.Println(b.String())
}

func wrapped(email string) {
	err := fmt.Errorf("signup %s: %w", email, errors.New("taken"))
	// ruleid: log.go.stdlib
	log.Println(err)
}

func multiReturn(email string) (string, error) { return strings.TrimSpace(email), nil }

func multi(email string) {
	e, _ := multiReturn(email)
	// ruleid: log.go.stdlib
	log.Println(e)
}

func globalState(email string) {
	lastEmail = email
	// ruleid: log.go.stdlib
	log.Println(lastEmail)
}

func channels(email string) {
	ch := make(chan string, 1)
	ch <- email
	// ruleid: log.go.stdlib
	log.Println(<-ch)
}

func dynamicDispatch(email string) {
	var n notifier = smsNotifier{}
	n.notify(email)
}

func variadic(email string) {
	parts := []any{"user", email}
	// ruleid: log.go.stdlib
	log.Println(parts...)
}

func switchOverwrites(email string, kind int) {
	x := email
	switch kind {
	case 1:
		x = "one"
	default:
		x = "other"
	}
	// ok: log.go.stdlib
	log.Println(x)
}
