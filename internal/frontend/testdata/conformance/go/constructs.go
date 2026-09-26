// Language constructs the Go frontend must lower. Unlike the shared
// scenarios in conformance.go, these are specific to Go.
package conformance

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
)

var lastEmail string

type notifier interface{ notify(to string) }

type smsNotifier struct{}

func (smsNotifier) notify(to string) {
	// Reached through the notifier interface: interface calls run the
	// module's implementations (class hierarchy analysis).
	// ruleid: log.go.stdlib
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

type draft struct{ Note string }

func storeOrder(email string) {
	d := &draft{}
	// ok: log.go.stdlib
	log.Println(d)
	d.Note = email
	// ruleid: log.go.stdlib
	log.Println(d)
}

// The error of a library call does not carry its arguments, and a
// connection handle does not carry its DSN; an error built from the data
// does.
func libraryErrors(password, email string) {
	db, err := sql.Open("postgres", "postgres://app:"+password+"@db/app")
	if err != nil {
		// ok: log.go.stdlib
		log.Println(err)
	}
	// ok: log.go.stdlib
	log.Println(db)
	var v map[string]any
	if err := json.Unmarshal([]byte(email), &v); err != nil {
		// ok: log.go.stdlib
		log.Println(err.Error())
	}
	// strconv quotes the input in its errors.
	if _, err := strconv.Atoi(email); err != nil {
		// ruleid: log.go.stdlib
		log.Println(err)
	}
	// ruleid: log.go.stdlib
	log.Println(fmt.Errorf("bad address %s", email))
}
