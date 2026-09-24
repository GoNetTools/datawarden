package service

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"strings"

	"example.com/goapp/model"
	"github.com/getsentry/sentry-go"
)

// Register leaks several fields.
func Register(c *model.Customer) {
	log.Printf("register %s", c.Contact)
	sentry.ConfigureScope(func(s *sentry.Scope) {
		s.SetUser(sentry.User{ID: fmt.Sprint(c.ID), Email: c.Email})
	})
	notify(c.CCCD)
	log.Printf("id=%d nick=%s note=%s", c.ID, c.Nickname, c.Note)
}

func notify(cccd string) {
	sendSMS("Your ID " + cccd)
}

func sendSMS(body string) {
	_, _ = http.Post("https://sms.vendor.example/send", "text/plain", strings.NewReader(body))
}

func maskPhone(p string) string {
	if len(p) < 4 {
		return "****"
	}
	return p[:3] + "****"
}

// Safe logs only a masked phone number.
func Safe(c *model.Customer) {
	log.Println(maskPhone(c.Contact))
}

// Handler reads PII from a request.
func Handler(w http.ResponseWriter, r *http.Request) {
	mobileNo := r.FormValue("mobile")
	slog.Info("got", "value", mobileNo)
	fmt.Println(r.RemoteAddr)
}
