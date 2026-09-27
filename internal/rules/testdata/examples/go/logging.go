// Examples for the Go logging sinks (internal/rules/builtin/go.yaml).
package examples

import (
	"fmt"
	"log"
	"log/slog"
	"net"

	zlog "github.com/rs/zerolog/log"
	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
)

func stdlib(email string, orderID int) {
	// ruleid: log.go.stdlib
	log.Printf("signup %s", email)
	// ok: log.go.stdlib
	log.Printf("order %d", orderID)
}

func fmtPrint(phoneNumber string) {
	// ruleid: log.go.fmt_print
	fmt.Println("otp sent to", phoneNumber)
}

func structured(email string) {
	// ruleid: log.go.slog
	slog.Info("login failed", "user", email)
}

func zapLogger(logger *zap.Logger, email string) {
	// ruleid: log.go.zap
	logger.Info("signup", zap.String("user", email))
}

func logrusLogger(email string) {
	// ruleid: log.go.logrus
	logrus.WithField("user", email).Info("signup")
}

func zerologLogger(phoneNumber string) {
	// ruleid: log.go.zerolog
	zlog.Info().Str("to", phoneNumber).Msg("otp sent")
}

// A key names the value only when the value does not say what it is:
// the listen address is not a postal address.
func zerologListen(l net.Listener) {
	// ok: log.go.zerolog
	zlog.Info().Str("address", l.Addr().String()).Msg("Started listening")
}

func zapSugared(logger *zap.Logger, email string, orderID int) {
	// Key/value pairs of the sugared logger: the value after "email".
	// ruleid: log.go.zap
	logger.Sugar().Infow("signup", "email", email)
	// ok: log.go.zap
	logger.Sugar().Infow("order", "id", orderID)
}
