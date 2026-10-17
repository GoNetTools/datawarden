// Examples for the Go logging sinks (internal/rules/builtin/go.yaml).
package examples

import (
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"os"

	kitlog "github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/go-logr/logr"
	"github.com/golang/glog"
	"github.com/hashicorp/go-hclog"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
	"k8s.io/klog/v2"
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

// fmt.Fprint* is a log only when it writes to stderr or stdout.
func fprint(w io.Writer, email, phoneNumber string) {
	// ruleid: log.go.fmt_fprint
	fmt.Fprintf(os.Stderr, "signup failed for %s\n", email)
	// ruleid: log.go.fmt_fprint
	fmt.Fprintln(os.Stdout, "otp sent to", phoneNumber)
	// ok: log.go.fmt_fprint
	fmt.Fprintf(w, "hello %s", email)
}

func stdioWrite(f *os.File, email string) {
	// ruleid: log.go.stdio_write
	os.Stderr.WriteString("user " + email + "\n")
	// ok: log.go.stdio_write
	// ruleid: storage.go.file
	f.WriteString(email)
}

func builtinPrint(email string) {
	// ruleid: log.go.fmt_print
	println("debug", email)
}

func zapGlobal(email string) {
	// ruleid: log.go.zap
	zap.L().Info("signup", zap.String("email", email))
	// ruleid: log.go.zap
	zap.S().Errorf("signup failed for %s", email)
}

func logrusMore(email string, err error) {
	// ruleid: log.go.logrus
	logrus.WithFields(logrus.Fields{"email": email}).Error("signup failed")
	// ruleid: log.go.logrus
	logrus.StandardLogger().Errorf("no account for %s", email)
}

func zerologMore(email string, u User) {
	// ruleid: log.go.zerolog
	zlog.Error().Msgf("no account for %s", email)
	// ruleid: log.go.zerolog
	zlog.Info().Interface("user", u).Send()
	// ruleid: log.go.zerolog
	zerolog.New(os.Stdout).Printf("user %s", email)
}

func klogAndGlog(email, phoneNumber string, orderID int) {
	// ruleid: log.go.klog
	klog.Infof("signup %s", email)
	// ruleid: log.go.klog
	klog.V(2).InfoS("otp sent", "to", phoneNumber)
	// ruleid: log.go.klog
	glog.Warningf("no account for %s", email)
	// ok: log.go.klog
	klog.Infof("order %d", orderID)
}

func logrLogger(l logr.Logger, email string) {
	// ruleid: log.go.logr
	l.Info("signup", "email", email)
	// ruleid: log.go.logr
	l.WithValues("user", email).Error(nil, "signup failed")
}

func hclogLogger(email string) {
	// ruleid: log.go.hclog
	hclog.Default().Info("signup", "email", email)
	// ruleid: log.go.hclog
	hclog.Default().With("user", email).Warn("signup failed")
}

func goKitLogger(l kitlog.Logger, email string) {
	// ruleid: log.go.gokit
	l.Log("msg", "signup", "email", email)
	// ruleid: log.go.gokit
	level.Info(kitlog.With(l, "user", email)).Log("msg", "signup")
}

// User is a value with a sensitive field; logging it whole logs the field.
type User struct {
	Email string `json:"email"`
	ID    int
}
