// Examples for the Go storage sinks. Databases are first party: the flows
// are reported but are not violations under the default policy.
package examples

import (
	"context"
	"database/sql"
	"os"

	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

type Customer struct {
	FullName string
	Email    string
}

func fileWrite(email string) {
	// ruleid: storage.go.file
	_ = os.WriteFile("/tmp/export.csv", []byte(email), 0o644)
}

func sqlExec(db *sql.DB, email string) {
	// ruleid: storage.go.sql
	_, _ = db.Exec("INSERT INTO customers (email) VALUES ($1)", email)
}

func gormCreate(db *gorm.DB, email string) {
	c := Customer{Email: email}
	// ruleid: storage.go.gorm
	db.Create(&c)
}

func redisSet(ctx context.Context, rdb *redis.Client, phoneNumber string) {
	// ruleid: storage.go.redis
	rdb.Set(ctx, "otp:last", phoneNumber, 0)
}
