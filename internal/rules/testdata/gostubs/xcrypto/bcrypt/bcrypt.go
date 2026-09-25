// Package bcrypt is an offline stand-in for golang.org/x/crypto/bcrypt.
package bcrypt

const DefaultCost = 10

func GenerateFromPassword(password []byte, cost int) ([]byte, error) { return password, nil }
