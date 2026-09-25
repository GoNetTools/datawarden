// Examples for the Go transform rules. A hash is not a safe transform by
// default (phone numbers can be enumerated), so logging it is still a
// violation; encryption is safe.
package examples

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"log"

	"golang.org/x/crypto/bcrypt"
)

func sha256Sum(phoneNumber string) {
	// ruleid: xform.go.sha256
	sum := sha256.Sum256([]byte(phoneNumber))
	// ruleid: log.go.stdlib
	log.Printf("lookup key %x", sum)
}

func sha512Sum(email string) {
	// ruleid: xform.go.sha512
	sum := sha512.Sum512([]byte(email))
	// ruleid: log.go.stdlib
	log.Printf("key %x", sum)
}

func weakHash(email string) {
	// ruleid: xform.go.weak_hash
	sum := md5.Sum([]byte(email))
	// ruleid: log.go.stdlib
	log.Printf("gravatar %x", sum)
}

func hashSum(email string) {
	h := sha256.New()
	h.Write([]byte(email))
	// ruleid: xform.go.hash_sum
	sum := h.Sum(nil)
	// ruleid: log.go.stdlib
	log.Printf("key %x", sum)
}

func kdf(email string) {
	// ruleid: xform.go.kdf
	digest, _ := bcrypt.GenerateFromPassword([]byte(email), bcrypt.DefaultCost)
	// ruleid: log.go.stdlib
	log.Printf("digest %x", digest)
}

func encrypt(key, nonce []byte, email string) {
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	// ruleid: xform.go.encrypt
	sealed := aead.Seal(nil, nonce, []byte(email), nil)
	// ok: log.go.stdlib
	log.Printf("sealed %x", sealed)
}

func b64(email string) {
	// ruleid: xform.go.base64
	enc := base64.StdEncoding.EncodeToString([]byte(email))
	// ruleid: log.go.stdlib
	log.Printf("encoded %s", enc)
}
