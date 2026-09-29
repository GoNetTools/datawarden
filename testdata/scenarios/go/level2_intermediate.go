// Level 2: a value is formatted, stored in an object or a map, or passed
// to a helper before it reaches a sink.
package scenarios

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
)

// S08: health data formatted into a message.
func s08Formatted(patientID int, diagnosis string) {
	msg := fmt.Sprintf("patient %d diagnosis %s", patientID, diagnosis)
	// ruleid: log.go.stdlib
	log.Println(msg)
}

type PaymentCard struct {
	Holder     string
	CardNumber string
	Expiry     string
}

// S09: a field of an object written to a file.
func s09ObjectField(card PaymentCard) {
	// ruleid: storage.go.file
	_ = os.WriteFile("last-card.txt", []byte(card.CardNumber), 0o600)
	// ok: storage.go.file
	_ = os.WriteFile("last-expiry.txt", []byte(card.Expiry), 0o600)
}

// S10: a map key says what its value is.
func s10MapKey(value string) {
	body, _ := json.Marshal(map[string]string{"ssn": value})
	// ruleid: net.go.http_body
	_, _ = http.Post("https://kyc.partner.example/verify", "application/json", bytes.NewReader(body))
}

// auditLog is a helper several scenarios call.
func auditLog(event, detail string) {
	// ruleid: log.go.stdlib
	log.Println("audit", event, detail)
}

// S11: the value is logged by a helper.
func s11Helper(email string) {
	auditLog("login", email)
}

type Patient struct {
	id  int
	mrn string
}

func (p *Patient) MedicalRecordNumber() string { return p.mrn }

// S12: a getter returns the value.
func s12Getter(p *Patient) {
	// ruleid: log.go.slog
	slog.Info("record opened", "mrn", p.MedicalRecordNumber())
}

// S13: the value is replaced on one path before it is logged.
func s13Overwritten(email string, anonymous bool) {
	shown := email
	if anonymous {
		shown = "anonymous"
		// ok: log.go.stdlib
		log.Println("comment by", shown)
		return
	}
	// ruleid: log.go.stdlib
	log.Println("comment by", shown)
}

// S14: an API key sent to the service it authenticates to.
func s14CredentialToItsService(apiKey string) {
	req, _ := http.NewRequest(http.MethodGet, "https://api.payments.example/v1/balance", nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	// ok: net.go.http_do
	_, _ = http.DefaultClient.Do(req)
}
