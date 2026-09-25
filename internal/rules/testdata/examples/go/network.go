// Examples for the Go HTTP client sinks.
package examples

import (
	"net/http"
	"net/url"
	"strings"
)

func httpPost(cccd string) {
	// ruleid: net.go.http_body
	_, _ = http.Post("https://kyc.vendor.example/check", "text/plain", strings.NewReader(cccd))
}

func httpForm(phoneNumber string) {
	// ruleid: net.go.http_form
	_, _ = http.PostForm("https://sms.vendor.example/send", url.Values{"to": {phoneNumber}})
}

func httpGet(r *http.Request, orderID string) {
	// ruleid: net.go.http_get
	_, _ = http.Get("https://geo.vendor.example/lookup?ip=" + r.RemoteAddr)
	// ok: net.go.http_get
	_, _ = http.Get("https://api.shop.example/orders/" + orderID)
}

func httpDo(email string) {
	req, _ := http.NewRequest(http.MethodPost, "https://crm.vendor.example/leads", strings.NewReader(email))
	// ruleid: net.go.http_do
	_, _ = http.DefaultClient.Do(req)
}
