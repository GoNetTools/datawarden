package model

// Card is what the checkout form posts. The security code is tagged
// explicitly; the other fields are recognised by name.
type Card struct {
	Number     string `json:"card_number"`
	Code       string `json:"code" pci:"card_security_code"`
	ExpMonth   int    `json:"exp_month"`
	ExpYear    int    `json:"exp_year"`
	HolderName string `json:"holder_name"`
	Last4      string `json:"last4"`
}
