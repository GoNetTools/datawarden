// Package model holds the shop's persisted types.
package model

// Customer is a registered shopper.
type Customer struct {
	ID          int64  `json:"id" db:"id"`
	FullName    string `json:"full_name" db:"full_name"`
	Email       string `json:"email" db:"email"`
	Contact     string `json:"contact" db:"phone_number"` // phone, found through the column name
	CCCD        string `json:"cccd" db:"cccd"`
	DateOfBirth string `json:"date_of_birth" db:"date_of_birth"`
	Nickname    string `json:"nickname" db:"nickname"`
	Note        string `json:"note" pii:"-"` // explicitly not personal data
}

// Payment is a card payment for an order.
type Payment struct {
	OrderID    int64
	CardNumber string
	AmountVND  int64
}

// ContactInfo is what the support widget shows.
type ContactInfo struct {
	Email string
	Phone string
}
