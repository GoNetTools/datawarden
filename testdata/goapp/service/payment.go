package service

import (
	"fmt"
	"log/slog"
	"os"

	"example.com/goapp/model"
)

// Charge logs cardholder data on the way to the processor.
func Charge(card *model.Card, amount int) error {
	fmt.Fprintf(os.Stderr, "charging %d to %s (%s)\n", amount, card.Number, card.Code)
	slog.Info("charge", "exp", fmt.Sprintf("%02d/%d", card.ExpMonth, card.ExpYear), "holder", card.HolderName)
	// The last four digits are not cardholder data.
	slog.Info("charged", "card", card.Last4, "amount", amount)
	return nil
}
