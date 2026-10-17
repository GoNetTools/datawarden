package com.example.payments;

import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;

@Slf4j
public class PaymentService {
    public void charge(String cardNumber, String cvv, String cardholderName, String expiryDate, long amount) {
        MDC.put("card", cardNumber);
        log.info("charging {} for {} ({}, exp {})", amount, cardholderName, cvv, expiryDate);
        log.info("charged {} to card ending {}", amount, cardNumber.substring(cardNumber.length() - 4));
        try {
            authorize(cardNumber);
        } catch (IllegalStateException e) {
            e.printStackTrace();
        }
    }

    private void authorize(String cardNumber) {
        throw new IllegalStateException("declined: " + cardNumber);
    }
}
