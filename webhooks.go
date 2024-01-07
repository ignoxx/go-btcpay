package btcpay

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Parse the webhook body into an InvoiceEvent
func ParseWebhook(r *http.Request) (*InvoiceEvent, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	var event = &InvoiceEvent{}
	if err := json.Unmarshal(body, event); err != nil {
		return nil, err
	}

	return event, err
}

// Verify the webhook signature
func (c *Client) VerifyWebhook(r *http.Request) error {
	var messageMAC = []byte(strings.TrimPrefix(r.Header.Get("BTCPay-Sig"), "sha256="))
	if len(messageMAC) == 0 {
		return errors.New("BTCPay-Sig header missing")
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}

	var mac = hmac.New(sha256.New, []byte(c.WebhookSecret))
	mac.Write(body)

	var expectedMAC = []byte(hex.EncodeToString(mac.Sum(nil)))
	if !hmac.Equal(messageMAC, expectedMAC) {
		return fmt.Errorf("HMAC mismatch, got %s, want %s", messageMAC, expectedMAC)
	}

	return nil
}
