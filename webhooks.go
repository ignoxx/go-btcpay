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

// Verify the webhook signatura and parse it into *InvoiceEvent
func VerifyWebhook(r *http.Request, webhookSecret string) (*InvoiceEvent, error) {
	var messageMAC = []byte(strings.TrimPrefix(r.Header.Get("BTCPay-Sig"), "sha256="))
	if len(messageMAC) == 0 {
		return nil, errors.New("BTCPay-Sig header missing")
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	var mac = hmac.New(sha256.New, []byte(webhookSecret))
	mac.Write(body)

	var expectedMAC = []byte(hex.EncodeToString(mac.Sum(nil)))
	if !hmac.Equal(messageMAC, expectedMAC) {
		return nil, fmt.Errorf("HMAC mismatch, got %s, want %s", messageMAC, expectedMAC)
	}

	var event = &InvoiceEvent{}
	if err := json.Unmarshal(body, event); err != nil {
		return nil, err
	}

	return event, nil
}
