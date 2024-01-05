package btcpay

import "testing"

func TestConstructInvoicesEndpoint(t *testing.T) {
	actual := constructInvoicesEndpoint("https://example.com", "storeID", "1000")
	expected := "https://example.com/api/v1/stores/storeID/invoices?orderId=1000"
	if actual != expected {
		t.Errorf("Expected %s, got %s", expected, actual)
	}

	actual = constructInvoicesEndpoint("https://example.com", "storeID", "1000", "2000")
	expected = "https://example.com/api/v1/stores/storeID/invoices?orderId=1000&orderId=2000"
	if actual != expected {
		t.Errorf("Expected %s, got %s", expected, actual)
	}

	actual = constructInvoicesEndpoint("https://example.com", "storeID")
	expected = "https://example.com/api/v1/stores/storeID/invoices"
	if actual != expected {
		t.Errorf("Expected %s, got %s", expected, actual)
	}
}
