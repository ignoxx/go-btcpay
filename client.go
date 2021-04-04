package btcpay

// WIP (webhooks?)

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

type Client struct {
	URL      string
	APIKey   string
	Username string
	Password string
}

func NewClient(url, apiKey string) *Client {
	return &Client{
		URL:    url,
		APIKey: apiKey,
	}
}

func NewBasicClient(url, username, password string) *Client {
	return &Client{
		URL:      url,
		Username: username,
		Password: password,
	}
}

func (c *Client) doRequest(req *http.Request) ([]byte, error) {
	if len(c.APIKey) > 0 {
		req.Header.Set("Authorization", fmt.Sprintf("token %s", c.APIKey))
	} else if len(c.Username) > 0 && len(c.Password) > 0 {
		req.SetBasicAuth(c.Username, c.Password)
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s", body)
	}
	return body, nil
}
