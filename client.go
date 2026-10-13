package curlgo

import (
	"net/http"
	"net/http/cookiejar"
)

// Client combines an http.Client with a curl-impersonate Transport. The standard
// Client API provides redirects, cookies, Get, Post and PostForm. Close releases
// all native handles, including requests whose response bodies remain open.
type Client struct {
	*http.Client
	CurlTransport *Transport
}

// NewClient creates a client with a persistent cookie jar and native handle pool.
// An empty profile selects Chrome. Unsupported profiles are rejected immediately.
func NewClient(profile Profile) (*Client, error) {
	if profile == "" {
		profile = Profile("chrome")
	}
	normalized, err := NormalizeProfile(profile)
	if err != nil {
		return nil, err
	}
	// Fail at construction if the native library cannot be loaded.
	c, err := NewCurl()
	if err != nil {
		return nil, err
	}
	transport := &Transport{Profile: normalized, idle: []*Curl{c}, handleProfiles: map[*Curl]Profile{c: normalized}}
	jar, err := cookiejar.New(nil)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return &Client{Client: &http.Client{Transport: transport, Jar: jar}, CurlTransport: transport}, nil
}

// Close releases native resources and cancels active transfers.
func (c *Client) Close() error {
	if c == nil || c.CurlTransport == nil {
		return nil
	}
	return c.CurlTransport.Close()
}
