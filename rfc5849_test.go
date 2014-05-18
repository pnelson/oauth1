package oauth1

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const authorizationHeader = `OAuth realm="Example",
oauth_consumer_key="9djdj82h48djs9d2",
oauth_token="kkk9d7dh3k39sjv7",
oauth_signature_method="HMAC-SHA1",
oauth_timestamp="137131201",
oauth_nonce="7d8f3e4a",
oauth_signature="bYT5CMsGcbgUdFHObYMEfcx6bsw%3D"`

func TestSignatureBase(t *testing.T) {
	url := "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b"
	body := strings.NewReader("c2&a3=2+q")
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", authorizationHeader)

	expected := "" +
		"POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q" +
		"%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_" +
		"key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_m" +
		"ethod%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk" +
		"9d7dh3k39sjv7"

	out, err := signatureBase(req, nil)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	if out != expected {
		t.Errorf("incorrect\nhave %s\nwant %s", out, expected)
	}
}

func TestBaseStringURI(t *testing.T) {
	var tests = []struct {
		// in
		scheme string
		host   string
		path   string

		// out
		out string
	}{
		{"http", "EXAMPLE.COM:80", "/r%20v/X?id=123", "http://example.com/r%20v/X"},
		{"https", "www.example.net:8080", "/?q=1", "https://www.example.net:8080/"},
	}

	for i, tt := range tests {
		url := tt.scheme + "://" + tt.host + tt.path
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatalf("unexpected error %v", err)
		}

		out, err := baseStringURI(req)
		if err != nil {
			t.Fatalf("unexpected error %v", err)
		}

		if out != tt.out {
			t.Errorf("%d. baseStringURI %v\nhave %s\nwant %s", i, url, out, tt.out)
		}
	}
}

func TestCollectParameters(t *testing.T) {
	url := "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b"
	body := strings.NewReader("c2&a3=2+q")
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", authorizationHeader)

	values, err := collectParameters(req, nil)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	if _, ok := values["b5"]; !ok {
		t.Errorf("query component should be processed")
	}

	if _, ok := values["oauth_token"]; !ok {
		t.Errorf("authorization header should be processed")
	}

	if _, ok := values["c2"]; !ok {
		t.Errorf("entity body should be processed")
	}

	if _, ok := values["oauth_signature"]; ok {
		t.Errorf("oauth_signature MUST be excluded")
	}
}

func TestNormalizeParameters(t *testing.T) {
	params := url.Values{}
	params.Add("b5", "=%3D")
	params.Add("a3", "a")
	params.Add("c@", "")
	params.Add("a2", "r b")
	params.Add("oauth_consumer_key", "9djdj82h48djs9d2")
	params.Add("oauth_token", "kkk9d7dh3k39sjv7")
	params.Add("oauth_signature_method", "HMAC-SHA1")
	params.Add("oauth_timestamp", "137131201")
	params.Add("oauth_nonce", "7d8f3e4a")
	params.Add("c2", "")
	params.Add("a3", "2 q")

	expected := "" +
		"a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9dj" +
		"dj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1" +
		"&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7"

	out := normalizeParameters(params)
	if out != expected {
		t.Errorf("incorrect\nhave %s\nwant %s", out, expected)
	}
}

func TestParseAuthorizationHeader(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com/", nil)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	req.Header.Set("Authorization", authorizationHeader)

	values, err := parseAuthorizationHeader(req)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	if v := values.Get("oauth_token"); v != "kkk9d7dh3k39sjv7" {
		t.Errorf("oauth_token\nhave %s\nwant %s", v, "kkk9d7dh3k39sjv7")
	}

	if _, ok := values["realm"]; ok {
		t.Errorf("realm should be excluded")
	}
}
