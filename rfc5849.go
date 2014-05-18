package oauth1

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	errAuthHeaderParam = errors.New("request header Authorization is malformed")
)

// authenticate calculates the values of a set of protocol parameters and
// returns the signed Authorization header
//
// See RFC 5849 Section 3.1.
func authenticate(req *http.Request, params url.Values, key string) (string, error) {
	base, err := signatureBase(req, params)
	if err != nil {
		return "", err
	}

	signature, err := sign(base, key)
	if err != nil {
		return "", err
	}

	params.Add("oauth_signature", signature)

	return makeAuthorizationHeader(params), nil
}

// makeAuthorizationHeader returns the value for the Authorize header.
//
// See RFC 5849 Section 3.1.
func makeAuthorizationHeader(params url.Values) string {
	rv := "OAuth "
	for k, v := range params {
		if strings.HasPrefix(k, "oauth_") {
			rv += k + `="` + encode(v[0]) + `",`
		}
	}

	return rv[:len(rv)-1]
}

// generateTimestamp returns the seconds since epoch in UTC as a string.
//
// See RFC 5849 Section 3.3.
func generateTimestamp() string {
	return strconv.FormatInt(time.Now().Unix(), 10)
}

// generateNonce returns a random string to prevent replay attacks.
// The current unix timestamp is appended to random data.
//
// See RFC 5849 Section 3.3.
func generateNonce() (string, error) {
	b := make([]byte, 24)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b) + generateTimestamp(), nil
}

// signatureBase constructs the signature base string for signing purposes.
//
// See RFC 5849 Section 3.4.1.1.
func signatureBase(req *http.Request, extra url.Values) (string, error) {
	base, err := baseStringURI(req)
	if err != nil {
		return "", err
	}

	values, err := collectParameters(req, extra)
	if err != nil {
		return "", err
	}

	params := normalizeParameters(values)

	return req.Method + "&" + encode(base) + "&" + encode(params), nil
}

// baseStringURI parses a http.Request into a base string URI.
//
// See RFC 5849 Section 3.4.1.2.
func baseStringURI(req *http.Request) (string, error) {
	// Include the port only if it is the default port for the scheme.
	scheme := strings.ToLower(req.URL.Scheme)
	hostname := strings.ToLower(req.Host)
	switch {
	case scheme == "http" && strings.HasSuffix(hostname, ":80"):
		hostname = hostname[:len(hostname)-len(":80")]
	case scheme == "https" && strings.HasSuffix(hostname, ":443"):
		hostname = hostname[:len(hostname)-len(":443")]
	}

	// Remove the query portion from the encoded request URI.
	u := *req.URL
	u.RawQuery = ""
	path := u.RequestURI()

	return scheme + "://" + hostname + path, nil
}

// collectParameters collects parameters from the request.
//
// See RFC 5849 Section 3.4.1.3.1.
func collectParameters(req *http.Request, extra url.Values) (url.Values, error) {
	params, err := parseAuthorizationHeader(req)
	if err != nil {
		return nil, err
	}

	rv := url.Values{}
	err = req.ParseForm()
	if err == nil {
		for k := range req.Form {
			for _, v := range req.Form[k] {
				rv.Add(k, v)
			}
		}
	}

	for k := range params {
		for _, v := range params[k] {
			rv.Add(k, v)
		}
	}

	for k := range extra {
		for _, v := range extra[k] {
			rv.Add(k, v)
		}
	}

	rv.Del("oauth_signature")

	return rv, nil
}

// normalizeParameters sorts and encodes url.Values.
//
// See RFC 5849 Section 3.4.1.3.2.
func normalizeParameters(in url.Values) string {
	rv := ""
	if in == nil {
		return ""
	}

	params := make(url.Values, len(in))
	for k, vs := range in {
		params[encode(k)] = vs
	}

	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}

	sort.Strings(keys)
	for _, k := range keys {
		vs := params[k]
		values := make([]string, 0, len(vs))
		for _, v := range vs {
			values = append(values, encode(v))
		}

		sort.Strings(values)
		for _, v := range values {
			if len(rv) > 0 {
				rv += "&"
			}
			rv += k + "=" + v
		}
	}

	return rv
}

// sign returns the HMAC-SHA1 signature from base and key.
//
// See RFC 5849 Section 3.4.2.
func sign(base string, key string) (string, error) {
	h := hmac.New(sha1.New, []byte(key))
	_, err := h.Write([]byte(base))
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

// parseAuthorizationHeader parses the HTTP Authorization header if present.
// The realm parameter is removed if present.
//
// See RFC 5849 Section 3.5.1.
func parseAuthorizationHeader(req *http.Request) (url.Values, error) {
	header := req.Header.Get("Authorization")
	if len(header) < 6 {
		return nil, nil
	}

	scheme := strings.ToLower(header[:6])
	if scheme != "oauth " {
		return nil, nil
	}

	parts := strings.Split(header[6:], ",")
	rv := make(url.Values)
	for _, part := range parts {
		part = strings.TrimSpace(part)
		param := strings.Split(part, "=")
		if len(param) != 2 || param[1] == "" {
			return nil, errAuthHeaderParam
		}

		// Add key/value pair without surrounding value quotes.
		rv.Add(param[0], param[1][1:len(param[1])-1])
	}

	rv.Del("realm")

	return rv, nil
}

// encode performs percent encoding on strings.
//
// See RFC 5849 Section 3.6.
func encode(s string) string {
	n := 0
	for i := 0; i < len(s); i++ {
		if shouldEncode(s[i]) {
			n += 3
		} else {
			n++
		}
	}

	b := make([]byte, n)
	j := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if shouldEncode(s[i]) {
			b[j] = '%'
			b[j+1] = "0123456789ABCDEF"[c>>4]
			b[j+2] = "0123456789ABCDEF"[c&15]
			j += 3
		} else {
			b[j] = c
			j++
		}
	}

	return string(b)
}

// shouldEncode returns true if the specified byte should be encoded.
func shouldEncode(c byte) bool {
	if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' {
		return false
	}

	switch c {
	case '-', '_', '.', '~':
		return false
	}

	return true
}
