package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

type payload struct {
	Issuer         string `json:"iss"`
	Subject        string `json:"sub"`
	Audience       string `json:"aud"`
	ExpirationTime int64  `json:"exp"`
	NotBefore      int64  `json:"nbf"`
	IssuedAt       int64  `json:"iat"`
	JWTID          string `json:"jti"`
}

// Generate signature for header payload
func signature(header header, payload payload, secret []byte) string {
	header.Algorithm = "HS256"

	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	hStr := base64.RawURLEncoding.EncodeToString(h)
	pStr := base64.RawURLEncoding.EncodeToString(p)

	hs := hmac.New(sha256.New, secret)
	hs.Write([]byte(fmt.Sprintf("%s.%s", hStr, pStr)))
	s := base64.RawURLEncoding.EncodeToString(hs.Sum(nil))

	return fmt.Sprintf("%s.%s.%s", hStr, pStr, s)
}

// Parse string
func parse(src string) (header, payload, error) {
	var (
		header  header
		payload payload
	)

	srcArr := strings.Split(src, ".")
	if len(srcArr) != 3 {
		return header, payload, fmt.Errorf("invalid token")
	}

	hJ, err := base64.RawURLEncoding.DecodeString(srcArr[0])
	if err != nil {
		return header, payload, err
	}

	pJ, err := base64.RawURLEncoding.DecodeString(srcArr[1])
	if err != nil {
		return header, payload, err
	}

	if err := json.Unmarshal([]byte(hJ), &header); err != nil {
		return header, payload, err
	}
	if err := json.Unmarshal([]byte(pJ), &payload); err != nil {
		return header, payload, err
	}

	return header, payload, nil
}

// Generate token string
func New(d time.Duration, iss, sub, aud string, secret []byte) string {
	t := time.Now()
	header := header{"", "JWT"}
	payload := payload{
		Issuer:         iss,
		Subject:        sub,
		Audience:       aud,
		ExpirationTime: t.Add(d).Unix(),
		NotBefore:      t.Unix(),
		IssuedAt:       t.Unix(),
		JWTID:          uuid.NewString(),
	}
	return signature(header, payload, secret)
}

// Verify signature
func VerifySignature(src string, secret []byte) (payload, error) {
	h, p, err := parse(src)
	if err != nil {
		return p, err
	}

	if src != signature(h, p, secret) {
		return p, fmt.Errorf("invalid signature")
	}

	return p, nil
}

// After verifying the signature, a new token is returned
// The old token can still be used
func Refresh(src string, d time.Duration, secret []byte) (string, error) {
	if _, err := VerifySignature(src, secret); err != nil {
		return "", err
	}

	h, p, _ := parse(src)

	now := time.Now()
	p.ExpirationTime = now.Add(d).Unix()
	p.IssuedAt = now.Unix()
	p.NotBefore = now.Unix()
	return signature(h, p, secret), nil
}
