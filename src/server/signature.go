package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

const SignatureLength = 43

var ErrSignature = errors.New("signature failed")

func hash(kind TokenKind, value string, secret []byte) (string, error) {
	value = fmt.Sprintf("%s%s", kind, value)
	cookieHmac := hmac.New(sha256.New, secret)
	_, err := cookieHmac.Write([]byte(value))
	if err != nil {
		return "", err
	}
	signature := cookieHmac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(signature), nil
}

func Sign(kind TokenKind, value string, secret []byte) (string, error) {
	signature, err := hash(kind, value, secret)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%s", signature, value), nil
}

func Verify(kind TokenKind, value string, secret []byte) (string, error) {
	if len(value) < SignatureLength {
		return "", ErrSignature
	}
	signature, data := value[:SignatureLength], value[SignatureLength:]

	actualSignature, err := hash(kind, data, secret)
	if err != nil {
		return "", err
	}
	if signature != actualSignature {
		return "", ErrSignature
	}
	return data, nil
}
