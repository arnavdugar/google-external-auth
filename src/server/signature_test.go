package server_test

import (
	"testing"

	"github.com/arnavdugar/google-external-auth/server"

	"github.com/stretchr/testify/assert"
)

var secret = []byte{
	0x4e, 0x5e, 0x07, 0x4c, 0x34, 0x30, 0x88, 0x85,
	0xef, 0x28, 0x88, 0x80, 0x2a, 0xd1, 0x97, 0x7e,
}

func TestSignatureLength(t *testing.T) {
	value := "value"
	signature, err := server.Sign("k", value, secret)
	assert.NoError(t, err)
	assert.Equal(t, "value", signature[server.SignatureLength:])
}

func TestSignature(t *testing.T) {
	expectedValue := "value"
	signature, err := server.Sign("k", expectedValue, secret)
	assert.NoError(t, err)
	actualValue, err := server.Verify("k", signature, secret)
	assert.NoError(t, err)
	assert.Equal(t, expectedValue, actualValue)
}
