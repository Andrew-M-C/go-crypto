package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"os"
	"testing"
)

func checkError(t *testing.T, err error, text string) {
	if err != nil {
		t.Errorf("%s error: %v", text, err)
		os.Exit(-1)
	}
}

func TestRsaEncDec(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	plain := []byte("Hello, world!")

	cipher, err := EncryptPKCS1v15PrivateKey(rand.Reader, priv, plain)
	checkError(t, err, "EncryptPKCS1v15PrivateKey")

	t.Logf("cipher (len %d): %s", len(cipher), hex.EncodeToString(cipher))

	dec, err := DecryptPKCS1v15PublicKey(&priv.PublicKey, cipher)
	checkError(t, err, "DecryptPKCS1v15PublicKey")

	t.Logf("dec: %s", string(dec))
}
