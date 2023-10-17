package rsa_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"testing"

	amcrsa "github.com/Andrew-M-C/go-crypto/rsa"
)

func checkError(t *testing.T, err error, text string) {
	if err != nil {
		t.Errorf("%s error: %v", text, err)
		os.Exit(-1)
	}
}

func TestRsaEncDec(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	printKey(t, priv)

	plain := []byte("Hello, world!")

	cipher, err := amcrsa.EncryptPKCS1v15PrivateKey(rand.Reader, priv, plain)
	checkError(t, err, "EncryptPKCS1v15PrivateKey")

	t.Logf("cipher (len %d): %s", len(cipher), hex.EncodeToString(cipher))

	dec, err := amcrsa.DecryptPKCS1v15PublicKey(&priv.PublicKey, cipher)
	checkError(t, err, "DecryptPKCS1v15PublicKey")

	t.Logf("dec: %s", string(dec))
}

func printKey(t *testing.T, priv *rsa.PrivateKey) {
	privPemBlk := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}

	pubB := x509.MarshalPKCS1PublicKey(&priv.PublicKey)
	// pubB, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	// if err != nil {
	// 	t.Errorf("x509.MarshalPKIXPublicKey error: %v", err)
	// 	return
	// }

	pubPemBlk := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubB,
	}

	buff := &bytes.Buffer{}
	_ = pem.Encode(buff, privPemBlk)

	buff.WriteString("\n\n\n")
	_ = pem.Encode(buff, pubPemBlk)

	t.Log(buff.String())
}
