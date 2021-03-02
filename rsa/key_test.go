package rsa

import (
	"crypto/rand"
	"os"
	"testing"
)

func home() string {
	return os.Getenv("HOME")
}

func TestParseKey(t *testing.T) {
	privpath := home() + "/.ssh/id_rsa"
	pubpath := home() + "/.ssh/id_rsa.pub"

	priv, err := ParsePrivateKeyPemByFile(privpath)
	checkError(t, err, "ParsePrivateKeyPemByFile")

	pub, err := ParsePublicKeyPubByFile(pubpath)
	checkError(t, err, "ParsePublicKeyPubByFile")

	text := "Hello, RSA!"

	sign, err := EncryptPKCS1v15PublicKey(rand.Reader, pub, []byte(text))
	checkError(t, err, "EncryptPKCS1v15PublicKey")

	plain, err := DecryptPKCS1v15PrivateKey(rand.Reader, priv, sign)
	checkError(t, err, "DecryptPKCS1v15PrivateKey")

	if s := string(plain); s != text {
		t.Errorf("plain text mismatch, got '%s'", s)
		return
	}

	t.Logf("check passed")
	return
}
