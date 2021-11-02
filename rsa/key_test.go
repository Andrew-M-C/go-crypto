package rsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
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

	// 生成 .pem 格式的 pub key，并重新读回来
	pubB := x509.MarshalPKCS1PublicKey(pub)
	pubPemBlk := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubB,
	}
	buff := &bytes.Buffer{}
	pem.Encode(buff, pubPemBlk)

	pub, err = ParsePublicKeyPem(buff.Bytes())
	checkError(t, err, "ParsePublicKeyPem")

	// 加解密检查
	text := "Hello, RSA!"

	ciphertext, err := EncryptPKCS1v15PrivateKey(rand.Reader, priv, []byte(text))
	checkError(t, err, "EncryptPKCS1v15PrivateKey")
	t.Logf("Got encrypted data: %s", hex.EncodeToString(ciphertext))

	plain, err := DecryptPKCS1v15PublicKey(pub, ciphertext)
	checkError(t, err, "DecryptPKCS1v15PublicKey")

	if s := string(plain); s != text {
		t.Errorf("plain text mismatch, got '%s'", s)
		return
	}

	// 签验签检查
	h := sha256.Sum256([]byte(text))
	ciphertext, err = rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
	checkError(t, err, "rsa.SignPKCS1v15")
	t.Logf("Got sign: %s", hex.EncodeToString(ciphertext))

	err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], ciphertext)
	checkError(t, err, "rsa.VerifyPKCS1v15")

	t.Logf("check passed")
}
