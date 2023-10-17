package rsa_test

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

	amcrsa "github.com/Andrew-M-C/go-crypto/rsa"
	"github.com/smartystreets/goconvey/convey"
)

var (
	cv = convey.Convey
	so = convey.So
	eq = convey.ShouldEqual

	isNil = convey.ShouldBeNil
)

func TestRSA(t *testing.T) {
	cv("解析 key", t, func() { testParseKey(t) })
	cv("RSA 加解密", t, func() { testRsaEncDec(t) })
}

func home() string {
	return os.Getenv("HOME")
}

func testParseKey(t *testing.T) {
	privpath := home() + "/.ssh/id_rsa"
	pubpath := home() + "/.ssh/id_rsa.pub"

	priv, err := amcrsa.ParsePrivateKeyPemByFile(privpath)
	so(err, isNil)

	pub, err := amcrsa.ParsePublicKeyPubByFile(pubpath)
	so(err, isNil)

	// 生成 .pem 格式的 pub key，并重新读回来
	pubB := x509.MarshalPKCS1PublicKey(pub)
	pubPemBlk := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubB,
	}
	buff := &bytes.Buffer{}
	_ = pem.Encode(buff, pubPemBlk)

	pub, err = amcrsa.ParsePublicKeyPem(buff.Bytes())
	so(err, isNil)

	// 加解密检查
	text := "Hello, RSA!"

	ciphertext, err := amcrsa.EncryptPKCS1v15PrivateKey(rand.Reader, priv, []byte(text))
	so(err, isNil)
	t.Logf("Got encrypted data: %s", hex.EncodeToString(ciphertext))

	plain, err := amcrsa.DecryptPKCS1v15PublicKey(pub, ciphertext)
	so(err, isNil)
	so(text, eq, string(plain))

	// 签验签检查
	h := sha256.Sum256([]byte(text))
	ciphertext, err = rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
	so(err, isNil)
	t.Logf("Got sign: %s", hex.EncodeToString(ciphertext))

	err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], ciphertext)
	so(err, isNil)
}
