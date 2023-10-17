package aes_test

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"

	amcaes "github.com/Andrew-M-C/go-crypto/aes"
	"github.com/smartystreets/goconvey/convey"
)

var (
	cv = convey.Convey
	so = convey.So
	eq = convey.ShouldEqual

	isNil = convey.ShouldBeNil
)

func TestAES(t *testing.T) {
	cv("带初始向量", t, func() { testAesWithLeadingIV(t) })
	cv("不带初始向量", t, func() { testAesWithoutLeadingIV(t) })
}

func testAesWithLeadingIV(t *testing.T) {
	raw := []byte("Hello, world!")
	key16, _ := hex.DecodeString("0123456789abcdef0123456789abcdef")
	key24, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef")
	key32, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	cip128, err := amcaes.EncryptWithRandomLeadingIV(raw, key16)
	so(err, isNil)

	cip192, err := amcaes.EncryptWithRandomLeadingIV(raw, key24)
	so(err, isNil)

	cip256, err := amcaes.EncryptWithRandomLeadingIV(raw, key32)
	so(err, isNil)

	t.Logf("128: %s", hex.EncodeToString(cip128))
	t.Logf("192: %s", hex.EncodeToString(cip192))
	t.Logf("256: %s", hex.EncodeToString(cip256))

	dec128, err := amcaes.DecryptWithLeadingIV(cip128, key16)
	so(err, isNil)
	so(dec128, eq, raw)

	dec192, err := amcaes.DecryptWithLeadingIV(cip192, key24)
	so(err, isNil)
	so(dec192, eq, raw)

	dec256, err := amcaes.DecryptWithLeadingIV(cip256, key32)
	so(err, isNil)
	so(dec256, eq, raw)

	// t.Logf("128: %s", string(dec128))
	// t.Logf("192: %s", string(dec192))
	// t.Logf("256: %s", string(dec256))
}

func testAesWithoutLeadingIV(t *testing.T) {
	raw := []byte("Hello, world!")
	iv := genIV()
	key16, _ := hex.DecodeString("0123456789abcdef0123456789abcdef")
	key24, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef")
	key32, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	t.Logf("IV:  %s", hex.EncodeToString(iv))

	cipNoIV, err := amcaes.EncryptWithoutIV(raw, key16)
	so(err, isNil)

	cip128, err := amcaes.EncryptWithIVNotLeading(raw, key16, iv)
	so(err, isNil)

	cip192, err := amcaes.EncryptWithIVNotLeading(raw, key24, iv)
	so(err, isNil)

	cip256, err := amcaes.EncryptWithIVNotLeading(raw, key32, iv)
	so(err, isNil)

	t.Logf("nIV: %s", hex.EncodeToString(cipNoIV))
	t.Logf("128: %s", hex.EncodeToString(cip128))
	t.Logf("192: %s", hex.EncodeToString(cip192))
	t.Logf("256: %s", hex.EncodeToString(cip256))

	decNoIV, err := amcaes.DecryptWithoutIV(cipNoIV, key16)
	so(err, isNil)
	so(decNoIV, eq, raw)

	dec128, err := amcaes.DecryptWithIVNotLeading(cip128, key16, iv)
	so(err, isNil)
	so(dec128, eq, raw)

	dec192, err := amcaes.DecryptWithIVNotLeading(cip192, key24, iv)
	so(err, isNil)
	so(dec192, eq, raw)

	dec256, err := amcaes.DecryptWithIVNotLeading(cip256, key32, iv)
	so(err, isNil)
	so(dec256, eq, raw)

	// t.Logf("nIV: %s", string(decNoIV))
	// t.Logf("128: %s", string(dec128))
	// t.Logf("192: %s", string(dec192))
	// t.Logf("256: %s", string(dec256))
}

func genIV() []byte {
	iv := make([]byte, 16)
	_, _ = io.ReadFull(rand.Reader, iv)
	return iv
}
