package aes

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"testing"
)

func checkError(t *testing.T, err error, text string) {
	if err != nil {
		t.Errorf("%s error: %v", text, err)
		os.Exit(-1)
	}
}

func TestAesWithLeadingIV(t *testing.T) {
	raw := []byte("Hello, world!")
	key16, _ := hex.DecodeString("0123456789abcdef0123456789abcdef")
	key24, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef")
	key32, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	cip128, err := EncryptWithRandomLeadingIV(raw, key16)
	checkError(t, err, "EncryptWithRandomLeadingIV-128")

	cip192, err := EncryptWithRandomLeadingIV(raw, key24)
	checkError(t, err, "EncryptWithRandomLeadingIV-192")

	cip256, err := EncryptWithRandomLeadingIV(raw, key32)
	checkError(t, err, "EncryptWithRandomLeadingIV-256")

	t.Logf("128: %s", hex.EncodeToString(cip128))
	t.Logf("192: %s", hex.EncodeToString(cip192))
	t.Logf("256: %s", hex.EncodeToString(cip256))

	dec128, err := DecryptWithLeadingIV(cip128, key16)
	checkError(t, err, "DecryptWithLeadingIV-128")

	dec192, err := DecryptWithLeadingIV(cip192, key24)
	checkError(t, err, "DecryptWithLeadingIV-192")

	dec256, err := DecryptWithLeadingIV(cip256, key32)
	checkError(t, err, "DecryptWithLeadingIV-256")

	t.Logf("128: %s", string(dec128))
	t.Logf("192: %s", string(dec192))
	t.Logf("256: %s", string(dec256))
}

func TestAesWithoutLeadingIV(t *testing.T) {
	raw := []byte("Hello, world!")
	iv := genIV()
	key16, _ := hex.DecodeString("0123456789abcdef0123456789abcdef")
	key24, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef")
	key32, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	t.Logf("IV:  %s", hex.EncodeToString(iv))

	cipNoIV, err := EncryptWithoutIV(raw, key16)
	checkError(t, err, "EncryptWithoutIV-128")

	cip128, err := EncryptWithIVNotLeading(raw, key16, iv)
	checkError(t, err, "EncryptWithIVNotLeading-128")

	cip192, err := EncryptWithIVNotLeading(raw, key24, iv)
	checkError(t, err, "EncryptWithIVNotLeading-192")

	cip256, err := EncryptWithIVNotLeading(raw, key32, iv)
	checkError(t, err, "EncryptWithIVNotLeading-256")

	t.Logf("nIV: %s", hex.EncodeToString(cipNoIV))
	t.Logf("128: %s", hex.EncodeToString(cip128))
	t.Logf("192: %s", hex.EncodeToString(cip192))
	t.Logf("256: %s", hex.EncodeToString(cip256))

	decNoIV, err := DecryptWithoutIV(cipNoIV, key16)
	checkError(t, err, "DecryptWithoutIV-128")

	dec128, err := DecryptWithIVNotLeading(cip128, key16, iv)
	checkError(t, err, "DecryptWithIVNotLeading-128")

	dec192, err := DecryptWithIVNotLeading(cip192, key24, iv)
	checkError(t, err, "DecryptWithIVNotLeading-192")

	dec256, err := DecryptWithIVNotLeading(cip256, key32, iv)
	checkError(t, err, "DecryptWithIVNotLeading-256")

	t.Logf("nIV: %s", string(decNoIV))
	t.Logf("128: %s", string(dec128))
	t.Logf("192: %s", string(dec192))
	t.Logf("256: %s", string(dec256))
}

func genIV() []byte {
	iv := make([]byte, 16)
	io.ReadFull(rand.Reader, iv)
	return iv
}
