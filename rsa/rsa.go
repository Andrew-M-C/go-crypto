package rsa

import (
	"crypto"
	"crypto/rsa"
	"io"
	"math/big"

	cryptoerr "github.com/Andrew-M-C/go-crypto/errors"
)

const (
	// ErrNilKey 表示空钥
	ErrNilKey = cryptoerr.E("nil key")
)

var (
	// DecryptPKCS1v15PrivateKey 使用密钥对一段密文进行解密
	DecryptPKCS1v15PrivateKey = rsa.DecryptPKCS1v15
	// EncryptPKCS1v15PublicKey 使用公钥对一段明文进行加密
	EncryptPKCS1v15PublicKey = rsa.EncryptPKCS1v15
)

// EncryptPKCS1v15PrivateKey 使用私钥对一段明文进行加密
func EncryptPKCS1v15PrivateKey(rand io.Reader, priv *rsa.PrivateKey, plain []byte) ([]byte, error) {
	if nil == priv {
		return nil, ErrNilKey
	}
	return rsa.SignPKCS1v15(rand, priv, crypto.Hash(0), plain)
}

// DecryptPKCS1v15PublicKey 使用公钥对一段密文进行解密
func DecryptPKCS1v15PublicKey(pub *rsa.PublicKey, ciphertext []byte) ([]byte, error) {
	if nil == pub {
		return nil, ErrNilKey
	}

	c := new(big.Int)
	m := new(big.Int)
	m.SetBytes(ciphertext)
	e := big.NewInt(int64(pub.E))
	c.Exp(m, e, pub.N)
	out := c.Bytes()
	skip := 0

	for i := 2; i < len(out); i++ {
		if i+1 >= len(out) {
			break
		}
		if out[i] == 0xFF && out[i+1] == 0 {
			skip = i + 2
			break
		}
	}
	return out[skip:], nil
}
