package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	crypto "gitlab.com/Andrew-M-C/go.crypto"
)

const (
	// ErrIllegalIV 表示初始向量不合法
	ErrIllegalIV = crypto.E("illegal initial vactor")
)

var (
	// nilIV 用于不指定向量的加解密
	nilIV = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
)

// EncryptWithLeadingIV 使用初始向量和密钥进行加密，同时将 IV 附在最字节串的最前面
func EncryptWithLeadingIV(in, iv, key []byte) (res []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		err = fmt.Errorf("aes.NewCipher error: %w", err)
		return
	}

	blockSize := block.BlockSize()
	in = padPKCS7(in, blockSize)

	res = make([]byte, blockSize+len(in))

	// 最前面的一个块作为 IV
	copy(res, iv)

	// 加密
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(res[blockSize:], in)

	return res, nil
}

// EncryptWithRandomLeadingIV 使用随机的初始响亮进行加密，并且将 IV 附在最字节串的最前面
func EncryptWithRandomLeadingIV(in, key []byte) ([]byte, error) {
	iv := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, fmt.Errorf("generate from rand error: %w", err)
	}

	return EncryptWithLeadingIV(in, iv, key)
}

// DecryptWithLeadingIV 解密一个最前面为初始向量的密文串
func DecryptWithLeadingIV(in, key []byte) (res []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		err = fmt.Errorf("aes.NewCipher error: %w", err)
		return
	}

	blockSize := block.BlockSize()
	if len(in) < blockSize {
		err = errors.New("ciphertext is too short")
		return
	}

	iv := in[:blockSize]
	in = in[blockSize:]
	if len(in)%blockSize != 0 {
		err = fmt.Errorf("cyphertext do not align to %d", blockSize)
		return
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	res = make([]byte, len(in))
	mode.CryptBlocks(res, in)

	res = unpadPKCS7(res)
	return res, nil
}

// EncryptWithIVNotLeading 加密，但在密文的最前面没有 IV。解密者需要手动指定
func EncryptWithIVNotLeading(in, key, iv []byte) (res []byte, err error) {
	if len(iv) != 16 {
		return nil, ErrIllegalIV
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		err = fmt.Errorf("aes.NewCipher error: %w", err)
		return
	}

	blockSize := block.BlockSize()
	in = padPKCS7(in, blockSize)

	res = make([]byte, len(in))

	// 加密
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(res, in)

	return res, nil
}

// DecryptWithIVNotLeading 解密，但 IV 需要手动指定，在密文的最前面并没有 IV
func DecryptWithIVNotLeading(in, key, iv []byte) (res []byte, err error) {
	if len(iv) != 16 {
		return nil, ErrIllegalIV
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		err = fmt.Errorf("aes.NewCipher error: %w", err)
		return
	}

	blockSize := block.BlockSize()
	if len(in)%blockSize != 0 {
		err = fmt.Errorf("cyphertext do not align to %d", blockSize)
		return
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	res = make([]byte, len(in))
	mode.CryptBlocks(res, in)

	res = unpadPKCS7(res)
	return res, nil
}

// EncryptWithoutIV 使用无视 IV 的模式进行加密
func EncryptWithoutIV(in, key []byte) (res []byte, err error) {
	return EncryptWithIVNotLeading(in, key, nilIV)
}

// DecryptWithoutIV 使用无视 IV 的模式进行解密
func DecryptWithoutIV(in, key []byte) (res []byte, err error) {
	return DecryptWithIVNotLeading(in, key, nilIV)
}

func padPKCS7(b []byte, blockSize int) []byte {
	padding := blockSize - len(b)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(b, padtext...)
}

func unpadPKCS7(b []byte) []byte {
	le := len(b)
	unPadding := int(b[le-1])
	return b[:(le - unPadding)]
}
