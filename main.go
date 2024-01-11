package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

func encrypt(originalData string) (string, []byte, error) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")

	plaintext := []byte(originalData)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", nil, err
	}

	// Generate a random nonce
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", nil, err
	}

	// Encrypt the data
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	return hex.EncodeToString(ciphertext), nonce, nil
}

func decrypt(encryptedData string, nonce []byte) (string, error) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	ciphertext, _ := hex.DecodeString(encryptedData)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Decrypt the data
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func main() {
	// Example usage
	originalData := "Hello, encryption!"
	encryptedData, nonce, err := encrypt(originalData)
	if err != nil {
		fmt.Println("Encryption error:", err)
		return
	}

	fmt.Println("Encrypted data:", encryptedData)

	decryptedData, err := decrypt(encryptedData, nonce)
	if err != nil {
		fmt.Println("Decryption error:", err)
		return
	}

	fmt.Println("Decrypted data:", decryptedData)
}
