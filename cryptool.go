package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"os"
)

/* SaltLength defines the max length of generated AES salt */
var SaltLength int = 16
/* KeyLength defines the max length of generated AES key */
var KeyLength int = 32
/* Iterations defines the number of pbkdf2 iterations the protocol performs */
var Iterations int = 1000000
/* File defines the struct holding all data to write/read from disk */
/* Data is a byte array holding Hex-encoded, AES-encrypted ciphertext */
/* Salt is a byte array holding Hex-encoded bytes, used by pbkdf2 to recover SHA256 key */
/* Nonce is a byte array holding Hex-encoded bytes, used by AES to recover plaintext */
type File struct {
	Data, Salt, Nonce []byte
}

func decrypt(file []byte, key []byte, nonce []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := gcm.Open(nil, nonce, file, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

func encrypt(file []byte, key []byte) ([]byte, []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	return gcm.Seal(nil, nonce, file, nil), nonce
}

func generateKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, Iterations, KeyLength, sha256.New)
}

func generateSalt() []byte {
	salt := make([]byte, SaltLength)
	_, err := rand.Read(salt)
	if err != nil {
		panic(err.Error())
	}
	return salt
}

func unmakeHex(in []byte) []byte {
	out := make([]byte, hex.DecodedLen(len(in)))
	_, err := hex.Decode(out, in)
	if err != nil {
		panic(err.Error())
	}
	return out
}

func makeHex(in []byte) []byte {
	out := make([]byte, hex.EncodedLen(len(in)))
	hex.Encode(out, in)
	return out
}

func printHelp() {
	fmt.Println("-e [filename]")
	fmt.Println("   encrypts file and writes to [filename].enc")
	fmt.Println("-d [filename]")
	fmt.Println("   decrypts file and writes to [filename].txt")
}

func main() {
	arguments := os.Args[1:]
	if len(arguments) < 2 {
		printHelp()
		os.Exit(1)
	}

	// Try to read file
	file, err := os.ReadFile(arguments[1])
	if err != nil {
		panic(err.Error())
	}

	// Get password from user
	fmt.Println("Enter file password: ")
	var password string
	fmt.Scanln(&password)

	var key []byte

	if arguments[0] == "-e" {
		// Generate key given user password
		var newSalt []byte
		newSalt = generateSalt()
		key = generateKey(password, newSalt)

		fmt.Println("Encrypt", arguments[1], "with pass", password)
		ciphertext, newNonce := encrypt(file, key)
		encData := File{
			Data:  makeHex(ciphertext),
			Nonce: makeHex(newNonce),
			Salt:  makeHex(newSalt),
		}
		fileOut, _ := json.Marshal(encData)
		_ = os.WriteFile(arguments[1]+".enc", fileOut, 0644)
	} else if arguments[0] == "-d" {
		fmt.Println("Decrypt", arguments[1], "with pass", password)
		encData := File{}
		_ = json.Unmarshal([]byte(file), &encData)
		key = generateKey(password, unmakeHex(encData.Salt))
		plaintext := decrypt(unmakeHex(encData.Data), key, unmakeHex(encData.Nonce))
		_ = os.WriteFile(arguments[1]+".txt", plaintext, 0644)
	}
}
