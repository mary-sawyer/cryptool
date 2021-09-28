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
	"os"
)

// SaltLength defines the max length of generated PBKDF2 salt
var SaltLength int = 16

// KeyLength defines the max length of generated AES key
var KeyLength int = 32

// Iterations defines the number of pbkdf2 iterations the protocol performs
var Iterations int = 1000000

// NonceLength defines the max length of generated AES nonce
var NonceLength int = 12

/* Data defines the struct holding all encryption data to write and read from disk
   - Ciphertext is a byte array holding Hex-encoded, AES-encrypted file
   - Salt is a byte array holding Hex-encoded bytes, used by pbkdf2 to recover SHA256 key
   - Nonce is a byte array holding Hex-encoded bytes, used by AES to recover plaintext */
type Data struct {
	Ciphertext, Salt, Nonce []byte
}

func newData(ciphertext []byte, salt []byte, nonce []byte) *Data {
	return &Data{Ciphertext: ciphertext, Salt: salt, Nonce: nonce}
}

func (d *Data) encode() {
	d.Ciphertext = makeHex(d.Ciphertext)
	d.Salt = makeHex(d.Salt)
	d.Nonce = makeHex(d.Nonce)
}

func (d *Data) decode() {
	d.Ciphertext = unmakeHex(d.Ciphertext)
	d.Salt = unmakeHex(d.Salt)
	d.Nonce = unmakeHex(d.Nonce)
}

func (d *Data) jsonify() []byte {
	j, err := json.Marshal(d)
	if err != nil {
		panic(err.Error())
	}
	return j
}

func decrypt(ciphertext []byte, key []byte, nonce []byte) []byte {
	// Generate new gcm block cipher using key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	// Decrypt ciphertext using key and nonce
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

func encrypt(plaintext []byte, key []byte) ([]byte, []byte) {
	// Generate new gcm block cipher using key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	// Generate cryptographically random nonce
	nonce := generateBytes(NonceLength)

	// Encrypt plaintext using key and nonce
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce
}

func generateKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, Iterations, KeyLength, sha256.New)
}

func generateBytes(length int) []byte {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		panic(err.Error())
	}
	return b
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

	// Check if arguments are ok
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

	if arguments[0] == "-e" { // encryption
		// Generate salt, then key using password and salt
		var salt []byte
		salt = generateBytes(SaltLength)
		key = generateKey(password, salt)

		fmt.Println("Encrypting", arguments[1])

		// Encrypt plaintext file using key
		ciphertext, nonce := encrypt(file, key)

		// Store encryption data in struct and encode
		var data Data = *newData(ciphertext, salt, nonce)
		data.encode()

		// Marshal data to JSON and write to file
		_ = os.WriteFile(arguments[1]+".enc", data.jsonify(), 0644)
	} else if arguments[0] == "-d" { // decryption
		fmt.Println("Decrypting", arguments[1])

		// Unmarshal data from JSON to struct, then decode
		data := Data{}
		_ = json.Unmarshal(file, &data)
		data.decode()

		// Retrieve key, then attempt to decrypt ciphertext
		key = generateKey(password, data.Salt)
		plaintext := decrypt(data.Ciphertext, key, data.Nonce)

		// Write plaintext to file
		_ = os.WriteFile(arguments[1]+".txt", plaintext, 0644)
	}
}
