# cryptool.go

Built with Go 1.16. Uses PBKDF2 with SHA-256 for key generation and AES-256 for encryption.

Usage
```
cd cryptool/
go get golang.org/x/crypto/pbkdf2
go build cryptool.go
./cryptool -e plaintext
./cryptool -d ciphertext
```
