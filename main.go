package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

func generateKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	publicKey := &privateKey.PublicKey
	return privateKey, publicKey, nil
}

func saveKeyToFile(key interface{}, fileName string) error {
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	if fileName == "encrypted_msg.txt"{
		keyToByte, _ := key.([]byte)
		err := os.WriteFile(fileName, keyToByte, 0644)
		if err != nil{
			return err
		}
		return nil
	}

	var pemBlock *pem.Block
	switch key := key.(type) {
	case *rsa.PrivateKey:
		pemBlock = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	case *rsa.PublicKey:
		derBytes, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return err
		}
		pemBlock = &pem.Block{Type: "RSA PUBLIC KEY", Bytes: derBytes}
	default:
		result, _ := key.([]byte)
		fmt.Println(result)
		return fmt.Errorf("unsupported key type")
	}

	return pem.Encode(file, pemBlock)
}

func loadKeyFromFile(fileName string, isPrivate bool) (interface{}, error) {
	fileData, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	pemBlock, _ := pem.Decode(fileData)

	switch pemBlock.Type {
	case "RSA PRIVATE KEY":
		if !isPrivate {
			return nil, fmt.Errorf("trying to load a private key as public key")
		}
		return x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	case "RSA PUBLIC KEY":
		if isPrivate {
			return nil, fmt.Errorf("trying to load a public key as private key")
		}
		keyInterface, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}
		publicKey, ok := keyInterface.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("unable to convert to RSA public key")
		}
		return publicKey, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", pemBlock.Type)
	}
}

func encrypt(message string, publicKey *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, []byte(message), nil)
}

func decrypt(ciphertext []byte, privateKey *rsa.PrivateKey) (string, error) {
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
	return string(plaintext), err
}

func main() {
	privateKey, publicKey, err := generateKeyPair()
	if err != nil {
		fmt.Println("Error generating key pair:", err)
		return
	}

	// Simpan kunci ke file
	err = saveKeyToFile(privateKey, "private_key.pem")
	if err != nil {
		fmt.Println("Error saving private key:", err)
		return
	}

	err = saveKeyToFile(publicKey, "public_key.pem")
	if err != nil {
		fmt.Println("Error saving public key:", err)
		return
	}

	// Load kunci dari file
	loadedPrivateKey, err := loadKeyFromFile("private_key.pem", true)
	if err != nil {
		fmt.Println("Error loading private key:", err)
		return
	}

	loadedPublicKey, err := loadKeyFromFile("public_key.pem", false)
	if err != nil {
		fmt.Println("Error loading public key:", err)
		return
	}

	// Pesan untuk dienkripsi
	originalMessage := "asjhdk@31_-|jfhKJAHSKU12`KJHS.KJHSD,,,"

	// Enkripsi
	ciphertext, err := encrypt(originalMessage, loadedPublicKey.(*rsa.PublicKey))
	if err != nil {
		fmt.Println("Error encrypting message:", err)
		return
	}

	fmt.Printf("Ciphertext: %x\n", ciphertext)
	fileName := "encrypted_msg.txt"
	err = saveKeyToFile(ciphertext, fileName)
	if err != nil{
		fmt.Println(err)
		return
	}
	
	fileData, err := ioutil.ReadFile(fileName)
	if err != nil{
		fmt.Println(err)
		return 
	}

	// fmt.Println(fileData)
	// Dekripsi
	decryptedMessage, err := decrypt(fileData, loadedPrivateKey.(*rsa.PrivateKey))
	if err != nil {
		fmt.Println("Error decrypting message:", err)
		return
	}

	fmt.Println("Decrypted Message:", decryptedMessage)
}
