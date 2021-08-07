package sigs

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

// SignedString struct
type SignedString struct {
	Signature []byte
	HashSum   []byte
}

func main() {
	privateKey, err := ParseRSAPrivateKey("/users/craig/crypto/private.pem")
	if err != nil {
		panic(err)
	}

	signedString, err := SignString(privateKey, "this is a secret message!")
	if err != nil {
		panic(err)
	}

	err = CheckSignature(&privateKey.PublicKey, signedString)
	if err != nil {
		panic(err)
	}

	fmt.Println("signature verified")
}

func ReadPrivateKey(b []byte) (*rsa.PrivateKey, error) {
	privPem, _ := pem.Decode(b)
	if privPem.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("RSA private key is of the wrong type")
	}

	var parsedKey interface{}
	parsedKey, err := x509.ParsePKCS1PrivateKey(privPem.Bytes)
	if err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(privPem.Bytes); err != nil {
			return nil, err
		}
	}

	privateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("unable to parse RSA private key")
	}

	return privateKey, nil
}

func ParseRSAPrivateKey(rsaPrivateKeyLocation string) (*rsa.PrivateKey, error) {
	priv, err := ioutil.ReadFile(rsaPrivateKeyLocation)
	if err != nil {
		return nil, err
	}

	return ReadPrivateKey(priv)
}

func ReadPublicKey(b []byte) (*rsa.PublicKey, error) {
	pubPem, _ := pem.Decode(b)
	if pubPem == nil {
		return nil, errors.New("rsa public key not in pem format")
	}
	if pubPem.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("RSA public key is of the wrong type %s", pubPem.Type)
	}

	parsedKey, err := x509.ParsePKIXPublicKey(pubPem.Bytes)
	if err != nil {
		return nil, err
	}

	var pubKey *rsa.PublicKey
	pubKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("unable to parse RSA public key")
	}

	return pubKey, nil
}

func ParseRSAPublicKey(rsaPublicKeyLocation string) (*rsa.PublicKey, error) {
	pub, err := ioutil.ReadFile(rsaPublicKeyLocation)
	if err != nil {
		return nil, err
	}

	return ReadPublicKey(pub)
}

func SignString(privateKey *rsa.PrivateKey, s string) (SignedString, error) {
	var signedString SignedString

	hashSum, err := HashSum(s)
	if err != nil {
		return signedString, err
	}
	signedString.HashSum = hashSum

	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, signedString.HashSum, nil)
	if err != nil {
		return signedString, err
	}
	signedString.Signature = signature

	return signedString, nil

}

func HashSum(s string) ([]byte, error) {
	b := []byte(s)
	msgHash := sha256.New()
	_, err := msgHash.Write(b)
	if err != nil {
		return nil, err
	}
	return msgHash.Sum(nil), nil
}

func CheckSignature(publicKey *rsa.PublicKey, signedString SignedString) error {
	err := rsa.VerifyPSS(publicKey, crypto.SHA256, signedString.HashSum, signedString.Signature, nil)
	if err != nil {
		return err
	}
	return nil
}
