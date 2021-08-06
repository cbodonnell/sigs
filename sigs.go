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
	// The GenerateKey method takes in a reader that returns random bits, and
	// the number of bits
	privateKey, err := ParseRSA("/users/craig/crypto/private.pem")
	if err != nil {
		panic(err)
	}

	signedString, err := SignString(privateKey, "this is a secret message!")
	if err != nil {
		panic(err)
	}

	// To verify the signature, we provide the public key, the hashing algorithm
	// the hash sum of our message and the signature we generated previously
	// there is an optional "options" parameter which can omit for now
	err = CheckSignature(privateKey, signedString)
	if err != nil {
		panic(err)
	}
	// If we don't get any error from the `VerifyPSS` method, that means our
	// signature is valid
	fmt.Println("signature verified")
}

func ParseRSA(rsaPrivateKeyLocation string) (*rsa.PrivateKey, error) {
	priv, err := ioutil.ReadFile(rsaPrivateKeyLocation)
	if err != nil {
		return nil, err
	}

	privPem, _ := pem.Decode(priv)
	if privPem.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("RSA private key is of the wrong type")
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(privPem.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(privPem.Bytes); err != nil {
			return nil, err
		}
	}

	var privateKey *rsa.PrivateKey
	var ok bool
	privateKey, ok = parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, err
	}

	// pub, err := ioutil.ReadFile(rsaPublicKeyLocation)
	// if err != nil {
	// 	return nil, err
	// }

	// pubPem, _ := pem.Decode(pub)
	// if pubPem == nil {
	// 	return nil, errors.New("rsa public key not in pem format")
	// }
	// if pubPem.Type != "PUBLIC KEY" {
	// 	return nil, fmt.Errorf("RSA public key is of the wrong type %s", pubPem.Type)
	// }

	// if parsedKey, err = x509.ParsePKIXPublicKey(pubPem.Bytes); err != nil {
	// 	return nil, err
	// }

	// var pubKey *rsa.PublicKey
	// if pubKey, ok = parsedKey.(*rsa.PublicKey); !ok {
	// 	return nil, errors.New("unable to parse RSA public key")
	// }

	// privateKey.PublicKey = *pubKey

	return privateKey, nil
}

func SignString(privateKey *rsa.PrivateKey, s string) (SignedString, error) {

	var signedString SignedString

	b := []byte(s)

	// Before signing, we need to hash our message
	// The hash is what we actually sign
	msgHash := sha256.New()
	_, err := msgHash.Write(b)
	if err != nil {
		return signedString, err
	}
	signedString.HashSum = msgHash.Sum(nil)

	// In order to generate the signature, we provide a random number generator,
	// our private key, the hashing algorithm that we used, and the hash sum
	// of our message
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, signedString.HashSum, nil)
	if err != nil {
		return signedString, err
	}

	signedString.Signature = signature

	return signedString, nil

}

func CheckSignature(privateKey *rsa.PrivateKey, signedString SignedString) error {
	err := rsa.VerifyPSS(&privateKey.PublicKey, crypto.SHA256, signedString.HashSum, signedString.Signature, nil)
	if err != nil {
		return err
	}
	return nil
}
