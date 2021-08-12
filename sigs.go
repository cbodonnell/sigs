package sigs

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

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

func SignString(privateKey *rsa.PrivateKey, s string) (string, error) {
	hashSum, err := hashSum([]byte(s))
	if err != nil {
		return "", err
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashSum)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil

}

func hashSum(b []byte) ([]byte, error) {
	msgHash := sha256.New()
	_, err := msgHash.Write(b)
	if err != nil {
		return nil, err
	}
	return msgHash.Sum(nil), nil
}

func Digest(b []byte) (string, error) {
	hashSum, err := hashSum(b)
	if err != nil {
		return "", err
	}
	digest := base64.StdEncoding.EncodeToString(hashSum)
	if err != nil {
		return "", err
	}
	return string(digest), nil
}

func Check(msg string, signatureString string, publicKeyString string) error {
	publicKey, err := ReadPublicKey([]byte(publicKeyString))
	if err != nil {
		return err
	}

	hashSum, err := hashSum([]byte(msg))
	if err != nil {
		return err
	}

	signature, err := base64.StdEncoding.DecodeString(signatureString)
	if err != nil {
		return err
	}

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashSum, signature)
	if err != nil {
		return err
	}

	return nil
}

// Sign an http request given rsa `privateKey` string and public key `keyID` string
// with request body `data`
func SignRequest(req *http.Request, data []byte, privateKey string, keyID string) error {
	headers := []string{"(request-target)", "date", "host", "content-type", "digest"}
	var signedLines []string
	for _, h := range headers {
		var s string
		switch h {
		case "(request-target)":
			s = strings.ToLower(req.Method) + " " + req.URL.RequestURI()
		case "date":
			s = req.Header.Get(h)
			if s == "" {
				s = time.Now().UTC().Format(http.TimeFormat)
				req.Header.Set(h, s)
			}
		case "host":
			s = req.Header.Get(h)
			if s == "" {
				s = req.URL.Hostname()
				req.Header.Set(h, s)
			}
		case "content-type":
			s = req.Header.Get(h)
		case "digest":
			s = req.Header.Get(h)
			if s == "" {
				digest, err := Digest(data)
				if err != nil {
					return err
				}
				s = fmt.Sprintf("SHA-256=%s", digest)
				req.Header.Set(h, s)
			}
		}
		signedLines = append(signedLines, h+": "+s)
	}
	signedString := strings.Join(signedLines, "\n")

	key, err := ReadPrivateKey([]byte(privateKey))
	if err != nil {
		return err
	}
	sig, err := SignString(key, signedString)
	if err != nil {
		return err
	}

	sigHeader := fmt.Sprintf(`keyId="%s",algorithm="%s",headers="%s",signature="%s"`,
		keyID,
		"rsa-sha256",
		strings.Join(headers, " "),
		sig,
	)
	req.Header.Set("Signature", sigHeader)
	return nil
}
