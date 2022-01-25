// sigs is a package that provides utilities implementing the
// http signature protocol: https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures
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
	"regexp"
	"strings"
	"time"
)

// ReadPrivateKey reads a byte array and returns a pointer to a PrivateKey
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

// ParseRSAPrivateKey takes a file path and reads the private key
func ParseRSAPrivateKey(rsaPrivateKeyLocation string) (*rsa.PrivateKey, error) {
	priv, err := ioutil.ReadFile(rsaPrivateKeyLocation)
	if err != nil {
		return nil, err
	}

	return ReadPrivateKey(priv)
}

// ReadPublicKey reads a byte array and returns a pointer to a PublicKey
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

// ParseRSAPrivateKey takes a file path and reads the public key
func ParseRSAPublicKey(rsaPublicKeyLocation string) (*rsa.PublicKey, error) {
	pub, err := ioutil.ReadFile(rsaPublicKeyLocation)
	if err != nil {
		return nil, err
	}

	return ReadPublicKey(pub)
}

// Sign string returns the base64 encoded signature of a string signed by a PrivateKey
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

// Digest returns a string representing the base64 encoded hashSum of a byte array
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

// Check validates the signature given a message and public key string
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

// Verify the Signature header for a request is valid.
// The request body should be provided separately.
// The fetchPublicKeyString function takes a keyname and returns a public key.
// Returns keyname if known, and/or error.
func VerifyRequest(req *http.Request, content []byte, fetchPublicKeyString func(string) (string, error)) (string, error) {
	sighdr := req.Header.Get("Signature")
	if sighdr == "" {
		return "", fmt.Errorf("no signature header")
	}

	var re_sighdrval = regexp.MustCompile(`(.*)="(.*)"`)

	var keyname, algo, heads, sig string
	for _, v := range strings.Split(sighdr, ",") {
		m := re_sighdrval.FindStringSubmatch(v)
		if len(m) != 3 {
			return keyname, fmt.Errorf("bad scan: %s from %s", v, sighdr)
		}
		switch m[1] {
		case "keyId":
			keyname = m[2]
		case "algorithm":
			algo = m[2]
		case "headers":
			heads = m[2]
		case "signature":
			sig = m[2]
		default:
			return keyname, fmt.Errorf("bad sig val: %s", m[1])
		}
	}
	if keyname == "" || algo == "" || heads == "" || sig == "" {
		return keyname, fmt.Errorf("missing a sig value")
	}

	required := make(map[string]bool)
	required["(request-target)"] = true
	required["host"] = true
	required["digest"] = true
	required["date"] = true
	headers := strings.Split(heads, " ")
	var stuff []string
	for _, h := range headers {
		var s string
		switch h {
		case "(request-target)":
			s = strings.ToLower(req.Method) + " " + req.URL.RequestURI()
		case "host":
			s = req.Host
			if s == "" {
				return keyname, fmt.Errorf("warning: no host header value")
			}
		case "digest":
			s = req.Header.Get(h)
			digest, err := Digest(content)
			if err != nil {
				return keyname, err
			}
			expv := "SHA-256=" + digest
			if s != expv {
				return keyname, fmt.Errorf("digest header '%s' did not match content", s)
			}
		case "date":
			s = req.Header.Get(h)
			d, err := time.Parse(http.TimeFormat, s)
			if err != nil {
				return keyname, fmt.Errorf("error parsing date header: %s", err)
			}
			now := time.Now()
			if d.Before(now.Add(-30*time.Minute)) || d.After(now.Add(30*time.Minute)) {
				return keyname, fmt.Errorf("date header '%s' out of range", s)
			}
		default:
			s = req.Header.Get(h)
		}
		delete(required, h)
		stuff = append(stuff, h+": "+s)
	}
	if len(required) > 0 {
		var missing []string
		for h := range required {
			missing = append(missing, h)
		}
		return keyname, fmt.Errorf("required httpsig headers missing (%s)", strings.Join(missing, ","))
	}

	msg := strings.Join(stuff, "\n")
	publicKeyString, err := fetchPublicKeyString(keyname)
	if err != nil {
		return keyname, err
	}

	err = Check(msg, sig, publicKeyString)
	if err != nil {
		return keyname, err
	}
	return keyname, nil
}
