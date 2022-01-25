package sigs

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	RSA_PUBLIC_KEY  string = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwDCN9BXesQ7lb7Q05CUY\nfJvhkmyd/B5Xec3ELH/W3UPFGdss0wg+7x8rhEloOFvVZuExjPW1OJNHFGEAC0R4\nz91v2i39ph/uzkp6twk56cioJj+gYC1qog7YWnIO1v3aZOrbgIPiEeAHNtQBLG/Q\n/ePtx3xdqEJ11gOFIVAdBWnYUAtetGUGdpiVd+pfxV7Ygmt3BTojbfDGb57XuX40\nf7f1U8E1YOxwNzmyH6CZQ+VWDtkjEBsVv2YE7l3Mqa8etAal2c9lrM5WUiLjSN7o\noLFWsXR1k6fZ8jwWd/kfoJUutyBrl98YSoMhQTmsT6ExQS2C9Uen/Im4/oyfM7Jj\nKwIDAQAB\n-----END PUBLIC KEY-----"
	RSA_PRIVATE_KEY string = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAwDCN9BXesQ7lb7Q05CUYfJvhkmyd/B5Xec3ELH/W3UPFGdss\n0wg+7x8rhEloOFvVZuExjPW1OJNHFGEAC0R4z91v2i39ph/uzkp6twk56cioJj+g\nYC1qog7YWnIO1v3aZOrbgIPiEeAHNtQBLG/Q/ePtx3xdqEJ11gOFIVAdBWnYUAte\ntGUGdpiVd+pfxV7Ygmt3BTojbfDGb57XuX40f7f1U8E1YOxwNzmyH6CZQ+VWDtkj\nEBsVv2YE7l3Mqa8etAal2c9lrM5WUiLjSN7ooLFWsXR1k6fZ8jwWd/kfoJUutyBr\nl98YSoMhQTmsT6ExQS2C9Uen/Im4/oyfM7JjKwIDAQABAoIBAQCo/8lD0pthPMUa\nZe+AkvImWPiRRnviAFhRnlQcAUpShU5jvyx6Yazdnp4olFhV/sL31Zw55LI3jqKZ\nU/ay8cH+nyzFQV3jX/8hXbLtEurfHfhmsdp32FgFK2KqndNY0B7kUPU13ELGDyao\n2uIxTh4LtAsaOM0usUpnJ+9AbO8oGvUj7B6JI/b36pyMficnzvTFaT95ejeQ8sLL\nrU/coPMGXFEZu9kyPZTdQwgv2oxXjB17cO8KhgqWbK7wPXfEq4LFi/8qU3aX8mpv\nsGxa4PAYh5aGQQo5sVQdFwwb+2V78p1Txpnya/jW+LAYYUEHviN5LTIVsAoITS+C\n/GIY86bhAoGBAOwgNcxK5OW9TFeL616uIl0U5ZbhGPNOliVXFZYqG11wPPRcnqYT\nifVZugbNZPODBKbftug/Kl2wgpIsXk2ublc7qriJbuQAijEf7klzd1e3M0zs5EhW\njNQ3lBe9iN4SGOoNzRwh8rXYDm1l2JOC1bvXXQuL4kzyxLZTBJPZFhjxAoGBANBd\np4xx8D+o7h5J1s3Ij1A8DxLaxt5qjN4Kfm2UBSju9SLC71G4NRtU8PYXzSawJpY2\nRT7bRubZrbIpak8SVoRzRzpD0Oma/YsoW5OfP5BodNw9hsU64u1SX+tYx1x71Qf7\ny5tLIKQ7ZHGcKSHSdlctox+pLTUVGcXlO1KWc93bAoGAeDn6SnfDznoxGc5jXIT7\neDuAnu8j/haAeqi5lAkCf/P7BUz3doYyU1uJTZddFGQchT8ZaW1oC+YoxXaT2ae8\nBOybg3RuoubndhXVBU8mb+IW288ueOqgsBlQbToTK0c5qkq2qeFbLF3DEs6tlIYk\nf40rkgp6gkWGBXOFvCXni3ECgYAT0fTQHT53L8CGzQtLw9ouDah5aKomGgiQTns8\nPSpIfIKA7f4JzfXvRaMuJZF0Lqlc/IiVtBIIf4hQPDRKlTn5m2WZGz5SGlYn2Izt\ne+Z1/BmxoYCiXjmbzYwmPOmp2HWpLsBtYzYVqTiivfIDr5tmK4cqydLtC7bJ5kZA\nUuNupQKBgQCQzyeUkX98+eKdzhFs9f2lb6XQPahAP3LyAacJKNGfCkgPp1VrwF50\ntemiWIs6eSp9EPkBYcVM+PwKCEzZcvgf/IsC1c2CxCn8cVr2Pn6ICMFU+wHxgvXH\nNf+T9tdOh71yJ4OaAw5U/cGy/9qlY/e39QBnFBxti0Ja7UUWo2z73Q==\n-----END RSA PRIVATE KEY-----"
)

// TestReadPublicKey tests that a public key can be read from a byte array
func TestReadPublicKey(t *testing.T) {
	_, err := ReadPublicKey([]byte(RSA_PUBLIC_KEY))
	if err != nil {
		t.Fatal("failed to read public key:", err)
	}
}

// TestReadPrivateKey tests that a private key can be read from a byte array
func TestReadPrivateKey(t *testing.T) {
	_, err := ReadPrivateKey([]byte(RSA_PRIVATE_KEY))
	if err != nil {
		t.Fatal("failed to read private key:", err)
	}
}

// TestDigest tests the resulting digest of a string against an expected result
func TestDigest(t *testing.T) {
	testCase := "What is the digest of this data?"
	expected := "NvTvyw6Fw32PZ8WdFydsJfPuPb5T+6InIFwLM/Gi7qQ="
	result, err := Digest([]byte(testCase))
	if err != nil {
		t.Fatal("failed to create digest:", err)
	}
	if result != expected {
		t.Fatalf("result was %s, expected %s", result, expected)
	}
}

// TestSignString tests the resulting signature of a string against an expected result
func TestSignString(t *testing.T) {
	testCase := "What does this string look like signed?"
	expected := "Tz4EC9sdgFRLStsMh82122/upo7HOIFVn10qm5MmWuCy8iFAoN5/8XwJ8N927xWlBdWuZHh4zVmucHYSP/h0UkvbE5HIE+TtNbNQjg10dp3rhBGj7DCrFkBXY6SMREOSKd+IEwgE/ZryGcjd+ciIv8Lqd2QvlnaI5QTip6nCdh9bkatjvi09jDVw5E1SMnMburlS5ci/xFfpuqC1TtI6T8sjjrFwwafbtB8Xp/ZnFBFtql9Q4fQ90X4v3qUprngWjVyRmjbxRQwR/y5AZDusL39MjQKjzW2djquslLxRV/Asw9lFQFYLp69DBkiWEXzCaSlAPKpdzHBi8/xldT4Lag=="
	key, err := ReadPrivateKey([]byte(RSA_PRIVATE_KEY))
	if err != nil {
		t.Fatal("failed to read private key:", err)
	}
	result, err := SignString(key, testCase)
	if err != nil {
		t.Fatal("failed to sign string:", err)
	}
	if result != expected {
		t.Fatalf("result was %s, expected %s", result, expected)
	}
}

// TestCheck tests that a signature is able to be validated for a message
func TestCheck(t *testing.T) {
	msg := "What does this string look like signed?"
	signature := "Tz4EC9sdgFRLStsMh82122/upo7HOIFVn10qm5MmWuCy8iFAoN5/8XwJ8N927xWlBdWuZHh4zVmucHYSP/h0UkvbE5HIE+TtNbNQjg10dp3rhBGj7DCrFkBXY6SMREOSKd+IEwgE/ZryGcjd+ciIv8Lqd2QvlnaI5QTip6nCdh9bkatjvi09jDVw5E1SMnMburlS5ci/xFfpuqC1TtI6T8sjjrFwwafbtB8Xp/ZnFBFtql9Q4fQ90X4v3qUprngWjVyRmjbxRQwR/y5AZDusL39MjQKjzW2djquslLxRV/Asw9lFQFYLp69DBkiWEXzCaSlAPKpdzHBi8/xldT4Lag=="
	err := Check(msg, signature, RSA_PUBLIC_KEY)
	if err != nil {
		t.Fatal("failed to validate the signature:", err)
	}
}

// TestSignAndVerifyRequest signs and http request and validates it
func TestSignAndVerifyRequest(t *testing.T) {
	keyName := "key-name"
	data := []byte("this is only a test")
	body := bytes.NewBuffer(data)
	request := httptest.NewRequest(http.MethodPost, "/api/endpoint", body)
	request.Header.Add("Host", "example.com")
	request.Header.Add("Content-Type", "application/json")
	err := SignRequest(request, data, RSA_PRIVATE_KEY, keyName)
	if err != nil {
		t.Fatal("failed to sign request:", err)
	}
	result, err := VerifyRequest(request, data, func(s string) (string, error) {
		return RSA_PUBLIC_KEY, nil
	})
	if err != nil {
		t.Fatal("failed to validate request:", err)
	}
	if result != keyName {
		t.Fatal("returned invalid key name:", result)
	}
}
