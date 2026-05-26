package outbound

import (
	"strings"
	"testing"
)

const testOpenVPNCert = `-----BEGIN CERTIFICATE-----
MIIBszCCAVmgAwIBAgIUQbG/Z7JQGg+Jb42bBYK6q8I4g5swCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHbWlob21vMB4XDTI2MDUwMTAwMDAwMFoXDTM2MDQyOTAwMDAw
MFowEjEQMA4GA1UEAwwHbWlob21vMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
hT8O8v9COiL0e7Gmab6r8jYxgB5xIvEtL10eF6QpJm+5ROK8f8yO8JHj2L2F6i1v
g7CNgMCoX9YnZ9wqOqNTMFEwHQYDVR0OBBYEFDuK1nBI7w+Kz8o9hD7UzpJkq1N2
MB8GA1UdIwQYMBaAFDuK1nBI7w+Kz8o9hD7UzpJkq1N2MA8GA1UdEwEB/wQFMAMB
Af8wCgYIKoZIzj0EAwIDSAAwRQIhAJ4mquCRw+W1M7RCNzUVpV9qPzR9qYpK4SAi
6pEh8FeaAiBKv+YbWBjjiWk0Yxch3v7y8W7S7e3pVtHh8x9n9+6w1Q==
-----END CERTIFICATE-----`

func testTLSAuthBlock(fill string) string {
	return `-----BEGIN OpenVPN Static key V1-----
` + strings.Repeat(fill, 256) + `
-----END OpenVPN Static key V1-----`
}

func TestNewOpenVPNNormalizesAuthTLSAlias(t *testing.T) {
	outbound, err := NewOpenVPN(OpenVPNOption{
		Name:         "openvpn-test",
		Server:       "vpn.example.com",
		Port:         1194,
		Proto:        "udp",
		Dev:          "tun",
		Cipher:       "AES-128-GCM",
		Auth:         "SHA1",
		CA:           testOpenVPNCert,
		Username:     "user",
		Password:     "secret",
		AuthTLS:      testTLSAuthBlock("00"),
		KeyDirection: "1",
		Compress:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(outbound.config.TLSAuthKey); got != 256 {
		t.Fatalf("unexpected tls-auth key length: %d", got)
	}
	if outbound.config.KeyDirection != "1" {
		t.Fatalf("unexpected key-direction: %q", outbound.config.KeyDirection)
	}
	if outbound.config.Compression != "stub" {
		t.Fatalf("unexpected compression: %q", outbound.config.Compression)
	}
}

func TestNewOpenVPNRejectsConflictingTLSAuthAliases(t *testing.T) {
	_, err := NewOpenVPN(OpenVPNOption{
		Name:     "openvpn-test",
		Server:   "vpn.example.com",
		Port:     1194,
		Proto:    "udp",
		Dev:      "tun",
		Cipher:   "AES-128-GCM",
		Auth:     "SHA1",
		CA:       testOpenVPNCert,
		Username: "user",
		Password: "secret",
		TLSAuth:  testTLSAuthBlock("00"),
		AuthTLS:  testTLSAuthBlock("11"),
	})
	if err == nil {
		t.Fatal("expected conflicting auth-tls/tls-auth error")
	}
	if !strings.Contains(err.Error(), "auth-tls") || !strings.Contains(err.Error(), "tls-auth") {
		t.Fatalf("unexpected error: %v", err)
	}
}
