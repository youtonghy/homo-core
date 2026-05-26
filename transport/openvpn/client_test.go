package openvpn

import "testing"

func TestNewClientSelectsTLSAuthWrapper(t *testing.T) {
	io, _ := newMemoryPacketPair()
	defer io.Close()

	config := &ClientConfig{
		RemoteHost:   "vpn.example.com",
		RemotePort:   1194,
		Proto:        ProtoUDP,
		Dev:          "tun",
		Cipher:       CipherAES128GCM,
		Auth:         AuthSHA1,
		CA:           []byte(testCert),
		Cert:         []byte(testCert),
		Key:          []byte(testKey),
		TLSAuthKey:   testStaticKey(),
		KeyDirection: "",
		Username:     "user",
		Password:     "secret",
	}

	client, err := NewClient(config, io)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if _, ok := client.control.wrapper.(*TLSAuth); !ok {
		t.Fatalf("expected tls-auth wrapper, got %T", client.control.wrapper)
	}
}

func TestNewClientSelectsTLSCryptWrapper(t *testing.T) {
	io, _ := newMemoryPacketPair()
	defer io.Close()

	config := &ClientConfig{
		RemoteHost:  "vpn.example.com",
		RemotePort:  1194,
		Proto:       ProtoUDP,
		Dev:         "tun",
		Cipher:      CipherAES128GCM,
		Auth:        AuthSHA256,
		CA:          []byte(testCert),
		Cert:        []byte(testCert),
		Key:         []byte(testKey),
		TLSCryptKey: testStaticKey(),
		Username:    "user",
		Password:    "secret",
	}

	client, err := NewClient(config, io)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if _, ok := client.control.wrapper.(*TLSCrypt); !ok {
		t.Fatalf("expected tls-crypt wrapper, got %T", client.control.wrapper)
	}
}

func TestHandlePushControlMessage(t *testing.T) {
	if reply, err := handlePushControlMessage("INFO_PRE,waiting"); err != nil || reply != nil {
		t.Fatalf("unexpected info result: reply=%#v err=%v", reply, err)
	}
	if reply, err := handlePushControlMessage("AUTH_PENDING,timeout 10"); err != nil || reply != nil {
		t.Fatalf("unexpected auth-pending result: reply=%#v err=%v", reply, err)
	}
	if _, err := handlePushControlMessage("AUTH_FAILED,bad password"); err == nil {
		t.Fatal("expected auth failure error")
	}
	if _, err := handlePushControlMessage("AUTH_FAILED"); err == nil {
		t.Fatal("expected bare auth failure error")
	}
	reply, err := handlePushControlMessage("PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,peer-id 3")
	if err != nil {
		t.Fatal(err)
	}
	if reply.PeerID != 3 {
		t.Fatalf("unexpected peer id: %d", reply.PeerID)
	}
}
