package openvpn

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func TestTLSAuthRoundTripBidirectional(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 256)
	client, err := NewTLSAuth(key, AuthSHA256, "")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewTLSAuth(key, AuthSHA256, "")
	if err != nil {
		t.Fatal(err)
	}

	header := []byte{opcodeKeyID(PControlHardResetClientV2, 0), 1, 2, 3, 4, 5, 6, 7, 8}
	plain := []byte{0, 0, 0, 0, 0}
	packet, err := client.Wrap(header, 7, 1234, plain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(packet[:len(header)], header) {
		t.Fatalf("tls-auth packet must keep opcode/session header first")
	}
	gotHeader, packetID, unixTime, gotPlain, err := server.Unwrap(packet)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotHeader, header) || !bytes.Equal(gotPlain, plain) {
		t.Fatalf("unexpected unwrap result header=%x plain=%x", gotHeader, gotPlain)
	}
	if packetID != 7 || unixTime != 1234 {
		t.Fatalf("unexpected packet id/time: %d/%d", packetID, unixTime)
	}
	packet[len(packet)-1] ^= 0xff
	if _, _, _, _, err := server.Unwrap(packet); err == nil {
		t.Fatal("expected authentication failure after tamper")
	}
}

func TestTLSAuthKeyDirection(t *testing.T) {
	key := append(bytes.Repeat([]byte{0x11}, 128), bytes.Repeat([]byte{0x22}, 128)...)
	client, err := NewTLSAuth(key, AuthSHA256, "1")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewTLSAuth(key, AuthSHA256, "0")
	if err != nil {
		t.Fatal(err)
	}

	header := []byte{opcodeKeyID(PControlV1, 0), 1, 1, 1, 1, 1, 1, 1, 1}
	plain := []byte("control")
	packet, err := client.Wrap(header, 9, 5678, plain)
	if err != nil {
		t.Fatal(err)
	}
	tagEnd := len(header) + sha256.Size
	if packetID := binary.BigEndian.Uint32(packet[tagEnd : tagEnd+4]); packetID != 9 {
		t.Fatalf("unexpected packet id in wire packet: %d", packetID)
	}
	if _, _, _, _, err := server.Unwrap(packet); err != nil {
		t.Fatal(err)
	}
}

func TestTLSAuthRoundTripSHA1(t *testing.T) {
	key := bytes.Repeat([]byte{0x24}, 256)
	client, err := NewTLSAuth(key, AuthSHA1, "")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewTLSAuth(key, AuthSHA1, "")
	if err != nil {
		t.Fatal(err)
	}

	header := []byte{opcodeKeyID(PControlV1, 0), 9, 8, 7, 6, 5, 4, 3, 2}
	plain := []byte("control")
	packet, err := client.Wrap(header, 11, 567890, plain)
	if err != nil {
		t.Fatal(err)
	}
	tagEnd := len(header) + sha1.Size
	if got := len(packet); got != len(header)+sha1.Size+TLSAuthPacketIDSize+len(plain) {
		t.Fatalf("unexpected tls-auth sha1 packet length: %d", got)
	}
	if packetID := binary.BigEndian.Uint32(packet[tagEnd : tagEnd+4]); packetID != 11 {
		t.Fatalf("unexpected packet id in wire packet: %d", packetID)
	}
	gotHeader, packetID, unixTime, gotPlain, err := server.Unwrap(packet)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotHeader, header) || !bytes.Equal(gotPlain, plain) {
		t.Fatalf("unexpected unwrap result header=%x plain=%x", gotHeader, gotPlain)
	}
	if packetID != 11 || unixTime != 567890 {
		t.Fatalf("unexpected packet id/time: %d/%d", packetID, unixTime)
	}
}
