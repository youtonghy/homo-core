package openvpn

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strings"
)

const (
	TLSAuthPacketIDSize = 4 + 4
)

type TLSAuth struct {
	sendHMACKey []byte
	recvHMACKey []byte
	newHash     func() hash.Hash
	digestSize  int
}

func NewTLSAuth(staticKey []byte, auth string, keyDirection string) (*TLSAuth, error) {
	if len(staticKey) != staticKeySize {
		return nil, fmt.Errorf("invalid tls-auth static key length %d, expected %d", len(staticKey), staticKeySize)
	}
	newHash, digestSize, err := openVPNAuthHash(auth)
	if err != nil {
		return nil, err
	}
	sendSlot, recvSlot, err := openVPNKeyDirectionSlots(keyDirection)
	if err != nil {
		return nil, err
	}
	return &TLSAuth{
		sendHMACKey: cloneBytes(tlsAuthHMACKey(staticKey, sendSlot, digestSize)),
		recvHMACKey: cloneBytes(tlsAuthHMACKey(staticKey, recvSlot, digestSize)),
		newHash:     newHash,
		digestSize:  digestSize,
	}, nil
}

func (a *TLSAuth) Wrap(header []byte, packetID uint32, unixTime uint32, plaintext []byte) ([]byte, error) {
	if len(header) != TLSCryptHeaderSize {
		return nil, fmt.Errorf("invalid tls-auth header length %d, expected %d", len(header), TLSCryptHeaderSize)
	}
	var pid [TLSAuthPacketIDSize]byte
	binary.BigEndian.PutUint32(pid[:4], packetID)
	binary.BigEndian.PutUint32(pid[4:], unixTime)

	tag := a.hmac(a.sendHMACKey, pid[:], header, plaintext)
	out := make([]byte, 0, len(header)+len(tag)+len(pid)+len(plaintext))
	out = append(out, header...)
	out = append(out, tag...)
	out = append(out, pid[:]...)
	out = append(out, plaintext...)
	return out, nil
}

func (a *TLSAuth) Unwrap(packet []byte) (header []byte, packetID uint32, unixTime uint32, plaintext []byte, err error) {
	if len(packet) < TLSCryptHeaderSize+a.digestSize+TLSAuthPacketIDSize {
		return nil, 0, 0, nil, errors.New("tls-auth packet too short")
	}
	header = cloneBytes(packet[:TLSCryptHeaderSize])
	tagEnd := TLSCryptHeaderSize + a.digestSize
	tag := packet[TLSCryptHeaderSize:tagEnd]
	pidEnd := tagEnd + TLSAuthPacketIDSize
	pid := packet[tagEnd:pidEnd]
	plaintext = cloneBytes(packet[pidEnd:])

	tagCheck := a.hmac(a.recvHMACKey, pid, header, plaintext)
	if !hmac.Equal(tag, tagCheck) {
		return nil, 0, 0, nil, errors.New("tls-auth authentication failed")
	}
	packetID = binary.BigEndian.Uint32(pid[:4])
	unixTime = binary.BigEndian.Uint32(pid[4:])
	return header, packetID, unixTime, plaintext, nil
}

func (a *TLSAuth) hmac(key []byte, parts ...[]byte) []byte {
	mac := hmac.New(a.newHash, key)
	for _, part := range parts {
		_, _ = mac.Write(part)
	}
	return mac.Sum(nil)
}

func tlsAuthHMACKey(staticKey []byte, slot int, size int) []byte {
	start := slot*keySlotSize + 64
	return staticKey[start : start+size]
}

func openVPNAuthHash(auth string) (func() hash.Hash, int, error) {
	switch strings.ToUpper(strings.TrimSpace(auth)) {
	case "", AuthSHA256:
		return sha256.New, sha256.Size, nil
	case AuthSHA1:
		return sha1.New, sha1.Size, nil
	default:
		return nil, 0, fmt.Errorf("unsupported openvpn tls-auth digest %q", auth)
	}
}

func openVPNKeyDirectionSlots(direction string) (sendSlot int, recvSlot int, err error) {
	switch strings.TrimSpace(direction) {
	case "":
		return 0, 0, nil
	case "0":
		return 0, 1, nil
	case "1":
		return 1, 0, nil
	default:
		return 0, 0, fmt.Errorf("unsupported openvpn key-direction %q", direction)
	}
}
