package openvpn

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestKeyMethod2ClientMarshalAndDerive(t *testing.T) {
	record := &KeyMethod2Record{
		Options:  InstallScriptOptionsString(ProtoUDP, CipherAES128GCM, AuthSHA256, "", "tls-crypt", CompressionNone),
		PeerInfo: InstallScriptPeerInfo(ProtoUDP, CipherAES128GCM, CompressionNone),
	}
	for i := range record.Sources.Client.PreMaster {
		record.Sources.Client.PreMaster[i] = byte(i + 1)
	}
	for i := range record.Sources.Client.Random1 {
		record.Sources.Client.Random1[i] = byte(i + 2)
		record.Sources.Client.Random2[i] = byte(i + 3)
		record.Sources.Server.Random1[i] = byte(i + 4)
		record.Sources.Server.Random2[i] = byte(i + 5)
	}

	encoded, err := record.MarshalClient()
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(encoded[:4]) != 0 || encoded[4] != KeyMethod2 {
		t.Fatalf("unexpected key method prefix: %x", encoded[:5])
	}
	if !bytes.Contains(encoded, []byte(record.Options)) {
		t.Fatalf("encoded record is missing options")
	}

	var clientID, serverID SessionID
	copy(clientID[:], []byte("client01"))
	copy(serverID[:], []byte("server01"))
	keys, err := DeriveClientKeyMaterial(record.Sources, clientID, serverID, 16)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.SendCipherKey) != 16 || len(keys.RecvCipherKey) != 16 {
		t.Fatalf("unexpected cipher key lengths: %d/%d", len(keys.SendCipherKey), len(keys.RecvCipherKey))
	}
	if len(keys.SendHMACKey) != maxHMACKeyLength || len(keys.RecvHMACKey) != maxHMACKeyLength {
		t.Fatalf("unexpected hmac key lengths: %d/%d", len(keys.SendHMACKey), len(keys.RecvHMACKey))
	}
	if bytes.Equal(keys.SendCipherKey, keys.RecvCipherKey) {
		t.Fatalf("send and recv keys should differ")
	}
}

func TestKeyMethod2DeriveAES256(t *testing.T) {
	record := &KeyMethod2Record{
		Options:  InstallScriptOptionsString(ProtoUDP, CipherAES256GCM, AuthSHA256, "", "tls-crypt", CompressionNone),
		PeerInfo: InstallScriptPeerInfo(ProtoUDP, CipherAES256GCM, CompressionNone),
	}
	for i := range record.Sources.Client.PreMaster {
		record.Sources.Client.PreMaster[i] = byte(i + 1)
	}
	for i := range record.Sources.Client.Random1 {
		record.Sources.Client.Random1[i] = byte(i + 2)
		record.Sources.Client.Random2[i] = byte(i + 3)
		record.Sources.Server.Random1[i] = byte(i + 4)
		record.Sources.Server.Random2[i] = byte(i + 5)
	}
	var clientID, serverID SessionID
	copy(clientID[:], []byte("client01"))
	copy(serverID[:], []byte("server01"))
	keys, err := DeriveClientKeyMaterial(record.Sources, clientID, serverID, 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.SendCipherKey) != 32 || len(keys.RecvCipherKey) != 32 {
		t.Fatalf("unexpected cipher key lengths: %d/%d", len(keys.SendCipherKey), len(keys.RecvCipherKey))
	}
	if len(keys.SendHMACKey) != maxHMACKeyLength || len(keys.RecvHMACKey) != maxHMACKeyLength {
		t.Fatalf("unexpected hmac key lengths: %d/%d", len(keys.SendHMACKey), len(keys.RecvHMACKey))
	}
	if bytes.Equal(keys.SendCipherKey, keys.RecvCipherKey) {
		t.Fatalf("send and recv keys should differ")
	}
}

func TestInstallScriptOptionsCBCSHA1(t *testing.T) {
	options := InstallScriptOptionsString(ProtoTCP, CipherAES256CBC, AuthSHA1, "", "tls-crypt", CompressionNone)
	for _, want := range []string{"proto TCPv4_CLIENT", "cipher AES-256-CBC", "auth SHA1", "keysize 256"} {
		if !bytes.Contains([]byte(options), []byte(want)) {
			t.Fatalf("options missing %q: %s", want, options)
		}
	}
}

func TestInstallScriptCompressionCompatibility(t *testing.T) {
	options := InstallScriptOptionsString(ProtoTCP, CipherAES256GCM, AuthSHA1, "1", "tls-auth", CompressionStub)
	if !bytes.Contains([]byte(options), []byte("link-mtu 1551")) || !bytes.Contains([]byte(options), []byte(",comp-lzo,")) {
		t.Fatalf("compression options missing compatibility fields: %s", options)
	}
	if !bytes.Contains([]byte(options), []byte(",keydir 1,")) || !bytes.Contains([]byte(options), []byte(",tls-auth,")) {
		t.Fatalf("tls-auth options missing compatibility fields: %s", options)
	}
	peerInfo := InstallScriptPeerInfo(ProtoTCP, CipherAES256GCM, CompressionStub)
	for _, want := range []string{
		"IV_VER=2.6.14\n",
		"IV_PLAT=mac\n",
		"IV_NCP=2\n",
		"IV_MTU=1500\n",
		"IV_PROTO=282\n",
		"IV_TCPNL=1\n",
		"IV_LZO_STUB=1\n",
		"IV_COMP_STUB=1\n",
		"IV_COMP_STUBv2=1\n",
	} {
		if !bytes.Contains([]byte(peerInfo), []byte(want)) {
			t.Fatalf("peer info missing %q in %q", want, peerInfo)
		}
	}
}

func TestDeriveClientKeyMaterialExported(t *testing.T) {
	exported := make([]byte, exportedKeyMaterialSize)
	for i := range exported {
		exported[i] = byte(i)
	}
	keys, err := DeriveClientKeyMaterialExported(exported, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keys.SendCipherKey, exported[:32]) {
		t.Fatalf("unexpected send cipher key: %x", keys.SendCipherKey)
	}
	if !bytes.Equal(keys.SendHMACKey, exported[maxCipherKeyLength:maxCipherKeyLength+maxHMACKeyLength]) {
		t.Fatalf("unexpected send hmac key: %x", keys.SendHMACKey)
	}
	if !bytes.Equal(keys.RecvCipherKey, exported[maxCipherKeyLength+maxHMACKeyLength:maxCipherKeyLength+maxHMACKeyLength+32]) {
		t.Fatalf("unexpected recv cipher key: %x", keys.RecvCipherKey)
	}
	if !bytes.Equal(keys.RecvHMACKey, exported[maxCipherKeyLength*2+maxHMACKeyLength:]) {
		t.Fatalf("unexpected recv hmac key: %x", keys.RecvHMACKey)
	}
}

func TestInstallScriptStubV2Compatibility(t *testing.T) {
	options := InstallScriptOptionsString(ProtoUDP, CipherAES128GCM, AuthSHA256, "", "tls-crypt", CompressionStubV2)
	if !bytes.Contains([]byte(options), []byte("link-mtu 1550")) || !bytes.Contains([]byte(options), []byte(",comp-lzo,")) {
		t.Fatalf("stub-v2 options missing compatibility fields: %s", options)
	}
}

func TestParseServerKeyMethod2Record(t *testing.T) {
	var packet []byte
	packet = binary.BigEndian.AppendUint32(packet, 0)
	packet = append(packet, KeyMethod2)
	packet = append(packet, bytes.Repeat([]byte{1}, keySourceRandomSize)...)
	packet = append(packet, bytes.Repeat([]byte{2}, keySourceRandomSize)...)
	packet = appendOpenVPNString(packet, "server-options")
	packet = appendOpenVPNString(packet, "")
	packet = appendOpenVPNString(packet, "")
	packet = appendOpenVPNString(packet, "IV_VER=server\n")

	record, err := ParseServerKeyMethod2Record(packet)
	if err != nil {
		t.Fatal(err)
	}
	if record.Options != "server-options" || record.PeerInfo != "IV_VER=server\n" {
		t.Fatalf("unexpected parsed strings: %#v", record)
	}
	if record.Sources.Server.Random1[0] != 1 || record.Sources.Server.Random2[0] != 2 {
		t.Fatalf("unexpected server randoms")
	}
}

func TestParseServerKeyMethod2RecordRemainderOffset(t *testing.T) {
	var packet []byte
	packet = binary.BigEndian.AppendUint32(packet, 0)
	packet = append(packet, KeyMethod2)
	packet = append(packet, bytes.Repeat([]byte{1}, keySourceRandomSize)...)
	packet = append(packet, bytes.Repeat([]byte{2}, keySourceRandomSize)...)
	packet = appendOpenVPNString(packet, "server-options")
	packet = appendOpenVPNString(packet, "")
	packet = appendOpenVPNString(packet, "")
	packet = appendOpenVPNString(packet, "IV_VER=server\n")
	packet = append(packet, []byte("PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0\x00")...)

	record, offset, err := parseServerKeyMethod2Record(packet)
	if err != nil {
		t.Fatal(err)
	}
	if record.Options != "server-options" {
		t.Fatalf("unexpected options: %q", record.Options)
	}
	if got := string(packet[offset:]); got != "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0\x00" {
		t.Fatalf("unexpected remainder: %q", got)
	}
}
