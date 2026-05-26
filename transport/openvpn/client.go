package openvpn

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/tls"
)

const (
	DefaultHandshakeTimeout = 30 * time.Second
	ControlRetransmitDelay  = time.Second
)

type Client struct {
	config *ClientConfig
	mux    *PacketMux

	control *ControlChannel
	tlsConn *tls.Conn
	tlsBuf  []byte
	data    *DataChannel
	push    *PushReply

	cancel context.CancelFunc
}

func NewClient(config *ClientConfig, io PacketIO) (*Client, error) {
	if config == nil {
		return nil, errors.New("nil openvpn client config")
	}
	if io == nil {
		return nil, errors.New("nil openvpn packet io")
	}
	var wrapper ControlPacketWrapper
	var err error
	if len(config.TLSAuthKey) > 0 {
		wrapper, err = NewTLSAuth(config.TLSAuthKey, config.Auth, config.KeyDirection)
	} else if len(config.TLSCryptKey) > 0 {
		wrapper, err = NewTLSCrypt(config.TLSCryptKey, true)
	}
	if err != nil {
		return nil, err
	}
	local, err := NewSessionID()
	if err != nil {
		return nil, err
	}
	runCtx, cancel := context.WithCancel(context.Background())
	mux := NewPacketMux(io)
	go mux.Run(runCtx)
	return &Client{
		config:  config,
		mux:     mux,
		control: NewControlChannel(mux, wrapper, local),
		cancel:  cancel,
	}, nil
}

func (c *Client) Handshake(ctx context.Context) (*PushReply, error) {
	if c == nil {
		return nil, errors.New("nil openvpn client")
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultHandshakeTimeout)
		defer cancel()
	}
	if err := c.control.SendReset(ctx); err != nil {
		return nil, fmt.Errorf("send hard reset: %w", err)
	}
	if err := c.waitServerReset(ctx); err != nil {
		return nil, err
	}

	tlsConfig, err := c.tlsConfig()
	if err != nil {
		return nil, err
	}
	controlConn := NewControlConn(c.control)
	c.tlsConn = tls.Client(controlConn, tlsConfig)
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.tlsConn.SetDeadline(deadline)
	}
	if err := c.tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("openvpn tls handshake: %w", err)
	}

	compression := c.config.CompressionMode()
	controlKeyMode := "tls-crypt"
	if len(c.config.TLSAuthKey) > 0 {
		controlKeyMode = "tls-auth"
	}
	clientOptions := InstallScriptOptionsString(c.config.Proto, c.config.Cipher, c.config.Auth, c.config.KeyDirection, controlKeyMode, compression)
	clientPeerInfo := InstallScriptPeerInfo(c.config.Proto, c.config.Cipher, compression)
	log.Debugln("[OpenVPN] key-method options=%q peer-info=%q", clientOptions, clientPeerInfo)
	clientRecord, err := NewClientKeyMethod2Record(
		clientOptions,
		clientPeerInfo,
		strings.TrimSpace(c.config.Username),
		c.config.Password,
	)
	if err != nil {
		return nil, err
	}
	clientBytes, err := clientRecord.MarshalClient()
	if err != nil {
		return nil, err
	}
	if _, err := c.tlsConn.Write(clientBytes); err != nil {
		return nil, fmt.Errorf("write key method 2 client record: %w", err)
	}
	serverRecord, err := c.readServerKeyMethod(ctx)
	if err != nil {
		return nil, err
	}

	if _, err := c.tlsConn.Write([]byte(PushRequest + "\x00")); err != nil {
		return nil, fmt.Errorf("write push request: %w", err)
	}
	push, err := c.readPushReply(ctx)
	if err != nil {
		return nil, err
	}
	log.Debugln("[OpenVPN] push reply: peer-id=%d tls-ekm=%t raw=%q", push.PeerID, push.TLSEKM, push.Raw)
	if push.Compression != "" {
		compression = push.Compression
	}
	log.Debugln("[OpenVPN] negotiated compression=%q", compression)
	keys, err := c.deriveDataChannelKeys(clientRecord, serverRecord, push)
	if err != nil {
		return nil, err
	}
	c.push = push
	c.data, err = NewDataChannelWithCompression(keys, c.config.Cipher, c.config.Auth, push.PeerID, compression)
	if err != nil {
		return nil, err
	}
	return push, nil
}

func (c *Client) WriteIPPacket(ctx context.Context, packet []byte) error {
	if c.data == nil {
		return errors.New("openvpn data channel is not ready")
	}
	log.Debugln("[OpenVPN] send IP packet len=%d", len(packet))
	encrypted, err := c.data.Encrypt(packet)
	if err != nil {
		return err
	}
	log.Debugln("[OpenVPN] send data packet len=%d", len(encrypted))
	return c.mux.WritePacket(ctx, encrypted)
}

func (c *Client) ReadIPPacket(ctx context.Context) ([]byte, error) {
	if c.data == nil {
		return nil, errors.New("openvpn data channel is not ready")
	}
	for {
		packet, err := c.mux.ReadDataPacket(ctx)
		if err != nil {
			return nil, err
		}
		plain, err := c.data.Decrypt(packet)
		if err != nil {
			if len(packet) > 0 {
				opcode, keyID := parseOpcodeKeyID(packet[0])
				log.Debugln("[OpenVPN] drop data packet opcode=%s key-id=%d len=%d: %v", opcode, keyID, len(packet), err)
			} else {
				log.Debugln("[OpenVPN] drop empty data packet: %v", err)
			}
			continue
		}
		log.Debugln("[OpenVPN] recv IP packet len=%d", len(plain))
		return plain, nil
	}
}

func (c *Client) Close() error {
	if c.cancel != nil {
		c.cancel()
	}
	if c.tlsConn != nil {
		_ = c.tlsConn.Close()
	}
	if c.mux != nil {
		return c.mux.Close()
	}
	return nil
}

func (c *Client) deriveDataChannelKeys(clientRecord, serverRecord *KeyMethod2Record, push *PushReply) (*KeyMaterial, error) {
	cipherKeyLen := c.config.DataCipherKeyLength()
	if push != nil && push.TLSEKM {
		log.Debugln("[OpenVPN] deriving data channel keys via TLS exporter")
		state := c.tlsConn.ConnectionState()
		exported, err := state.ExportKeyingMaterial(exportKeyDataLabel, nil, exportedKeyMaterialSize)
		if err != nil {
			return nil, fmt.Errorf("export tls keying material: %w", err)
		}
		keys, err := DeriveClientKeyMaterialExported(exported, cipherKeyLen)
		if err != nil {
			return nil, fmt.Errorf("derive exported data channel keys: %w", err)
		}
		return keys, nil
	}

	log.Debugln("[OpenVPN] deriving data channel keys via control handshake material")
	sources := clientRecord.Sources
	sources.Server = serverRecord.Sources.Server
	keys, err := DeriveClientKeyMaterial(sources, c.control.LocalSessionID(), c.control.RemoteSessionID(), cipherKeyLen)
	if err != nil {
		return nil, fmt.Errorf("derive data channel keys: %w", err)
	}
	return keys, nil
}

func (c *Client) waitServerReset(ctx context.Context) error {
	retransmits := 0
	for {
		readCtx := ctx
		cancel := func() {}
		if c.config.Proto == ProtoUDP {
			readCtx, cancel = context.WithTimeout(ctx, ControlRetransmitDelay)
		}
		packet, err := c.control.Read(readCtx)
		cancel()
		if err != nil {
			if c.config.Proto == ProtoUDP && errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
				if err := c.control.RetransmitPending(ctx); err != nil {
					return fmt.Errorf("retransmit hard reset: %w", err)
				}
				retransmits++
				continue
			}
			return fmt.Errorf("read hard reset response after %d retransmits: %w", retransmits, err)
		}
		switch packet.Opcode {
		case PControlHardResetServerV2:
			return c.control.SendAck(ctx)
		case PControlHardResetServerV1:
			return fmt.Errorf("openvpn server replied with unsupported key method 1 reset")
		}
	}
}

func (c *Client) readServerKeyMethod(ctx context.Context) (*KeyMethod2Record, error) {
	var buf []byte
	tmp := make([]byte, 4096)
	for {
		if deadline, ok := ctx.Deadline(); ok {
			_ = c.tlsConn.SetReadDeadline(deadline)
		}
		n, err := c.tlsConn.Read(tmp)
		if err != nil {
			return nil, fmt.Errorf("read key method 2 server record: %w", err)
		}
		buf = append(buf, tmp[:n]...)
		record, offset, err := parseServerKeyMethod2Record(buf)
		if err == nil {
			if offset < len(buf) {
				c.tlsBuf = append(c.tlsBuf, buf[offset:]...)
			}
			return record, nil
		}
		if !strings.Contains(err.Error(), "truncated") && !errors.Is(err, ioStringEOF) {
			return nil, err
		}
	}
}

func (c *Client) readPushReply(ctx context.Context) (*PushReply, error) {
	buf := c.tlsBuf
	c.tlsBuf = nil
	tmp := make([]byte, 4096)
	for {
		for {
			idx := bytes.IndexByte(buf, 0)
			if idx < 0 {
				break
			}
			msg := string(buf[:idx])
			buf = buf[idx+1:]
			if strings.TrimSpace(msg) == "" {
				continue
			}
			reply, err := handlePushControlMessage(msg)
			if err != nil {
				return nil, err
			}
			if reply != nil {
				return reply, nil
			}
		}
		if deadline, ok := ctx.Deadline(); ok {
			_ = c.tlsConn.SetReadDeadline(deadline)
		}
		n, err := c.tlsConn.Read(tmp)
		if err != nil {
			if errors.Is(err, io.EOF) && len(buf) > 0 {
				break
			}
			return nil, fmt.Errorf("read push reply: %w", err)
		}
		buf = append(buf, tmp[:n]...)
	}
	return nil, ctx.Err()
}

func handlePushControlMessage(msg string) (*PushReply, error) {
	msg = strings.TrimRight(msg, "\x00")
	switch {
	case strings.HasPrefix(msg, "PUSH_REPLY"):
		reply, err := ParsePushReply(msg)
		if err != nil {
			return nil, fmt.Errorf("parse push reply %q: %w", msg, err)
		}
		return reply, nil
	case strings.HasPrefix(msg, "AUTH_FAILED"):
		reason := strings.TrimPrefix(msg, "AUTH_FAILED")
		reason = strings.TrimPrefix(reason, ",")
		if reason == "" {
			return nil, fmt.Errorf("openvpn authentication failed: %q", msg)
		}
		return nil, fmt.Errorf("openvpn authentication failed: %s", reason)
	case strings.HasPrefix(msg, "AUTH_PENDING"),
		strings.HasPrefix(msg, "INFO_PRE"),
		strings.HasPrefix(msg, "INFO"),
		strings.HasPrefix(msg, "CR_RESPONSE"):
		return nil, nil
	case strings.HasPrefix(msg, "RESTART"),
		strings.HasPrefix(msg, "HALT"),
		strings.HasPrefix(msg, "EXIT"):
		return nil, fmt.Errorf("openvpn server requested %s", msg)
	default:
		return nil, fmt.Errorf("unexpected openvpn control message while waiting for push reply: %q", msg)
	}
}

func (c *Client) tlsConfig() (*tls.Config, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(c.config.CA) {
		return nil, errors.New("parse openvpn ca certificate")
	}
	verify := func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("openvpn server did not provide certificate")
		}
		intermediates := x509.NewCertPool()
		for _, cert := range cs.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}
		_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		return err
	}
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		VerifyConnection:   verify,
	}
	certPEM := bytes.TrimSpace(c.config.Cert)
	keyPEM := bytes.TrimSpace(c.config.Key)
	if len(certPEM) > 0 && len(keyPEM) > 0 {
		cert, err := tls.X509KeyPair(c.config.Cert, c.config.Key)
		if err != nil {
			return nil, fmt.Errorf("parse client certificate/key: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

var _ net.Conn = (*ControlConn)(nil)
