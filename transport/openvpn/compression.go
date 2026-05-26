package openvpn

import (
	"errors"
	"fmt"
)

const (
	noCompressByte        = 0xfa
	noCompressByteSwap    = 0xfb
	compAlgV2Indicator    = 0x50
	compAlgV2Uncompressed = 0x00
)

func frameCompression(packet []byte, compression string) ([]byte, error) {
	if len(packet) == 0 {
		return cloneBytes(packet), nil
	}
	switch normalizeCompressionUnchecked(compression) {
	case CompressionNone:
		return cloneBytes(packet), nil
	case CompressionStub:
		out := make([]byte, len(packet)+1)
		out[0] = noCompressByteSwap
		copy(out[1:], packet[1:])
		out[len(out)-1] = packet[0]
		return out, nil
	case CompressionCompLZONo, CompressionCompLZO:
		out := make([]byte, len(packet)+1)
		out[0] = noCompressByte
		copy(out[1:], packet)
		return out, nil
	case CompressionStubV2:
		if packet[0] != compAlgV2Indicator {
			return cloneBytes(packet), nil
		}
		out := make([]byte, len(packet)+2)
		out[0] = compAlgV2Indicator
		out[1] = compAlgV2Uncompressed
		copy(out[2:], packet)
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported openvpn compression %q", compression)
	}
}

func unframeCompression(packet []byte, compression string) ([]byte, error) {
	if len(packet) == 0 {
		return cloneBytes(packet), nil
	}
	switch normalizeCompressionUnchecked(compression) {
	case CompressionNone:
		return cloneBytes(packet), nil
	case CompressionStub:
		if packet[0] != noCompressByteSwap {
			return nil, fmt.Errorf("bad openvpn compression stub header byte: 0x%02x", packet[0])
		}
		if len(packet) < 2 {
			return nil, errors.New("openvpn compression stub packet too short")
		}
		out := make([]byte, len(packet)-1)
		out[0] = packet[len(packet)-1]
		copy(out[1:], packet[1:len(packet)-1])
		return out, nil
	case CompressionCompLZONo:
		if packet[0] != noCompressByte {
			return nil, fmt.Errorf("bad openvpn comp-lzo header byte: 0x%02x", packet[0])
		}
		return cloneBytes(packet[1:]), nil
	case CompressionCompLZO:
		return lzo1xDecompressSafe(packet)
	case CompressionStubV2:
		if packet[0] != compAlgV2Indicator {
			return cloneBytes(packet), nil
		}
		if len(packet) < 2 {
			return nil, errors.New("openvpn compression stub-v2 packet too short")
		}
		if packet[1] != compAlgV2Uncompressed {
			return nil, fmt.Errorf("bad openvpn compression stub-v2 header byte: 0x%02x", packet[1])
		}
		return cloneBytes(packet[2:]), nil
	default:
		return nil, fmt.Errorf("unsupported openvpn compression %q", compression)
	}
}
