//go:build linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 *
 * Portions of this file are adapted from WireGuard/wireguard-go commit
 * ecfc5a8d54462e18e13c72173e2623d16d8e25a0. Only RX GSO splitting and
 * virtio-net header handling needed by CONNECT-IP are retained.
 */

package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/sys/unix"
)

const (
	virtioNetHdrLen = 10  // sizeof(struct virtio_net_hdr), Linux UAPI
	MaxGSOBatch     = 128 // ceil(65535 / minimum supported CONNECT-IP MTU 576)
)

var ErrMalformedGSO = errors.New("malformed TUN virtio GSO packet")

type virtioNetHdr struct {
	flags, gsoType                         uint8
	hdrLen, gsoSize, csumStart, csumOffset uint16
}

func (v *virtioNetHdr) decode(b []byte) error {
	if len(b) < virtioNetHdrLen {
		return io.ErrShortBuffer
	}
	v.flags, v.gsoType = b[0], b[1]
	v.hdrLen, v.gsoSize = binary.LittleEndian.Uint16(b[2:]), binary.LittleEndian.Uint16(b[4:])
	v.csumStart, v.csumOffset = binary.LittleEndian.Uint16(b[6:]), binary.LittleEndian.Uint16(b[8:])
	return nil
}

// ReadBatch reads one TUN record. In VNET_HDR mode it splits TCPv4/TCPv6 GSO
// records into caller-owned buffers with offset bytes reserved at the front.
func (d *Device) ReadBatch(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) < len(bufs) || offset < 0 || offset >= len(bufs[0]) {
		return 0, fmt.Errorf("invalid TUN batch buffers")
	}
	if !d.offload {
		n, err := d.f.Read(bufs[0][offset:])
		if err == nil {
			sizes[0] = n
			return 1, nil
		}
		return 0, err
	}
	n, err := d.f.Read(d.readBuffer[:])
	if err != nil {
		return 0, err
	}
	packets, err := handleVirtioRead(d.readBuffer[:n], bufs, sizes, offset)
	if err != nil {
		return 0, err
	}
	for i := 0; i < packets; i++ {
		if sizes[i] > d.MTU {
			return 0, fmt.Errorf("%w: split packet exceeds configured MTU", ErrMalformedGSO)
		}
	}
	return packets, nil
}

func handleVirtioRead(in []byte, bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) < len(bufs) || offset < 0 {
		return 0, fmt.Errorf("%w: invalid output buffers", ErrMalformedGSO)
	}
	for _, b := range bufs {
		if offset > len(b) {
			return 0, fmt.Errorf("%w: invalid output offset", ErrMalformedGSO)
		}
	}
	var hdr virtioNetHdr
	if err := hdr.decode(in); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrMalformedGSO, err)
	}
	in = in[virtioNetHdrLen:]
	if len(in) == 0 {
		return 0, fmt.Errorf("%w: empty packet", ErrMalformedGSO)
	}
	if hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_NONE {
		if hdr.flags&unix.VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
			if err := gsoNoneChecksum(in, hdr.csumStart, hdr.csumOffset); err != nil {
				return 0, fmt.Errorf("%w: %v", ErrMalformedGSO, err)
			}
		}
		if len(in) > len(bufs[0])-offset {
			return 0, fmt.Errorf("%w: non-GSO packet exceeds MTU", ErrMalformedGSO)
		}
		sizes[0] = copy(bufs[0][offset:], in)
		return 1, nil
	}
	if hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV4 && hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV6 {
		return 0, fmt.Errorf("%w: unsupported GSO type %d", ErrMalformedGSO, hdr.gsoType)
	}
	if hdr.gsoSize == 0 {
		return 0, fmt.Errorf("%w: zero GSO size", ErrMalformedGSO)
	}
	isV6 := in[0]>>4 == 6
	if (!isV6 && hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV4) || (isV6 && hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV6) {
		return 0, fmt.Errorf("%w: IP/GSO type mismatch", ErrMalformedGSO)
	}
	if !isV6 && in[0]>>4 != 4 {
		return 0, fmt.Errorf("%w: invalid IP version", ErrMalformedGSO)
	}
	if !isV6 {
		if len(in) < 20 || int(in[0]&0x0f)*4 != int(hdr.csumStart) {
			return 0, fmt.Errorf("%w: invalid IPv4 header length", ErrMalformedGSO)
		}
	} else if len(in) < 40 || hdr.csumStart < 40 {
		return 0, fmt.Errorf("%w: invalid IPv6 transport offset", ErrMalformedGSO)
	}
	if int(hdr.csumStart)+13 > len(in) {
		return 0, fmt.Errorf("%w: truncated TCP header", ErrMalformedGSO)
	}
	tcpLen := uint16(in[hdr.csumStart+12]>>4) * 4
	if tcpLen < 20 || tcpLen > 60 {
		return 0, fmt.Errorf("%w: invalid TCP header length", ErrMalformedGSO)
	}
	hdr.hdrLen = hdr.csumStart + tcpLen
	if int(hdr.hdrLen) > len(in) || hdr.hdrLen < hdr.csumStart || int(hdr.csumStart+hdr.csumOffset)+2 > len(in) {
		return 0, fmt.Errorf("%w: invalid header offsets", ErrMalformedGSO)
	}
	n, err := gsoSplit(in, hdr, bufs, sizes, offset, isV6)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrMalformedGSO, err)
	}
	return n, nil
}

func gsoSplit(in []byte, hdr virtioNetHdr, out [][]byte, sizes []int, offset int, isV6 bool) (int, error) {
	ipLen, addrAt, addrLen := int(hdr.csumStart), 12, 4
	if isV6 {
		addrAt, addrLen = 8, 16
	} else if ipLen < 20 || len(in) < 12 {
		return 0, errors.New("invalid IPv4 header")
	}
	csumAt := int(hdr.csumStart + hdr.csumOffset)
	in[csumAt], in[csumAt+1] = 0, 0
	if !isV6 {
		in[10], in[11] = 0, 0
	}
	seq := binary.BigEndian.Uint32(in[hdr.csumStart+4:])
	start, count := int(hdr.hdrLen), 0
	for start < len(in) {
		if count == len(out) {
			return 0, errors.New("too many GSO segments")
		}
		end := start + int(hdr.gsoSize)
		if end > len(in) {
			end = len(in)
		}
		total := int(hdr.hdrLen) + end - start
		if total > len(out[count])-offset {
			return 0, errors.New("GSO segment exceeds MTU")
		}
		p := out[count][offset : offset+total]
		copy(p[:ipLen], in[:ipLen])
		copy(p[hdr.csumStart:hdr.hdrLen], in[hdr.csumStart:hdr.hdrLen])
		copy(p[hdr.hdrLen:], in[start:end])
		if isV6 {
			binary.BigEndian.PutUint16(p[4:], uint16(total-ipLen))
		} else {
			if count > 0 {
				binary.BigEndian.PutUint16(p[4:], binary.BigEndian.Uint16(p[4:])+uint16(count))
			}
			binary.BigEndian.PutUint16(p[2:], uint16(total))
			binary.BigEndian.PutUint16(p[10:], ^checksum(p[:ipLen], 0))
		}
		binary.BigEndian.PutUint32(p[hdr.csumStart+4:], seq+uint32(hdr.gsoSize)*uint32(count))
		if end != len(in) {
			p[hdr.csumStart+13] &^= 0x09
		}
		length := uint16(total - ipLen)
		pseudo := pseudoChecksum(unix.IPPROTO_TCP, in[addrAt:addrAt+addrLen], in[addrAt+addrLen:addrAt+addrLen*2], length)
		binary.BigEndian.PutUint16(p[csumAt:], ^checksum(p[hdr.csumStart:], pseudo))
		sizes[count] = total
		count++
		start = end
	}
	return count, nil
}

func gsoNoneChecksum(p []byte, start, off uint16) error {
	at := int(start + off)
	if at+2 > len(p) || int(start) > len(p) {
		return io.ErrUnexpectedEOF
	}
	initial := binary.BigEndian.Uint16(p[at:])
	p[at], p[at+1] = 0, 0
	binary.BigEndian.PutUint16(p[at:], ^checksum(p[start:], uint64(initial)))
	return nil
}
func checksum(p []byte, initial uint64) uint16 {
	sum := initial
	for len(p) >= 2 {
		sum += uint64(binary.BigEndian.Uint16(p))
		p = p[2:]
	}
	if len(p) == 1 {
		sum += uint64(p[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum)
}
func pseudoChecksum(proto uint8, src, dst []byte, length uint16) uint64 {
	sum := uint64(proto) + uint64(length)
	for _, b := range [][]byte{src, dst} {
		for len(b) >= 2 {
			sum += uint64(binary.BigEndian.Uint16(b))
			b = b[2:]
		}
	}
	return sum
}
