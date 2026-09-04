//go:build linux

package tunnel

// This is the TCP-only TX half of WireGuard-go's Linux GRO path. It is kept
// deliberately per-call and ordered: CONNECT-IP sessions never share a GRO
// table, and the caller owns the packets until WriteBatch returns.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/sys/unix"
)

const MaxTXGROBatch = 32
const tcpFlagPSH = 0x08

type tcpGROMeta struct {
	ipLen, tcpLen int
	seq           uint32
	payload       int
	psh           bool
	v6            bool
	src, dst      [16]byte
	sport, dport  uint16
	ack           uint32
}

func tcpGROMetaFor(p []byte) (tcpGROMeta, bool) {
	var m tcpGROMeta
	if len(p) < 20 {
		return m, false
	}
	m.v6 = p[0]>>4 == 6
	if !m.v6 {
		m.ipLen = int(p[0]&15) * 4
		if m.ipLen < 20 || m.ipLen > len(p) || binary.BigEndian.Uint16(p[2:]) != uint16(len(p)) || p[9] != unix.IPPROTO_TCP || p[6]&0x3f != 0 {
			return m, false
		}
		copy(m.src[:4], p[12:16])
		copy(m.dst[:4], p[16:20])
	} else {
		m.ipLen = 40
		if len(p) < 40 || binary.BigEndian.Uint16(p[4:]) != uint16(len(p)-40) || p[6] != unix.IPPROTO_TCP {
			return m, false
		}
		copy(m.src[:], p[8:24])
		copy(m.dst[:], p[24:40])
	}
	if len(p) < m.ipLen+20 {
		return m, false
	}
	m.tcpLen = int(p[m.ipLen+12]>>4) * 4
	if m.tcpLen < 20 || m.tcpLen > 60 || len(p) < m.ipLen+m.tcpLen {
		return m, false
	}
	flags := p[m.ipLen+13]
	if flags != 0x10 && flags != 0x18 {
		return m, false
	}
	m.psh = flags&8 != 0
	m.payload = len(p) - m.ipLen - m.tcpLen
	if m.payload == 0 || !validTCPChecksum(p, m) {
		return m, false
	}
	m.sport = binary.BigEndian.Uint16(p[m.ipLen:])
	m.dport = binary.BigEndian.Uint16(p[m.ipLen+2:])
	m.seq = binary.BigEndian.Uint32(p[m.ipLen+4:])
	m.ack = binary.BigEndian.Uint32(p[m.ipLen+8:])
	return m, true
}

func validTCPChecksum(p []byte, m tcpGROMeta) bool {
	addrLen := 4
	addrAt := 12
	if m.v6 {
		addrLen = 16
		addrAt = 8
	}
	return ^checksum(p[m.ipLen:], pseudoChecksum(unix.IPPROTO_TCP, p[addrAt:addrAt+addrLen], p[addrAt+addrLen:addrAt+2*addrLen], uint16(len(p)-m.ipLen))) == 0
}

func tcpCanAppend(a, b tcpGROMeta, pa, pb []byte) bool {
	if a.v6 != b.v6 || a.src != b.src || a.dst != b.dst || a.sport != b.sport || a.dport != b.dport || a.ack != b.ack || a.ipLen != b.ipLen || a.tcpLen != b.tcpLen || a.psh || !ipHeadersCompatible(pa, pb) {
		return false
	}
	if a.tcpLen > 20 && !bytes.Equal(pa[a.ipLen+20:a.ipLen+a.tcpLen], pb[b.ipLen+20:b.ipLen+b.tcpLen]) {
		return false
	}
	return b.seq == a.seq+uint32(a.payload)
}

func ipHeadersCompatible(a, b []byte) bool {
	if a[0]>>4 == 6 {
		return a[0] == b[0] && a[1]>>4 == b[1]>>4 && a[7] == b[7]
	}
	return a[1] == b[1] && a[6]>>5 == b[6]>>5 && a[8] == b[8]
}

func (d *Device) WriteBatch(packets [][]byte) (int, error) {
	if !d.txGRO || len(packets) < 2 {
		total := 0
		for _, p := range packets {
			n, err := d.Write(p)
			if err != nil {
				return total, err
			}
			total += n
		}
		return total, nil
	}
	if d.txGROBuf == nil {
		d.txGROBuf = make([]byte, virtioNetHdrLen+65535)
	}
	written := 0
	for i := 0; i < len(packets); {
		m, ok := tcpGROMetaFor(packets[i])
		if !ok {
			n, err := d.Write(packets[i])
			if err != nil {
				return written, err
			}
			written += n
			i++
			continue
		}
		j := i + 1
		total := len(packets[i])
		for j < len(packets) && j-i < MaxTXGROBatch {
			n, good := tcpGROMetaFor(packets[j])
			if !good || !tcpCanAppend(m, n, packets[i], packets[j]) {
				break
			}
			if total+len(packets[j])-m.ipLen-m.tcpLen > 65535-virtioNetHdrLen {
				break
			}
			total += len(packets[j]) - m.ipLen - m.tcpLen
			m.payload += n.payload
			j++
		}
		if j-i < 2 {
			n, err := d.Write(packets[i])
			if err != nil {
				return written, err
			}
			written += n
			i++
			continue
		}
		super := d.txGROBuf[virtioNetHdrLen : virtioNetHdrLen+total]
		copy(super, packets[i][:m.ipLen+m.tcpLen])
		pos := m.ipLen + m.tcpLen
		for k := i; k < j; k++ {
			mm, _ := tcpGROMetaFor(packets[k])
			copy(super[pos:], packets[k][mm.ipLen+mm.tcpLen:])
			pos += mm.payload
		}
		if last, _ := tcpGROMetaFor(packets[j-1]); last.psh {
			super[m.ipLen+13] |= tcpFlagPSH
		}
		if m.v6 {
			binary.BigEndian.PutUint16(super[4:], uint16(total-m.ipLen))
		} else {
			binary.BigEndian.PutUint16(super[2:], uint16(total))
			binary.BigEndian.PutUint16(super[10:], ^checksum(super[:m.ipLen], 0))
		}
		binary.LittleEndian.PutUint16(d.txGROBuf[2:], uint16(m.ipLen+m.tcpLen))
		binary.LittleEndian.PutUint16(d.txGROBuf[4:], uint16(m.payload))
		binary.LittleEndian.PutUint16(d.txGROBuf[6:], uint16(m.ipLen))
		binary.LittleEndian.PutUint16(d.txGROBuf[8:], 16)
		d.txGROBuf[0] = unix.VIRTIO_NET_HDR_F_NEEDS_CSUM
		if m.v6 {
			d.txGROBuf[1] = unix.VIRTIO_NET_HDR_GSO_TCPV6
		} else {
			d.txGROBuf[1] = unix.VIRTIO_NET_HDR_GSO_TCPV4
		}
		addrLen, addrAt := 4, 12
		if m.v6 {
			addrLen, addrAt = 16, 8
		}
		binary.BigEndian.PutUint16(super[m.ipLen+16:], uint16(pseudoChecksum(unix.IPPROTO_TCP, super[addrAt:addrAt+addrLen], super[addrAt+addrLen:addrAt+2*addrLen], uint16(total-m.ipLen))))
		n, err := d.writev(d.txGROBuf[:virtioNetHdrLen], super)
		if err != nil {
			return written, err
		}
		written += n
		i = j
	}
	return written, nil
}

func (d *Device) writev(header, payload []byte) (int, error) {
	raw, err := d.f.SyscallConn()
	if err != nil {
		return 0, err
	}
	n := 0
	err = raw.Write(func(fd uintptr) bool {
		n, err = unix.Writev(int(fd), [][]byte{header, payload})
		return !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK)
	})
	if err != nil {
		return 0, err
	}
	if n != len(header)+len(payload) {
		return 0, io.ErrShortWrite
	}
	return len(payload), nil
}
