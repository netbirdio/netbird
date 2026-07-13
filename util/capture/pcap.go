package capture

import (
	"encoding/binary"
	"io"
	"time"
)

const (
	pcapMagic      = 0xa1b2c3d4
	pcapVersionMaj = 2
	pcapVersionMin = 4
	// linkTypeRaw is LINKTYPE_RAW: raw IPv4/IPv6 packets without link-layer header.
	linkTypeRaw    = 101
	defaultSnapLen = 65535
)

// PcapWriter writes packets in pcap format to an underlying writer.
// The global header is written lazily on the first WritePacket call so that
// the writer can be used with unbuffered io.Pipes without deadlocking.
// It is not safe for concurrent use; callers must serialize access.
type PcapWriter struct {
	w             io.Writer
	snapLen       uint32
	headerWritten bool
}

// NewPcapWriter creates a pcap writer. The global header is deferred until the
// first WritePacket call.
func NewPcapWriter(w io.Writer, snapLen uint32) *PcapWriter {
	if snapLen == 0 {
		snapLen = defaultSnapLen
	}
	return &PcapWriter{w: w, snapLen: snapLen}
}

// writeGlobalHeader writes the 24-byte pcap file header.
func (pw *PcapWriter) writeGlobalHeader() error {
	var hdr [24]byte
	binary.LittleEndian.PutUint32(hdr[0:4], pcapMagic)
	binary.LittleEndian.PutUint16(hdr[4:6], pcapVersionMaj)
	binary.LittleEndian.PutUint16(hdr[6:8], pcapVersionMin)
	binary.LittleEndian.PutUint32(hdr[16:20], pw.snapLen)
	binary.LittleEndian.PutUint32(hdr[20:24], linkTypeRaw)

	_, err := pw.w.Write(hdr[:])
	return err
}

// WriteHeader writes the pcap global header. Safe to call multiple times.
func (pw *PcapWriter) WriteHeader() error {
	if pw.headerWritten {
		return nil
	}
	if err := pw.writeGlobalHeader(); err != nil {
		return err
	}
	pw.headerWritten = true
	return nil
}

// WritePacket writes a single packet record, preceded by the global header
// on the first call.
func (pw *PcapWriter) WritePacket(ts time.Time, data []byte) error {
	if err := pw.WriteHeader(); err != nil {
		return err
	}

	origLen := uint32(len(data))
	if origLen > pw.snapLen {
		data = data[:pw.snapLen]
	}

	var hdr [16]byte
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(ts.Unix()))
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(ts.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(data)))
	binary.LittleEndian.PutUint32(hdr[12:16], origLen)

	if _, err := pw.w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := pw.w.Write(data)
	return err
}
