package bridge

import (
	"bytes"
	"math/rand"
	"testing"
)

// legacyAnnexB is the reference per-packet transform (as fed to FFmpeg) for
// the camera-specific depacketization.
func legacyAnnexB(p []byte) []byte {
	startCode := []byte{0x00, 0x00, 0x00, 0x01}
	nalType := (p[0] >> 1) & 0x3f
	var pkt []byte
	if nalType == 49 && len(p) >= 3 {
		s := (p[2] >> 7) & 1
		fuType := p[2] & 0x3f
		if s == 1 {
			var sliceHdr [16]byte
			n := copy(sliceHdr[:], []byte{p[1]})
			if len(p) > 3 {
				copy(sliceHdr[n:], p[3:])
			}
			nalHdr := inferSliceNALHeader(fuType, sliceHdr[:])
			firstByte := p[1]
			pkt = make([]byte, 4+2+len(p[3:]))
			copy(pkt[0:4], startCode)
			pkt[4] = nalHdr
			pkt[5] = firstByte
			copy(pkt[6:], p[3:])
		} else {
			pkt = make([]byte, len(p[3:]))
			copy(pkt, p[3:])
		}
	} else if len(p) > 0 {
		pkt = make([]byte, 4+len(p))
		copy(pkt[0:4], startCode)
		copy(pkt[4:], p)
	}
	return pkt
}

// For well-formed input (every FU starts with a start fragment) the assembler
// must produce byte-for-byte the stream the legacy transform produced.
func TestNALAssembler_MatchesLegacyAnnexB(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	var packets [][]byte
	for i := 0; i < 400; i++ {
		if rng.Intn(3) == 0 {
			// single NAL: SPS/PPS/non-FU slice
			hdr := []byte{0x67, 0x68, 0x06, 0x41}[rng.Intn(4)]
			body := make([]byte, 1+rng.Intn(60))
			rng.Read(body)
			if (hdr>>1)&0x3f == 49 {
				hdr = 0x67
			}
			packets = append(packets, append([]byte{hdr}, body...))
			continue
		}
		frags := 1 + rng.Intn(5)
		fuType := []byte{19, 1, 20, 1}[rng.Intn(4)]
		for f := 0; f < frags; f++ {
			var fu byte = fuType
			if f == 0 {
				fu |= 0x80
			}
			if f == frags-1 {
				fu |= 0x40
			}
			body := make([]byte, 1+rng.Intn(1200))
			rng.Read(body)
			pl := append([]byte{49 << 1, byte(rng.Intn(256)), fu}, body...)
			packets = append(packets, pl)
		}
	}

	var want bytes.Buffer
	for _, p := range packets {
		want.Write(legacyAnnexB(p))
	}
	var got bytes.Buffer
	a := newNALAssembler(func(n []byte) {
		got.Write([]byte{0, 0, 0, 1})
		got.Write(n)
	})
	for _, p := range packets {
		a.Push(p)
	}
	a.Flush()
	if !bytes.Equal(want.Bytes(), got.Bytes()) {
		t.Fatalf("assembler output differs from legacy transform (%d vs %d bytes)", got.Len(), want.Len())
	}
}

func TestNALAssembler_IDRAndOrphanContinuation(t *testing.T) {
	var nals [][]byte
	a := newNALAssembler(func(n []byte) { nals = append(nals, append([]byte(nil), n...)) })
	a.Push([]byte{49 << 1, 0xAA, 0x00 | 1, 1, 2})  // orphan continuation: dropped
	a.Push([]byte{49 << 1, 0xB8, 0x80 | 19, 3, 4}) // IDR start
	a.Push([]byte{49 << 1, 0xB8, 0x40 | 19, 5})    // end
	a.Push([]byte{0x67, 0x42})                     // SPS
	if len(nals) != 2 {
		t.Fatalf("got %d NALs", len(nals))
	}
	if !bytes.Equal(nals[0], []byte{0x65, 0xB8, 3, 4, 5}) || h264NALType(nals[0]) != 5 {
		t.Fatalf("IDR NAL = %x", nals[0])
	}
	if h264NALType(nals[1]) != 7 {
		t.Fatalf("expected SPS, got %x", nals[1])
	}
}

func TestNALAssembler_FUType1_ISliceAndPSlice(t *testing.T) {
	var nals [][]byte
	a := newNALAssembler(func(n []byte) { nals = append(nals, append([]byte(nil), n...)) })

	// I-slice (0xB8 -> first_mb=0, slice_type=2) even with fuType=1 must be tagged IDR (0x65)
	a.Push([]byte{49 << 1, 0xB8, 0x80 | 1, 10, 11})
	a.Push([]byte{49 << 1, 0xB8, 0x40 | 1, 12})
	// P-slice (0xEB -> first_mb=0, slice_type=0) with fuType=1 must be tagged non-IDR (0x41)
	a.Push([]byte{49 << 1, 0xEB, 0x80 | 1, 20, 21})
	a.Push([]byte{49 << 1, 0xEB, 0x40 | 1, 22})

	if len(nals) != 2 {
		t.Fatalf("got %d NALs, want 2", len(nals))
	}
	if nals[0][0] != 0x65 {
		t.Fatalf("expected IDR header 0x65 for I-slice, got 0x%02x", nals[0][0])
	}
	if nals[1][0] != 0x41 {
		t.Fatalf("expected non-IDR header 0x41 for P-slice, got 0x%02x", nals[1][0])
	}
}

