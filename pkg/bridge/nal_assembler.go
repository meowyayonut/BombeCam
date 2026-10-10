package bridge

// nalAssembler rebuilds H.264 NAL units from the camera's video RTP payloads.
//
// The byte transform matches the WS03's packetization (verified against real
// cameras): fragmentation units use the HEVC-style
// FU header (type 49); the start fragment is rebuilt as an H.264 slice header
// (0x65 for IDR fragment types 19/20/18, otherwise 0x41) followed by payload
// byte 1 and the fragment data; every other payload is a complete NAL unit.
// TestNALAssembler_MatchesLegacyAnnexB pins this equivalence.
type nalAssembler struct {
	cur    []byte
	inFU   bool
	onNALU func(nalu []byte)
}

func newNALAssembler(onNALU func(nalu []byte)) *nalAssembler {
	return &nalAssembler{onNALU: onNALU}
}

// Push consumes one RTP payload (RTP header and extensions already stripped).
func (a *nalAssembler) Push(p []byte) {
	if len(p) == 0 {
		return
	}
	nalType := (p[0] >> 1) & 0x3f
	if nalType == 49 && len(p) >= 3 {
		start := (p[2]>>7)&1 == 1
		end := (p[2]>>6)&1 == 1
		fuType := p[2] & 0x3f
		if start {
			a.Flush()
			var sliceHdr [16]byte
			n := copy(sliceHdr[:], []byte{p[1]})
			if len(p) > 3 {
				copy(sliceHdr[n:], p[3:])
			}
			nalHdr := inferSliceNALHeader(fuType, sliceHdr[:])
			a.cur = make([]byte, 0, 2+len(p[3:])+4096)
			a.cur = append(a.cur, nalHdr, p[1])
			a.cur = append(a.cur, p[3:]...)
			a.inFU = true
		} else if a.inFU {
			a.cur = append(a.cur, p[3:]...)
		} else {
			// continuation without a start fragment (start packet lost): drop
			return
		}
		if end {
			a.Flush()
		}
		return
	}
	// Single NAL unit (SPS, PPS, SEI, small slices)
	a.Flush()
	nal := make([]byte, len(p))
	copy(nal, p)
	a.onNALU(nal)
}

// Flush emits any partially assembled NAL unit.
func (a *nalAssembler) Flush() {
	if a.inFU && len(a.cur) > 0 {
		a.onNALU(a.cur)
	}
	a.cur = nil
	a.inFU = false
}

// h264NALType returns the H.264 nal_unit_type of a NAL unit.
func h264NALType(nalu []byte) byte {
	if len(nalu) == 0 {
		return 0
	}
	return nalu[0] & 0x1f
}

// inferSliceNALHeader determines the H.264 NAL header byte (0x65 for IDR,
// 0x41 for non-IDR slice) from fuType and slice header data.
func inferSliceNALHeader(fuType byte, sliceData []byte) byte {
	if fuType == 5 || fuType == 18 || fuType == 19 || fuType == 20 {
		return 0x65
	}
	if isISlice(sliceData) {
		return 0x65
	}
	return 0x41
}

// isISlice parses first_mb_in_slice (ue) and slice_type (ue) from the slice header.
// Returns true if slice_type is an I-slice (slice_type % 5 == 2).
func isISlice(data []byte) bool {
	bitOff := 0
	_, ok := readUE(data, &bitOff)
	if !ok {
		return false
	}
	sliceType, ok := readUE(data, &bitOff)
	if !ok {
		return false
	}
	return (sliceType % 5) == 2
}

func readUE(data []byte, bitOff *int) (uint32, bool) {
	leadingZeros := 0
	for {
		byteIdx := *bitOff / 8
		bitIdx := 7 - (*bitOff % 8)
		if byteIdx >= len(data) {
			return 0, false
		}
		(*bitOff)++
		bit := (data[byteIdx] >> bitIdx) & 1
		if bit == 1 {
			break
		}
		leadingZeros++
		if leadingZeros > 31 {
			return 0, false
		}
	}
	if leadingZeros == 0 {
		return 0, true
	}
	var val uint32
	for i := 0; i < leadingZeros; i++ {
		byteIdx := *bitOff / 8
		bitIdx := 7 - (*bitOff % 8)
		if byteIdx >= len(data) {
			return 0, false
		}
		(*bitOff)++
		bit := uint32((data[byteIdx] >> bitIdx) & 1)
		val = (val << 1) | bit
	}
	return (1 << leadingZeros) - 1 + val, true
}

