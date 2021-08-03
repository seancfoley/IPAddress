package ipaddr

import (
	"math/big"
)

type IPv6SegInt uint16

const useIPv6SegmentCache = true

type ipv6DivsBlock struct {
	block []*ipv6SegmentValues
}

type ipv6DivsPartition struct {
	block []ipv6DivsBlock
}

var (
	AllRangeValsIPv6 = &ipv6SegmentValues{
		upperValue: IPv6MaxValuePerSegment,
	}
	allPrefixedCacheIPv6 = make([]*ipv4SegmentValues, IPv6BitsPerSegment+1)

	segmentCacheIPv6       = make([]*ipv6DivsBlock, IPv6MaxValuePerSegment+1)
	segmentPrefixCacheIPv6 = make([]*ipv6DivsPartition, IPv6BitsPerSegment+1) // for each prefix, all segment values, 0x100 blocks of size 0x100
	prefixBlocksCacheIPv6  = make([]*ipv6DivsPartition, IPv6BitsPerSegment+1) // for each prefix, all prefix blocks.  ??? For prefix of size 8, one block of size ff.  For prefix of size > 8, a number of blocks of size ff.  For prefix of size < 8, 1 block of size less than ff.
)

/*
//there are 0x10000 (ie 0xffff + 1 or 64k) possible segment values in IPv6.  We break the cache into 0x100 blocks of size 0x100
			private transient IPv6AddressSegment segmentCache[][];

			//we maintain a similar cache for each potential prefixed segment.
			//Note that there are 2 to the n possible values for prefix n
			//We break up that number into blocks of size 0x100
			private transient IPv6AddressSegment segmentPrefixCache[][][];
			private transient IPv6AddressSegment allPrefixedCache[];
*/

//TODO cache like ipv4xxxxx

func newIPv6SegmentVal(value IPv6SegInt) *ipv6SegmentValues {
	return &ipv6SegmentValues{
		value:      value,
		upperValue: value,
	}
}

func newIPv6SegmentPrefixedVal(value IPv6SegInt, prefLen PrefixLen) (result *ipv6SegmentValues) {
	return &ipv6SegmentValues{
		value:      value,
		upperValue: value,
		prefLen:    prefLen,
	}
}

func newIPv6SegmentPrefixedValues(value, upperValue IPv6SegInt, prefLen PrefixLen) *ipv6SegmentValues {
	return &ipv6SegmentValues{
		value:      value,
		upperValue: upperValue,
		prefLen:    prefLen,
	}
}

type ipv6SegmentValues struct {
	value      IPv6SegInt
	upperValue IPv6SegInt
	prefLen    PrefixLen
	cache      divCache
}

func (seg *ipv6SegmentValues) getAddrType() addrType {
	return ipv6Type
}

func (seg *ipv6SegmentValues) includesZero() bool {
	return seg.value == 0
}

func (seg *ipv6SegmentValues) includesMax() bool {
	return seg.upperValue == 0xffff
}

func (seg *ipv6SegmentValues) isMultiple() bool {
	return seg.value != seg.upperValue
}

func (seg *ipv6SegmentValues) getCount() *big.Int {
	return big.NewInt(int64((seg.upperValue - seg.value)) + 1)
}

func (seg *ipv6SegmentValues) getBitCount() BitCount {
	return IPv6BitsPerSegment
}

func (seg *ipv6SegmentValues) getByteCount() int {
	return IPv6BytesPerSegment
}

func (seg *ipv6SegmentValues) getValue() *BigDivInt {
	return big.NewInt(int64(seg.value))
}

func (seg *ipv6SegmentValues) getUpperValue() *BigDivInt {
	return big.NewInt(int64(seg.upperValue))
}

func (seg *ipv6SegmentValues) getDivisionValue() DivInt {
	return DivInt(seg.value)
}

func (seg *ipv6SegmentValues) getUpperDivisionValue() DivInt {
	return DivInt(seg.upperValue)
}

func (seg *ipv6SegmentValues) getDivisionPrefixLength() PrefixLen {
	return seg.prefLen
}

func (seg *ipv6SegmentValues) getSegmentValue() SegInt {
	return SegInt(seg.value)
}

func (seg *ipv6SegmentValues) getUpperSegmentValue() SegInt {
	return SegInt(seg.upperValue)
}

func (seg *ipv6SegmentValues) calcBytesInternal() (bytes, upperBytes []byte) {
	bytes = []byte{byte(seg.value >> 8), byte(seg.value)}
	if seg.isMultiple() {
		upperBytes = []byte{byte(seg.upperValue >> 8), byte(seg.upperValue)}
	} else {
		upperBytes = bytes
	}
	return
}

func (seg *ipv6SegmentValues) deriveNew(val, upperVal DivInt, prefLen PrefixLen) divisionValues {
	return newIPv6SegmentPrefixedValues(IPv6SegInt(val), IPv6SegInt(upperVal), prefLen)
}

func (seg *ipv6SegmentValues) deriveNewSeg(val SegInt, prefLen PrefixLen) divisionValues {
	return newIPv6SegmentPrefixedVal(IPv6SegInt(val), prefLen)
}

func (seg *ipv6SegmentValues) deriveNewMultiSeg(val, upperVal SegInt, prefLen PrefixLen) divisionValues {
	return newIPv6SegmentPrefixedValues(IPv6SegInt(val), IPv6SegInt(upperVal), prefLen)
}

func (seg *ipv6SegmentValues) getCache() *divCache {
	return &seg.cache
}

var _ divisionValues = &ipv6SegmentValues{}

var zeroIPv6Seg = NewIPv6Segment(0)

type IPv6AddressSegment struct {
	ipAddressSegmentInternal
}

func (seg *IPv6AddressSegment) init() *IPv6AddressSegment {
	if seg.divisionValues == nil {
		return zeroIPv6Seg
	}
	return seg
}

// We must override getBitCount, getByteCount and others for the case when we construct as the zero value

func (seg *IPv6AddressSegment) GetBitCount() BitCount {
	return IPv6BitsPerSegment
}

func (seg *IPv6AddressSegment) GetByteCount() int {
	return IPv6BytesPerSegment
}

func (seg *IPv6AddressSegment) GetMaxValue() IPv6SegInt {
	return 0xffff
}

func (seg *IPv6AddressSegment) ToPrefixedNetworkSegment(segmentPrefixLength PrefixLen) *IPv6AddressSegment {
	return seg.toPrefixedNetworkDivision(segmentPrefixLength).ToIPv6AddressSegment()
}

func (seg *IPv6AddressSegment) ToNetworkSegment(segmentPrefixLength PrefixLen) *IPv6AddressSegment {
	return seg.toNetworkDivision(segmentPrefixLength, false).ToIPv6AddressSegment()
}

func (seg *IPv6AddressSegment) ToPrefixedHostSegment(segmentPrefixLength PrefixLen) *IPv6AddressSegment {
	return seg.toPrefixedHostDivision(segmentPrefixLength).ToIPv6AddressSegment()
}

func (seg *IPv6AddressSegment) ToHostSegment(segmentPrefixLength PrefixLen) *IPv6AddressSegment {
	return seg.toHostDivision(segmentPrefixLength, false).ToIPv6AddressSegment()
}

func (seg *IPv6AddressSegment) Iterator() IPv6SegmentIterator {
	return ipv6SegmentIterator{seg.iterator()}
}

func (seg *IPv6AddressSegment) PrefixBlockIterator() IPv6SegmentIterator {
	return ipv6SegmentIterator{seg.prefixBlockIterator()}
}

func (seg *IPv6AddressSegment) PrefixedBlockIterator(segmentPrefixLen BitCount) IPv6SegmentIterator {
	return ipv6SegmentIterator{seg.prefixedBlockIterator(segmentPrefixLen)}
}

func (seg *IPv6AddressSegment) PrefixIterator() IPv6SegmentIterator {
	return ipv6SegmentIterator{seg.prefixIterator()}
}

func (seg *IPv6AddressSegment) WithoutPrefixLen() *IPv6AddressSegment {
	return seg.withoutPrefixLen().ToIPv6AddressSegment()
}

// Converts this IPv6 address segment into smaller segments,
// copying them into the given array starting at the given index.
//
// If a segment does not fit into the array because the segment index in the array is out of bounds of the array,
// then it is not copied.
func (seg *IPv6AddressSegment) visitSplitSegments(target func(index int, div *IPv4AddressSegment), boundaryIndex, index int) {
	if !seg.IsMultiple() {
		bitSizeSplit := BitCount(IPv6BitsPerSegment >> 1)
		myPrefix := seg.GetSegmentPrefixLength()
		highPrefixBits := getSegmentPrefixLength(bitSizeSplit, myPrefix, 0)
		lowPrefixBits := getSegmentPrefixLength(bitSizeSplit, myPrefix, 1)
		if index >= 0 && index < boundaryIndex {
			seg := NewIPv4PrefixSegment(IPv4SegInt(seg.highByte()), highPrefixBits)
			target(index, seg)
		}
		index++
		if index >= 0 && index < boundaryIndex {
			seg := NewIPv4PrefixSegment(IPv4SegInt(seg.lowByte()), lowPrefixBits)
			target(index, seg)
		}
	} else {
		seg.visitSplitSegmentsMultiple(target, boundaryIndex, index)
	}
}

//TODO this should error on certain ranged segments that cannot be split.  Use the same logic as in the parser.

func (seg *IPv6AddressSegment) visitSplitSegmentsMultiple(target func(index int, div *IPv4AddressSegment), boundaryIndex, index int) {
	myPrefix := seg.GetSegmentPrefixLength()
	bitSizeSplit := BitCount(IPv6BitsPerSegment >> 1)
	if index >= 0 && index < boundaryIndex {
		highLower := highByteIpv6(seg.GetSegmentValue())
		highUpper := highByteIpv6(seg.GetUpperSegmentValue())
		highPrefixBits := getSegmentPrefixLength(bitSizeSplit, myPrefix, 0)
		if highLower == highUpper {
			seg := NewIPv4PrefixSegment(IPv4SegInt(highLower), highPrefixBits)
			target(index, seg)
		} else {
			seg := NewIPv4RangePrefixSegment(IPv4SegInt(highLower), IPv4SegInt(highUpper), highPrefixBits)
			target(index, seg)
		}
	}
	index++
	if index >= 0 && index < boundaryIndex {
		lowLower := lowByteIpv6(seg.GetSegmentValue())
		lowUpper := lowByteIpv6(seg.GetUpperSegmentValue())
		lowPrefixBits := getSegmentPrefixLength(bitSizeSplit, myPrefix, 1)
		if lowLower == lowUpper {
			seg := NewIPv4PrefixSegment(IPv4SegInt(lowLower), lowPrefixBits)
			target(index, seg)
		} else {
			seg := NewIPv4RangePrefixSegment(IPv4SegInt(lowLower), IPv4SegInt(lowUpper), lowPrefixBits)
			target(index, seg)
		}
	}
}

func (seg *IPv6AddressSegment) highByte() SegInt {
	return highByteIpv6(seg.GetSegmentValue())
}

func (seg *IPv6AddressSegment) lowByte() SegInt {
	return lowByteIpv6(seg.GetSegmentValue())
}

func highByteIpv6(value SegInt) SegInt {
	return value >> 8
}

func lowByteIpv6(value SegInt) SegInt {
	return value & 0xff
}

// Converts this IPv6 address segment into smaller segments,
// copying them into the given array starting at the given index
//
// If a segment does not fit into the array because the segment index in the array is out of bounds of the array,
// then it is not copied.
func (seg *IPv6AddressSegment) GetSplitSegments(segs []*IPv4AddressSegment, index int) {
	seg.visitSplitSegments(func(index int, div *IPv4AddressSegment) { segs[index] = div }, len(segs), index)
}

func (seg *IPv6AddressSegment) getSplitSegments(segs []*AddressDivision, index int) {
	seg.visitSplitSegments(func(index int, div *IPv4AddressSegment) { segs[index] = div.ToAddressDivision() }, len(segs), index)
}

func (seg *IPv6AddressSegment) ReverseBits(perByte bool) (res *IPv6AddressSegment, err IncompatibleAddressError) {
	if seg.divisionValues == nil {
		res = seg
		return
	}
	if seg.IsMultiple() {
		var addrSeg *AddressSegment
		addrSeg, err = seg.reverseMultiValSeg(perByte)
		res = addrSeg.ToIPv6AddressSegment()
		return
	}
	oldVal := IPv6SegInt(seg.GetSegmentValue())
	val := IPv6SegInt(reverseUint16(uint16(oldVal)))
	if perByte {
		val = ((val & 0xff) << 8) | (val >> 8)
	}
	if oldVal == val && !seg.isPrefixed() {
		res = seg
	} else {
		res = NewIPv6Segment(val)
	}
	return
}

func (seg *IPv6AddressSegment) ReverseBytes() (res *IPv6AddressSegment, err IncompatibleAddressError) {
	if seg.divisionValues == nil {
		res = seg
		return
	}
	if seg.IsMultiple() {
		var addrSeg *AddressSegment
		addrSeg, err = seg.reverseMultiValSeg(false)
		res = addrSeg.ToIPv6AddressSegment()
		return
	}
	oldVal := IPv6SegInt(seg.GetSegmentValue())
	val := IPv6SegInt(reverseUint16(uint16(oldVal)))
	if oldVal == val && !seg.isPrefixed() {
		res = seg
	} else {
		res = NewIPv6Segment(val)
	}
	return
}

func (seg *IPv6AddressSegment) ToAddressSegment() *AddressSegment {
	return seg.ToIPAddressSegment().ToAddressSegment()
}

func (seg *IPv6AddressSegment) ToIPAddressSegment() *IPAddressSegment {
	if seg == nil {
		return nil
	}
	return (*IPAddressSegment)(seg.init())
}

func NewIPv6Segment(val IPv6SegInt) *IPv6AddressSegment {
	return newIPv6Segment(newIPv6SegmentVal(val))
}

func NewIPv6RangeSegment(val, upperVal IPv6SegInt) *IPv6AddressSegment {
	return newIPv6Segment(newIPv6SegmentPrefixedValues(val, upperVal, nil))
}

func NewIPv6PrefixSegment(val IPv6SegInt, prefixLen PrefixLen) *IPv6AddressSegment {
	return newIPv6Segment(newIPv6SegmentPrefixedVal(val, prefixLen))
}

func NewIPv6RangePrefixSegment(val, upperVal IPv6SegInt, prefixLen PrefixLen) *IPv6AddressSegment {
	return newIPv6Segment(newIPv6SegmentPrefixedValues(val, upperVal, prefixLen))
}

func newIPv6Segment(vals *ipv6SegmentValues) *IPv6AddressSegment {
	return &IPv6AddressSegment{
		ipAddressSegmentInternal{
			addressSegmentInternal{
				addressDivisionInternal{
					addressDivisionBase{vals},
				},
			},
		},
	}
}
