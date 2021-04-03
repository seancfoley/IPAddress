package ipaddr

import (
	"math/big"
)

type IPv6SegInt uint16

func ToIPv6SegInt(val SegInt) IPv6SegInt {
	return IPv6SegInt(val)
}

//TODO caching of ipv6SegmentValues

// https://www.tapirgames.com/blog/golang-interface-implementation
/*
type _interface struct {
	dynamicTypeInfo *_implementation
	dynamicValue    unsafe.Pointer // unsafe.Pointer means
	                               // *ArbitraryType in Go.
}
For the official Go compiler and runtime, a non-nil dynamicValue field value may store
the address of the dynamic value if the dynamic type is not a pointer type, or
the dynamic value itself if the dynamic type is a pointer type.
Surely, it is not essential to make the exception for pointer dynamic values.
This is just a compiler optimization. We can get why it is an optimization in following sections.
(BTW, about more current and future optimizations in the official interface implementation, please read this article.)
*/
// If ipv6SegmentValues implements divisionValues by pointer, then it will stick that pointer in the interface var
// So there is really no reason to make ipv6SegmentValues use non-pointer method receivers
// Cuz it will already by dereferencing at least one pointer through the interface, might as well be that one

func newIPv6SegmentValues(value, upperValue IPv6SegInt, prefLen PrefixLen) *ipv6SegmentValues {
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

func (seg *ipv6SegmentValues) getValue() *big.Int {
	return big.NewInt(int64(seg.value))
}

func (seg *ipv6SegmentValues) getUpperValue() *big.Int {
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
	return newIPv6SegmentValues(IPv6SegInt(val), IPv6SegInt(upperVal), prefLen)
}

func (seg *ipv6SegmentValues) deriveNewSeg(val SegInt, prefLen PrefixLen) divisionValues {
	return newIPv6SegmentValues(IPv6SegInt(val), IPv6SegInt(val), prefLen)
}

func (seg *ipv6SegmentValues) deriveNewMultiSeg(val, upperVal SegInt, prefLen PrefixLen) divisionValues {
	return newIPv6SegmentValues(IPv6SegInt(val), IPv6SegInt(upperVal), prefLen)
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

func (seg *IPv6AddressSegment) WithoutPrefixLength() *IPv6AddressSegment {
	return seg.withoutPrefixLength().ToIPv6AddressSegment()
}

// Converts this IPv6 address segment into smaller segments,
// copying them into the given array starting at the given index.
//
// If a segment does not fit into the array because the segment index in the array is out of bounds of the array,
// then it is not copied.
func (seg *IPv6AddressSegment) visitSplitSegments(target func(index int, div *IPv4AddressSegment), boundaryIndex, index int) {
	if !seg.IsMultiple() {
		bitSizeSplit := BitCount(IPv6BitsPerSegment >> 1)
		myPrefix := seg.GetDivisionPrefixLength()
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

func (seg *IPv6AddressSegment) visitSplitSegmentsMultiple(target func(index int, div *IPv4AddressSegment), boundaryIndex, index int) {
	myPrefix := seg.GetDivisionPrefixLength()
	bitSizeSplit := BitCount(IPv6BitsPerSegment >> 1)
	if index >= 0 && index < boundaryIndex {
		highLower := highByte(seg.GetSegmentValue())
		highUpper := highByte(seg.GetUpperSegmentValue())
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
		lowLower := lowByte(seg.GetSegmentValue())
		lowUpper := lowByte(seg.GetUpperSegmentValue())
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
	return highByte(seg.GetSegmentValue())
}

func (seg *IPv6AddressSegment) lowByte() SegInt {
	return lowByte(seg.GetSegmentValue())
}

func highByte(value SegInt) SegInt {
	return value >> 8
}

func lowByte(value SegInt) SegInt {
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
	return NewIPv6RangePrefixSegment(val, val, nil)
}

func NewIPv6RangeSegment(val, upperVal IPv6SegInt) *IPv6AddressSegment {
	return NewIPv6RangePrefixSegment(val, val, nil)
}

func NewIPv6PrefixSegment(val IPv6SegInt, prefixLen PrefixLen) *IPv6AddressSegment {
	return NewIPv6RangePrefixSegment(val, val, prefixLen)
}

func NewIPv6RangePrefixSegment(val, upperVal IPv6SegInt, prefixLen PrefixLen) *IPv6AddressSegment {
	return &IPv6AddressSegment{
		ipAddressSegmentInternal{
			addressSegmentInternal{
				addressDivisionInternal{
					addressDivisionBase{newIPv6SegmentValues(val, upperVal, prefixLen)},
				},
			},
		},
	}
}
