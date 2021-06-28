package ipaddr

import (
	"math/big"
)

type IPv4SegInt uint8

func ToIPv4SegInt(val SegInt) IPv4SegInt {
	return IPv4SegInt(val)
}

func newIPv4SegmentValues(value, upperValue IPv4SegInt, prefLen PrefixLen) *ipv4SegmentValues {
	return &ipv4SegmentValues{
		value:      value,
		upperValue: upperValue,
		prefLen:    prefLen,
	}
}

type ipv4SegmentValues struct {
	value      IPv4SegInt
	upperValue IPv4SegInt
	prefLen    PrefixLen
	cache      divCache
}

func (seg *ipv4SegmentValues) getAddrType() addrType {
	return ipv4Type
}

func (seg *ipv4SegmentValues) includesZero() bool {
	return seg.value == 0
}

func (seg *ipv4SegmentValues) includesMax() bool {
	return seg.upperValue == 0xff
}

func (seg *ipv4SegmentValues) isMultiple() bool {
	return seg.value != seg.upperValue
}

func (seg *ipv4SegmentValues) getCount() *big.Int {
	return big.NewInt(int64((seg.upperValue - seg.value)) + 1)
}

func (seg *ipv4SegmentValues) getBitCount() BitCount {
	return IPv4BitsPerSegment
}

func (seg *ipv4SegmentValues) getByteCount() int {
	return IPv4BytesPerSegment
}

func (seg *ipv4SegmentValues) getValue() *big.Int {
	return big.NewInt(int64(seg.value))
}

func (seg *ipv4SegmentValues) getUpperValue() *big.Int {
	return big.NewInt(int64(seg.upperValue))
}

func (seg *ipv4SegmentValues) getDivisionValue() DivInt {
	return DivInt(seg.value)
}

func (seg *ipv4SegmentValues) getUpperDivisionValue() DivInt {
	return DivInt(seg.upperValue)
}

func (seg *ipv4SegmentValues) getDivisionPrefixLength() PrefixLen {
	return seg.prefLen
}

func (seg *ipv4SegmentValues) deriveNew(val, upperVal DivInt, prefLen PrefixLen) divisionValues {
	return newIPv4SegmentValues(IPv4SegInt(val), IPv4SegInt(upperVal), prefLen)
}

func (seg *ipv4SegmentValues) deriveNewSeg(val SegInt, prefLen PrefixLen) divisionValues {
	return newIPv4SegmentValues(IPv4SegInt(val), IPv4SegInt(val), prefLen)
}

func (seg *ipv4SegmentValues) deriveNewMultiSeg(val, upperVal SegInt, prefLen PrefixLen) divisionValues {
	return newIPv4SegmentValues(IPv4SegInt(val), IPv4SegInt(upperVal), prefLen)
}

func (seg *ipv4SegmentValues) getCache() *divCache {
	return &seg.cache
}

func (seg *ipv4SegmentValues) getSegmentValue() SegInt {
	return SegInt(seg.value)
}

func (seg *ipv4SegmentValues) getUpperSegmentValue() SegInt {
	return SegInt(seg.upperValue)
}

func (seg *ipv4SegmentValues) calcBytesInternal() (bytes, upperBytes []byte) {
	bytes = []byte{byte(seg.value)}
	if seg.isMultiple() {
		upperBytes = []byte{byte(seg.upperValue)}
	} else {
		upperBytes = bytes
	}
	return
}

var _ divisionValues = &ipv4SegmentValues{}

var zeroIPv4Seg = NewIPv4Segment(0)

type IPv4AddressSegment struct {
	ipAddressSegmentInternal
}

func (seg *IPv4AddressSegment) init() *IPv4AddressSegment {
	if seg.divisionValues == nil {
		return zeroIPv4Seg
	}
	return seg
}

// We must override getBitCount, getByteCount and others for the case when we construct as the zero value and there are no divisionValues

func (seg *IPv4AddressSegment) GetBitCount() BitCount {
	return IPv4BitsPerSegment
}

func (seg *IPv4AddressSegment) GetByteCount() int {
	return IPv4BytesPerSegment
}

func (seg *IPv4AddressSegment) GetMaxValue() IPv4SegInt {
	return 0xff
}

func (seg *IPv4AddressSegment) Iterator() IPv4SegmentIterator {
	return ipv4SegmentIterator{seg.iterator()}
}

func (seg *IPv4AddressSegment) PrefixBlockIterator() IPv4SegmentIterator {
	return ipv4SegmentIterator{seg.prefixBlockIterator()}
}

func (seg *IPv4AddressSegment) PrefixedBlockIterator(segmentPrefixLen BitCount) IPv4SegmentIterator {
	return ipv4SegmentIterator{seg.prefixedBlockIterator(segmentPrefixLen)}
}

func (seg *IPv4AddressSegment) PrefixIterator() IPv4SegmentIterator {
	return ipv4SegmentIterator{seg.prefixIterator()}
}

func (seg *IPv4AddressSegment) WithoutPrefixLen() *IPv4AddressSegment {
	return seg.withoutPrefixLen().ToIPv4AddressSegment()
}

func (seg *IPv4AddressSegment) ToAddressSegment() *AddressSegment {
	return seg.ToIPAddressSegment().ToAddressSegment()
}

func (seg *IPv4AddressSegment) ToIPAddressSegment() *IPAddressSegment {
	if seg == nil {
		return nil
	}
	return (*IPAddressSegment)(seg.init())
}

func NewIPv4Segment(val IPv4SegInt) *IPv4AddressSegment {
	return NewIPv4RangePrefixSegment(val, val, nil)
}

func NewIPv4RangeSegment(val, upperVal IPv4SegInt) *IPv4AddressSegment {
	return NewIPv4RangePrefixSegment(val, val, nil)
}

func NewIPv4PrefixSegment(val IPv4SegInt, prefixLen PrefixLen) *IPv4AddressSegment {
	return NewIPv4RangePrefixSegment(val, val, prefixLen)
}

func NewIPv4RangePrefixSegment(val, upperVal IPv4SegInt, prefixLen PrefixLen) *IPv4AddressSegment {
	return &IPv4AddressSegment{
		ipAddressSegmentInternal{
			addressSegmentInternal{
				addressDivisionInternal{
					addressDivisionBase{
						newIPv4SegmentValues(val, upperVal, prefixLen),
					},
				},
			},
		},
	}
}
