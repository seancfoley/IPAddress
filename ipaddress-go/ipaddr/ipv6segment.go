package ipaddr

import "unsafe"

type IPv6SegInt uint16 //TODO consider changing to int32 later, because it makes arithmetic easier, in thigns like increment, or iterators, or spliterators

func ToIPv6SegInt(val SegInt) IPv6SegInt {
	return IPv6SegInt(val)
}

//TODO caching of ipv6SegmentValues

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

func (seg ipv6SegmentValues) GetBitCount() BitCount {
	return IPv6BitsPerSegment
}

func (seg ipv6SegmentValues) GetByteCount() int {
	return IPv6BytesPerSegment
}

func (seg ipv6SegmentValues) getDivisionValue() DivInt {
	return DivInt(seg.value)
}

func (seg ipv6SegmentValues) getUpperDivisionValue() DivInt {
	return DivInt(seg.upperValue)
}

func (seg ipv6SegmentValues) getDivisionPrefixLength() PrefixLen {
	return seg.prefLen
}

func (seg ipv6SegmentValues) getSegmentValue() SegInt {
	return SegInt(seg.value)
}

func (seg ipv6SegmentValues) getUpperSegmentValue() SegInt {
	return SegInt(seg.upperValue)
}

//func (seg ipv6SegmentValues) getLower() (divisionValues, *divCache) {
//	return newIPv6SegmentValues(seg.value, seg.value, seg.prefLen)
//}
//
//func (seg ipv6SegmentValues) getUpper() (divisionValues, *divCache) {
//	return newIPv6SegmentValues(seg.upperValue, seg.upperValue, seg.prefLen)
//}

func (seg ipv6SegmentValues) deriveNew(val, upperVal DivInt, prefLen PrefixLen) divisionValues {
	return newIPv6SegmentValues(seg.value, seg.value, seg.prefLen)
}

func (seg ipv6SegmentValues) getCache() *divCache {
	return &seg.cache
}

var _ divisionValues = ipv6SegmentValues{}

//var _ segmentValues = ipv6SegmentValues{}

type IPv6AddressSegment struct {
	ipAddressSegmentInternal
}

// We must override GetBitCount, GetByteCount and others for the case when we construct as the zero value

func (seg *IPv6AddressSegment) GetBitCount() BitCount {
	return IPv6BitsPerSegment
}

func (seg *IPv6AddressSegment) GetByteCount() int {
	return IPv6BytesPerSegment
}

func (seg *IPv6AddressSegment) ToAddressDivision() *AddressDivision {
	return seg.ToIPAddressSegment().ToAddressDivision()
}

func (seg *IPv6AddressSegment) ToAddressSegment() *AddressSegment {
	return seg.ToIPAddressSegment().ToAddressSegment()
}

func (seg *IPv6AddressSegment) ToIPAddressSegment() *IPAddressSegment {
	vals := seg.divisionValues
	if vals == nil {
		seg.divisionValues = ipv6SegmentValues{}
	}
	return (*IPAddressSegment)(unsafe.Pointer(seg))
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
				addressDivisionInternal{newIPv6SegmentValues(val, upperVal, prefixLen)},
			},
		},
	}
}
