package ipaddr

import (
	"math/big"
	"unsafe"
)

type IPv4SegInt uint8

func ToIPv4SegInt(val SegInt) IPv4SegInt {
	return IPv4SegInt(val)
}

func newIPv4SegmentValues(value, upperValue IPv4SegInt, prefLen PrefixLen) *ipv4SegmentValues {
	// caching, we will share cache and share the values when values match to cache
	//xxx not sure i like returnig a cache
	//xxx the cache is at different level
	//if we return a cache to sorrespond to a set of values,
	//then that means cache is determined by those values and should be in here?
	//but I guess we deermined cache is the same regardless of structure?
	//
	//
	//- makes sense to keep the interface stuff simple
	//- cache code can be shared
	//- but the interfaces know if/how to do the caching
	//
	//DO same as java
	//caching is not just one thing , there is the seg cache and also each thing in the divCache
	//in java they are cached in different places
	//In java, you cache the segs, and inside the segs are the div cache stuff
	//so here, put the div cache inside the cached segs and the code to put stuff in that cache is shared
	//so add a getCache()
	//xxxxxxxxxxxxxxxxx add getCache() xxxxx

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

func (seg ipv4SegmentValues) includesZero() bool {
	return seg.value == 0
}

func (seg ipv4SegmentValues) includesMax() bool {
	return seg.upperValue == 0xff
}

func (seg ipv4SegmentValues) isMultiple() bool {
	return seg.value != seg.upperValue
}

func (seg ipv4SegmentValues) getCount() *big.Int {
	return big.NewInt(int64((seg.upperValue - seg.value)) + 1)
}

func (seg ipv4SegmentValues) GetBitCount() BitCount {
	return IPv4BitsPerSegment
}

func (seg ipv4SegmentValues) GetByteCount() int {
	return IPv4BytesPerSegment
}

func (seg ipv4SegmentValues) getValue() *big.Int {
	return big.NewInt(int64(seg.value))
}

func (seg ipv4SegmentValues) getUpperValue() *big.Int {
	return big.NewInt(int64(seg.upperValue))
}

func (seg ipv4SegmentValues) getDivisionValue() DivInt {
	return DivInt(seg.value)
}

func (seg ipv4SegmentValues) getUpperDivisionValue() DivInt {
	return DivInt(seg.upperValue)
}

func (seg ipv4SegmentValues) getDivisionPrefixLength() PrefixLen {
	return seg.prefLen
}

func (seg ipv4SegmentValues) deriveNew(val, upperVal DivInt, prefLen PrefixLen) divisionValues {
	return newIPv4SegmentValues(IPv4SegInt(val), IPv4SegInt(upperVal), prefLen)
}

func (seg ipv4SegmentValues) deriveNewSeg(val, upperVal SegInt, prefLen PrefixLen) divisionValues {
	return newIPv4SegmentValues(IPv4SegInt(val), IPv4SegInt(upperVal), prefLen)
}

func (seg ipv4SegmentValues) getCache() *divCache {
	return &seg.cache
}

func (seg ipv4SegmentValues) getSegmentValue() SegInt {
	return SegInt(seg.value)
}

func (seg ipv4SegmentValues) getUpperSegmentValue() SegInt {
	return SegInt(seg.upperValue)
}

func (seg ipv4SegmentValues) calcBytesInternal() (bytes, upperBytes []byte) {
	bytes = []byte{byte(seg.value)}
	if seg.isMultiple() {
		upperBytes = []byte{byte(seg.upperValue)}
	} else {
		upperBytes = bytes
	}
	return
}

var _ divisionValues = ipv4SegmentValues{}

type IPv4AddressSegment struct {
	ipAddressSegmentInternal
}

// We must override GetBitCount, GetByteCount and others for the case when we construct as the zero value

func (seg *IPv4AddressSegment) GetBitCount() BitCount {
	return IPv4BitsPerSegment
}

func (seg *IPv4AddressSegment) GetByteCount() int {
	return IPv4BytesPerSegment
}

func (seg *IPv4AddressSegment) GetMaxValue() IPv4SegInt {
	return 0xff
}

//func (seg *IPv4AddressSegment) ToAddressDivision() *AddressDivision {
//	return seg.ToIPAddressSegment().ToAddressDivision() xxx
//}

func (seg *IPv4AddressSegment) ToAddressSegment() *AddressSegment {
	return seg.ToIPAddressSegment().ToAddressSegment()
}

func (seg *IPv4AddressSegment) ToIPAddressSegment() *IPAddressSegment {
	if seg == nil {
		return nil
	}
	vals := seg.divisionValues
	if vals == nil {
		seg.divisionValues = ipv4SegmentValues{}
	}
	return (*IPAddressSegment)(unsafe.Pointer(seg))
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
