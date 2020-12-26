package ipaddr

import (
	"unsafe"
)

//TODO consider changing to int16 later, because it makes arithmetic easier, in thigns like increment, or iterators, or spliterators
// So far I have decided against it, and instead used the unsigned types to save space
// Golang addresses also use unsigned
// I think you just need to be careful with arithmetic

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

func (seg ipv4SegmentValues) GetBitCount() BitCount {
	return IPv4BitsPerSegment
}

func (seg ipv4SegmentValues) GetByteCount() int {
	return IPv4BytesPerSegment
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
	return newIPv4SegmentValues(seg.value, seg.value, seg.prefLen)
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

//func (seg ipv4SegmentValues) GetSegmentPrefixLength() PrefixLen {
//	return seg.prefLen
//}

var _ divisionValues = ipv4SegmentValues{}

//var _ segmentValues = ipv4SegmentValues{}

//TODO make this use pointers to, just like sections and addresses, because we will have cached data too,
//isSinglePrefixBlock, cachedString,
//	protected transient String cachedWildcardString;
//	private transient byte[] lowerBytes, upperBytes;
// Now, since the parsing will populate the cachedString, we could move it out of the cached data, which is stuff that is populate on the fly
// But remember, that is a bad idea, we want to allow copying, so anything that is not always created right away must go to cache object

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

func (seg *IPv4AddressSegment) ToAddressDivision() *AddressDivision {
	return seg.ToIPAddressSegment().ToAddressDivision()
}

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
					newIPv4SegmentValues(val, upperVal, prefixLen),
				},
			},
		},
	}
}
