package ipaddr

import "unsafe"

type MACSegInt uint8 //TODO consider changing to int16 later, because it makes arithmetic easier, in thigns like increment, or iterators, or spliterators

func ToMACSegInt(val SegInt) MACSegInt {
	return MACSegInt(val)
}

//TODO caching, we will share cache and share the values when values match to cache

func newMACSegmentValues(value, upperValue MACSegInt) *macSegmentValues {
	return &macSegmentValues{value: value, upperValue: upperValue}
}

type macSegmentValues struct {
	value      MACSegInt
	upperValue MACSegInt
	cache      divCache
}

func (seg macSegmentValues) GetSegmentPrefixLength() PrefixLen {
	return nil
}

func (seg macSegmentValues) GetBitCount() BitCount {
	return MACBitsPerSegment
}

func (seg macSegmentValues) GetByteCount() int {
	return MACBytesPerSegment
}

func (seg macSegmentValues) getDivisionValue() DivInt {
	return DivInt(seg.value)
}

func (seg macSegmentValues) getUpperDivisionValue() DivInt {
	return DivInt(seg.upperValue)
}

func (seg macSegmentValues) getDivisionPrefixLength() PrefixLen {
	//TODO for MAC this needs to be changed to getMinPrefixLengthForBlock
	return nil
}

func (seg macSegmentValues) getSegmentValue() SegInt {
	return SegInt(seg.value)
}

func (seg macSegmentValues) getUpperSegmentValue() SegInt {
	return SegInt(seg.upperValue)
}

func (seg macSegmentValues) deriveNew(val, upperVal DivInt, prefLen PrefixLen) divisionValues {
	return newMACSegmentValues(seg.value, seg.value)
}

func (seg macSegmentValues) getCache() *divCache {
	return &seg.cache
}

//func (seg macSegmentValues) getLower() (divisionValues, *divCache) {
//	return newMACSegmentValues(seg.value, seg.value)
//}
//
//func (seg macSegmentValues) getUpper() (divisionValues, *divCache) {
//	return newMACSegmentValues(seg.upperValue, seg.upperValue)
//}

var _ divisionValues = macSegmentValues{}

//var _ segmentValues = macSegmentValues{}

type MACAddressSegment struct {
	addressSegmentInternal
}

// We must override GetBitCount, GetByteCount and others for the case when we construct as the zero value

func (seg *MACAddressSegment) GetBitCount() BitCount {
	return IPv4BitsPerSegment
}

func (seg *MACAddressSegment) GetByteCount() int {
	return IPv4BytesPerSegment
}

func (seg *MACAddressSegment) ToAddressDivision() *AddressDivision {
	return seg.ToAddressSegment().ToAddressDivision()
}

func (seg *MACAddressSegment) ToAddressSegment() *AddressSegment {
	if seg == nil {
		return nil
	}
	vals := seg.divisionValues
	if vals == nil {
		seg.divisionValues = macSegmentValues{}
	}
	return (*AddressSegment)(unsafe.Pointer(seg))
}

func NewMACSegment(val MACSegInt) *MACAddressSegment {
	return NewMACRangeSegment(val, val)
}

func NewMACRangeSegment(val, upperVal MACSegInt) *MACAddressSegment {
	return &MACAddressSegment{
		addressSegmentInternal{
			addressDivisionInternal{newMACSegmentValues(val, upperVal)},
		},
	}
}
