package ipaddr

import "unsafe"

type MACSegInt uint8 //TODO consider changing to int16 later, because it makes arithmetic easier, in thigns like increment, or iterators, or spliterators

func ToMACSegInt(val SegInt) MACSegInt {
	return MACSegInt(val)
}

type macSegmentValues struct {
	value      MACSegInt
	upperValue MACSegInt
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

func (seg macSegmentValues) GetSegmentValue() SegInt {
	return SegInt(seg.value)
}

func (seg macSegmentValues) GetUpperSegmentValue() SegInt {
	return SegInt(seg.upperValue)
}

func (seg macSegmentValues) getLower() (divisionValues, *divCache) {
	return newMACSegmentValues(seg.value, seg.value)
}

func (seg macSegmentValues) getUpper() (divisionValues, *divCache) {
	return newMACSegmentValues(seg.upperValue, seg.upperValue)
}

func newMACSegmentValues(value, upperValue MACSegInt) (*macSegmentValues, *divCache) {
	//TODO caching, we will share cache and share the values when values match to cache
	return &macSegmentValues{value: value, upperValue: upperValue}, &divCache{}
}

var _ divisionValues = macSegmentValues{}
var _ segmentValues = macSegmentValues{}

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
	vals, cache := newMACSegmentValues(val, upperVal)
	return &MACAddressSegment{
		addressSegmentInternal{
			addressDivisionInternal{divisionValues: vals, cache: cache},
		},
	}
}
