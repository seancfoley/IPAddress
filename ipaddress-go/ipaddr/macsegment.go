package ipaddr

import "unsafe"

type macSegmentValues struct {
	value      uint8
	upperValue uint8
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

func (seg macSegmentValues) GetDivisionValue() DivInt {
	return DivInt(seg.value)
}

func (seg macSegmentValues) GetUpperDivisionValue() DivInt {
	return DivInt(seg.upperValue)
}

func (seg macSegmentValues) getDivisionPrefixLength() PrefixLen {
	return nil
}

//func (seg macSegmentValues) GetSegmentPrefixLength() PrefixLen {
//	return seg.prefLen
//}

func (seg macSegmentValues) GetSegmentValue() SegInt {
	return SegInt(seg.value)
}

func (seg macSegmentValues) GetUpperSegmentValue() SegInt {
	return SegInt(seg.upperValue)
}

var _ divisionValues = macSegmentValues{}
var _ segmentValues = macSegmentValues{}

//TODO make this use pointers to, just like sections and addresses, because we will have cached data too,
//isSinglePrefixBlock, cachedString,
//	protected transient String cachedWildcardString;
//	private transient byte[] lowerBytes, upperBytes;
// Now, since the parsing will populate the cachedString, we could move it out of the cached data, which is stuff that is populate on the fly
// But remember, that is a bad idea, we want to allow copying, so anything that is not always created right away must go to cache object

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
	if seg == nil {
		return nil
	}
	vals := seg.divisionValues
	if vals == nil {
		seg.divisionValues = ipv4SegmentValues{}
	}
	return (*AddressDivision)(unsafe.Pointer(seg))
}

func NewMACSegment(val uint8) *MACAddressSegment {
	return NewMACRangeSegment(val, val)
}

func NewMACRangeSegment(val, upperVal uint8) *MACAddressSegment {
	return &MACAddressSegment{
		addressSegmentInternal{
			addressDivisionInternal{
				macSegmentValues{
					value:      val,
					upperValue: upperVal,
				},
			},
		},
	}
}
