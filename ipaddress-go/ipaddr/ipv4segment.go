package ipaddr

type ipv4SegmentValues struct {
	value      uint8
	upperValue uint8
	prefLen    PrefixLen
}

func (seg ipv4SegmentValues) GetBitCount() int {
	return IPv4BitsPerSegment
}

func (seg ipv4SegmentValues) GetByteCount() int {
	return IPv4BytesPerSegment
}

func (seg ipv4SegmentValues) GetDivisionValue() DivInt {
	return DivInt(seg.value)
}

func (seg ipv4SegmentValues) GetUpperDivisionValue() DivInt {
	return DivInt(seg.upperValue)
}

func (seg ipv4SegmentValues) getDivisionPrefixLength() PrefixLen {
	return seg.prefLen
}

var _ divisionValues = ipv4SegmentValues{}

type IPv4AddressSegment struct {
	ipAddressSegmentInternal
}

// We must override GetBitCount, GetByteCount and others for the case when we construct as the zero value

func (seg IPv4AddressSegment) GetBitCount() int {
	return IPv4BitsPerSegment
}

func (seg IPv4AddressSegment) GetByteCount() int {
	return IPv4BytesPerSegment
}

func (seg IPv4AddressSegment) ToAddressDivision() AddressDivision {
	vals := seg.divisionValues
	if vals == nil {
		seg.divisionValues = ipv4SegmentValues{}
	}
	return seg.AddressDivision
}

func (seg IPv4AddressSegment) ToIPAddressSegment() IPAddressSegment {
	vals := seg.divisionValues
	if vals == nil {
		seg.divisionValues = ipv4SegmentValues{}
	}
	return seg.IPAddressSegment
}

func (seg IPv4AddressSegment) ToIPv4AddressSegment() IPv4AddressSegment {
	return seg
}

func (seg IPv4AddressSegment) ToIPv6AddressSegment() IPv6AddressSegment {
	return IPv6AddressSegment{}
}

func NewIPv4Segment(val uint8) IPv4AddressSegment {
	return NewIPv4RangeSegment(val, val)
}

func NewIPv4RangeSegment(val, upperVal uint8) IPv4AddressSegment {
	return NewIPv4PrefixSegment(val, val, nil)
}

func NewIPv4PrefixSegment(val, upperVal uint8, prefixLen PrefixLen) IPv4AddressSegment {
	return IPv4AddressSegment{ipAddressSegmentInternal{IPAddressSegment{AddressDivision{
		ipv4SegmentValues{
			value:      val,
			upperValue: upperVal,
			prefLen:    prefixLen,
		},
	}}}}
}
