package ipaddr

type ipv6SegmentValues struct {
	value      uint16
	upperValue uint16
	prefLen    PrefixLen
}

func (seg ipv6SegmentValues) GetBitCount() BitCount {
	return IPv6BitsPerSegment
}

func (seg ipv6SegmentValues) GetByteCount() int {
	return IPv6BytesPerSegment
}

func (seg ipv6SegmentValues) GetDivisionValue() DivInt {
	return DivInt(seg.value)
}

func (seg ipv6SegmentValues) GetUpperDivisionValue() DivInt {
	return DivInt(seg.upperValue)
}

func (seg ipv6SegmentValues) getDivisionPrefixLength() PrefixLen {
	return seg.prefLen
}

func (seg ipv6SegmentValues) GetSegmentPrefixLength() PrefixLen {
	return seg.prefLen
}

func (seg ipv6SegmentValues) GetSegmentValue() SegInt {
	return SegInt(seg.value)
}

func (seg ipv6SegmentValues) GetUpperSegmentValue() SegInt {
	return SegInt(seg.upperValue)
}

var _ divisionValues = ipv6SegmentValues{}
var _ segmentValues = ipv6SegmentValues{}

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
	vals := seg.divisionValues
	if vals == nil {
		seg.divisionValues = ipv6SegmentValues{}
	}
	return &seg.AddressDivision
}

func (seg IPv6AddressSegment) ToIPAddressSegment() *IPAddressSegment {
	vals := seg.divisionValues
	if vals == nil {
		seg.divisionValues = ipv6SegmentValues{}
	}
	return &seg.IPAddressSegment
}

func (seg *IPv6AddressSegment) ToIPv6AddressSegment() *IPv6AddressSegment {
	return seg
}

func (seg *IPv6AddressSegment) ToIPv4AddressSegment() *IPv4AddressSegment {
	return nil
}

func NewIPv6Segment(val uint16) *IPv6AddressSegment {
	return NewIPv6RangeSegment(val, val)
}

func NewIPv6RangeSegment(val, upperVal uint16) *IPv6AddressSegment {
	return NewIPv6PrefixSegment(val, val, nil)
}

func NewIPv6PrefixSegment(val, upperVal uint16, prefixLen PrefixLen) *IPv6AddressSegment {
	return &IPv6AddressSegment{
		ipAddressSegmentInternal{
			IPAddressSegment{
				addressDivisionInternal{
					AddressDivision{
						ipv6SegmentValues{
							value:      val,
							upperValue: upperVal,
							prefLen:    prefixLen,
						},
					},
				},
			},
		},
	}
}
