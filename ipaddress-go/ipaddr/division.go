package ipaddr

// SegInt is an unsigned integer type for holding generic segment values, which are unsigned byte for MAC or IPv4 and two unsigned bytes for IPv6.
type SegInt = uint16

// DivInt is an unsigned integer type for division values, aliased to the largest unsigned primitive type to allow for the largest possible division values.
type DivInt = uint64

type divisionValuesBase interface { // shared by standard and large divisions
	GetBitCount() int

	GetByteCount() int
}

// DivisionValues represents divisions with values that are 64 bits or less
type divisionValues interface {
	divisionValuesBase

	// GetDivisionValue gets the lower value for the division
	GetDivisionValue() DivInt

	// GetUpperDivisionValue gets the upper value for the division
	GetUpperDivisionValue() DivInt

	getDivisionPrefixLength() PrefixLen
}

type AddressDivision struct {
	divisionValues
}

func (div AddressDivision) ToIPAddressSegment() IPAddressSegment {
	if bitCount := div.GetBitCount(); bitCount != IPv4BitsPerSegment && bitCount != IPv6BitsPerSegment {
		return IPAddressSegment{}
	}
	return IPAddressSegment{div}
}

func (div AddressDivision) ToIPv4AddressSegment() IPv4AddressSegment {
	return div.ToIPAddressSegment().ToIPv4AddressSegment()
}

func (div AddressDivision) ToIPv6AddressSegment() IPv6AddressSegment {
	return div.ToIPAddressSegment().ToIPv6AddressSegment()
}

func (div AddressDivision) GetBitCount() int {
	vals := div.divisionValues
	if vals == nil {
		return 0
	}
	return vals.GetBitCount()
}

func (div AddressDivision) GetByteCount() int {
	vals := div.divisionValues
	if vals == nil {
		return 0
	}
	return vals.GetByteCount()
}

func (div AddressDivision) GetDivisionValue() DivInt {
	vals := div.divisionValues
	if vals == nil {
		return 0
	}
	return vals.GetDivisionValue()
}

func (div AddressDivision) GetUpperDivisionValue() DivInt {
	vals := div.divisionValues
	if vals == nil {
		return 0
	}
	return vals.GetUpperDivisionValue()
}

type IPAddressSegment struct {
	AddressDivision
}

func (seg IPAddressSegment) ToAddressDivision() AddressDivision {
	return seg.AddressDivision
}

func (seg IPAddressSegment) ToIPAddressSegment() IPAddressSegment {
	return seg
}

func (seg IPAddressSegment) ToIPv4AddressSegment() IPv4AddressSegment {
	if bitCount := seg.GetBitCount(); bitCount != IPv4BitsPerSegment {
		return IPv4AddressSegment{}
	}
	return IPv4AddressSegment{ipAddressSegmentInternal{seg}}
}

func (seg IPAddressSegment) ToIPv6AddressSegment() IPv6AddressSegment {
	if bitCount := seg.GetBitCount(); bitCount != IPv6BitsPerSegment {
		return IPv6AddressSegment{}
	}
	return IPv6AddressSegment{ipAddressSegmentInternal{seg}}
}

func (seg IPAddressSegment) GetDivisionPrefixLength() PrefixLen {
	vals := seg.divisionValues
	if vals == nil {
		return nil
	}
	return vals.getDivisionPrefixLength()
}

// Need to prevent direct access to the IPAddressSegment, particularly when zero value
// The IPv4 and IPv6 types need to convert the segment to the appropriate zero value with every method call that defers to IPAddressSegment
type ipAddressSegmentInternal struct {
	IPAddressSegment
}
