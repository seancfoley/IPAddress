package ipaddrold

type ipAddressDivisionValues struct {
	addressDivisionValues
	prefix *PrefixLen
}

func (d *ipAddressDivisionValues) getDivisionPrefixLength() *PrefixLen {
	return d.prefix
}

type ipAddressDivisionInternal struct {
	addressDivisionInternal

	isSinglePrefixBlock *cachedBoolean // this cached value lost when downcasting, but that's ok
}

func (d *ipAddressDivisionInternal) getDivisionPrefixLength() *PrefixLen {
	if d.divisionValues == nil {
		return nil
	}
	return d.getDivisionPrefixLength()
}

func (d *ipAddressDivisionInternal) toIPSegment() *IPAddressSegment {
	d.assignDefaultValues()
	switch d.divisionValues.(type) {
	case *ipv4SegmentValues, *ipv6SegmentValues:
		return &IPAddressSegment{ipAddressSegmentInternal{*d}}
	default:
		return nil
	}
}

func (d *ipAddressDivisionInternal) ToDivision() *AddressDivision {
	d.assignDefaultValues()
	return &AddressDivision{d.addressDivisionInternal}
}

// ToIPv4() converts this IP division to an IPv4 segment if it originated as an IPv4 segment, otherwise it returns nil
func (d *ipAddressDivisionInternal) toIPv4() *IPv4AddressSegment {
	d.assignDefaultValues()
	if _, ok := d.divisionValues.(*ipv4SegmentValues); ok {
		return &IPv4AddressSegment{ipAddressSegmentInternal{*d}}
	}
	return nil
}

// ToIPv4() converts this division to an IPv6 segment if it originated as an IPv6 segment, otherwise it returns nil
func (d *ipAddressDivisionInternal) toIPv6() *IPv6AddressSegment {
	d.assignDefaultValues()
	if _, ok := d.divisionValues.(*ipv6SegmentValues); ok {
		return &IPv6AddressSegment{ipAddressSegmentInternal{*d}}
	}
	return nil
}

type IPAddressDivision struct {
	ipAddressDivisionInternal
}

// GetDivisionValue gets the lower value for the division
func (d *IPAddressDivision) GetDivisionValue() DivInt {
	return d.getDivisionValue()
}

// GetUpperDivisionValue gets the upper value for the division
func (d *IPAddressDivision) GetUpperDivisionValue() DivInt {
	return d.getUpperDivisionValue()
}

// ToIPSegment() converts this division to an IP segment if it originated as an IPv4 segment, otherwise it returns nil
func (d *IPAddressDivision) ToIPSegment() *IPAddressSegment {
	return d.toIPSegment()
}

// ToIPv4() converts this IP division to an IPv4 segment if it originated as an IPv4 segment, otherwise it returns nil
func (d *IPAddressDivision) ToIPv4() *IPv4AddressSegment {
	return d.toIPv4()
}

// ToIPv4() converts this division to an IPv6 segment if it originated as an IPv6 segment, otherwise it returns nil
func (d *IPAddressDivision) ToIPv6() *IPv6AddressSegment {
	return d.toIPv6()
}

func (d *IPAddressDivision) GetDivisionPrefixLength() *PrefixLen {
	return d.getDivisionPrefixLength()
}
