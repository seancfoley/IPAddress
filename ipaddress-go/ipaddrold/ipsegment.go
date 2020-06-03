package ipaddrold

type ipAddressSegmentInternal struct {
	ipAddressDivisionInternal
}

func (d *ipAddressSegmentInternal) GetSegmentValue() SegInt {
	return SegInt(d.GetDivisionValue())
}

func (d *ipAddressSegmentInternal) GetUpperSegmentValue() SegInt {
	return SegInt(d.GetUpperDivisionValue())
}

func (d *ipAddressSegmentInternal) ToIPDivision() *IPAddressDivision {
	d.assignDefaultValues()
	return &IPAddressDivision{d.ipAddressDivisionInternal}
}

func (d *ipAddressSegmentInternal) toIPSegment() *IPAddressSegment {
	return &IPAddressSegment{*d}
}

func (d *ipAddressSegmentInternal) GetSegmentPrefixLength() *PrefixLen {
	return d.getDivisionPrefixLength()
}

type IPAddressSegment struct {
	ipAddressSegmentInternal
}

// ToIPv4() converts this IP division to an IPv4 segment if it originated as an IPv4 segment, otherwise it returns nil
func (d *IPAddressSegment) ToIPv4() *IPv4AddressSegment {
	return d.toIPv4()
}

// ToIPv4() converts this division to an IPv6 segment if it originated as an IPv6 segment, otherwise it returns nil
func (d *IPAddressSegment) ToIPv6() *IPv6AddressSegment {
	return d.toIPv6()
}
