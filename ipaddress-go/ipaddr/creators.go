package ipaddr

type addressSegmentCreator interface {
	createRangeSegment(lower, upper SegInt) *AddressDivision

	createSegment(lower, upper SegInt, segmentPrefixLength PrefixLen) *AddressDivision

	createSegmentInternal(value SegInt, segmentPrefixLength PrefixLen, addressStr string,
		originalVal SegInt, isStandardString bool, lowerStringStartIndex, lowerStringEndIndex int) *AddressDivision

	createRangeSegmentInternal(lower, upper SegInt, segmentPrefixLength PrefixLen, addressStr string,
		originalLower, originalUpper SegInt, isStandardString, isStandardRangeString bool,
		lowerStringStartIndex, lowerStringEndIndex, upperStringEndIndex int) *AddressDivision

	createPrefixSegment(value SegInt, segmentPrefixLength PrefixLen) *AddressDivision

	getMaxValuePerSegment() SegInt
}

type parsedAddressCreator interface {
	addressSegmentCreator

	createSectionInternal(segments []*AddressDivision) *AddressSection

	createAddressInternal(section *AddressSection, identifier HostIdentifierString) *Address
}

type parsedIPAddressCreator interface {
	createPrefixedSectionInternalSingle(segments []*AddressDivision, prefixLength PrefixLen) *IPAddressSection

	createPrefixedSectionInternal(segments []*AddressDivision, prefixLength PrefixLen) *IPAddressSection

	createAddressInternalFromSection(*IPAddressSection, Zone, HostIdentifierString) *IPAddress
}

type ipAddressCreator interface {
	parsedAddressCreator

	parsedIPAddressCreator

	createAddressInternalFromBytes(bytes []byte, zone Zone) *IPAddress
}

type ipv6AddressCreator struct{}

func (creator *ipv6AddressCreator) getMaxValuePerSegment() SegInt {
	return IPv6MaxValuePerSegment
}

func (creator *ipv6AddressCreator) createSegment(lower, upper SegInt, segmentPrefixLength PrefixLen) *AddressDivision {
	return NewIPv6RangePrefixSegment(IPv6SegInt(lower), IPv6SegInt(upper), segmentPrefixLength).ToAddressDivision()
}

func (creator *ipv6AddressCreator) createRangeSegment(lower, upper SegInt) *AddressDivision {
	return NewIPv6RangeSegment(IPv6SegInt(lower), IPv6SegInt(upper)).ToAddressDivision()
}

func (creator *ipv6AddressCreator) createSegmentInternal(value SegInt, segmentPrefixLength PrefixLen, addressStr string,
	originalVal SegInt, isStandardString bool, lowerStringStartIndex, lowerStringEndIndex int) *AddressDivision {
	seg := NewIPv6PrefixSegment(IPv6SegInt(value), segmentPrefixLength)
	seg.setStandardString(addressStr, isStandardString, lowerStringStartIndex, lowerStringEndIndex, originalVal)
	seg.setWildcardString(addressStr, isStandardString, lowerStringStartIndex, lowerStringEndIndex, originalVal)
	return seg.ToAddressDivision()
}

func (creator *ipv6AddressCreator) createRangeSegmentInternal(lower, upper SegInt, segmentPrefixLength PrefixLen, addressStr string,
	originalLower, originalUpper SegInt, isStandardString, isStandardRangeString bool,
	lowerStringStartIndex, lowerStringEndIndex, upperStringEndIndex int) *AddressDivision {
	seg := NewIPv6RangePrefixSegment(IPv6SegInt(lower), IPv6SegInt(upper), segmentPrefixLength)
	seg.setRangeStandardString(addressStr, isStandardString, isStandardRangeString, lowerStringStartIndex, lowerStringEndIndex, upperStringEndIndex, originalLower, originalUpper)
	seg.setRangeWildcardString(addressStr, isStandardRangeString, lowerStringStartIndex, upperStringEndIndex, originalLower, originalUpper)
	return seg.ToAddressDivision()
}

func (creator *ipv6AddressCreator) createPrefixSegment(value SegInt, segmentPrefixLength PrefixLen) *AddressDivision {
	return NewIPv6PrefixSegment(IPv6SegInt(value), segmentPrefixLength).ToAddressDivision()
}

func (creator *ipv6AddressCreator) createPrefixedSectionInternal(segments []*AddressDivision, prefixLength PrefixLen) *IPAddressSection {
	sec, _ := newIPv6SectionSingle(segments, 0, prefixLength, false)
	return sec.ToIPAddressSection()
}

func (creator *ipv6AddressCreator) createPrefixedSectionInternalSingle(segments []*AddressDivision, prefixLength PrefixLen) *IPAddressSection {
	sec, _ := newIPv6SectionSingle(segments, 0, prefixLength, true)
	return sec.ToIPAddressSection()
}

func (creator *ipv6AddressCreator) createSectionInternal(segments []*AddressDivision) *AddressSection {
	return newIPv6SectionParsed(segments).ToAddressSection()
}

func (creator *ipv6AddressCreator) createAddressInternalFromBytes(bytes []byte, zone Zone) *IPAddress {
	addr, _ := newIPv6AddressFromZonedIP(bytes, string(zone))
	return addr.ToIPAddress()
}

func (creator *ipv6AddressCreator) createAddressInternalFromSection(section *IPAddressSection, zone Zone, originator HostIdentifierString) *IPAddress {
	res := newIPv6AddressZoned(section.ToIPv6AddressSection(), string(zone)).ToIPAddress()
	if originator != nil {
		// the originator is assigned to a parsedIPAddress struct in validateHostName or validateIPAddressStr
		res.cache.identifierStr = &IdentifierStr{originator}
	}
	return res
}

func (creator *ipv6AddressCreator) createAddressInternal(section *AddressSection, originator HostIdentifierString) *Address {
	res := newIPv6Address(section.ToIPv6AddressSection()).ToAddress()
	if originator != nil {
		// the originator is assigned to a parsedIPAddress struct in validateHostName or validateIPAddressStr
		res.cache.identifierStr = &IdentifierStr{originator}
	}
	return res
}

type ipv4AddressCreator struct{}

func (creator *ipv4AddressCreator) getMaxValuePerSegment() SegInt {
	return IPv4MaxValuePerSegment
}

func (creator *ipv4AddressCreator) createSegment(lower, upper SegInt, segmentPrefixLength PrefixLen) *AddressDivision {
	return NewIPv4RangePrefixSegment(IPv4SegInt(lower), IPv4SegInt(upper), segmentPrefixLength).ToAddressDivision()
}

func (creator *ipv4AddressCreator) createRangeSegment(lower, upper SegInt) *AddressDivision {
	return NewIPv4RangeSegment(IPv4SegInt(lower), IPv4SegInt(upper)).ToAddressDivision()
}

func (creator *ipv4AddressCreator) createSegmentInternal(value SegInt, segmentPrefixLength PrefixLen, addressStr string,
	originalVal SegInt, isStandardString bool, lowerStringStartIndex, lowerStringEndIndex int) *AddressDivision {
	seg := NewIPv4PrefixSegment(IPv4SegInt(value), segmentPrefixLength)
	seg.setStandardString(addressStr, isStandardString, lowerStringStartIndex, lowerStringEndIndex, originalVal)
	seg.setWildcardString(addressStr, isStandardString, lowerStringStartIndex, lowerStringEndIndex, originalVal)
	return seg.toAddressDivision()
}

func (creator *ipv4AddressCreator) createRangeSegmentInternal(lower, upper SegInt, segmentPrefixLength PrefixLen, addressStr string,
	originalLower, originalUpper SegInt, isStandardString, isStandardRangeString bool,
	lowerStringStartIndex, lowerStringEndIndex, upperStringEndIndex int) *AddressDivision {
	seg := NewIPv4RangePrefixSegment(IPv4SegInt(lower), IPv4SegInt(upper), segmentPrefixLength)
	seg.setRangeStandardString(addressStr, isStandardString, isStandardRangeString, lowerStringStartIndex, lowerStringEndIndex, upperStringEndIndex, originalLower, originalUpper)
	seg.setRangeWildcardString(addressStr, isStandardRangeString, lowerStringStartIndex, upperStringEndIndex, originalLower, originalUpper)
	return seg.ToAddressDivision()
}

func (creator *ipv4AddressCreator) createPrefixSegment(value SegInt, segmentPrefixLength PrefixLen) *AddressDivision {
	return NewIPv4PrefixSegment(IPv4SegInt(value), segmentPrefixLength).ToAddressDivision()
	//return creator.createIPv4PrefixSegment(ToIPv4SegInt(value), segmentPrefixLength)
}

func (creator *ipv4AddressCreator) createPrefixedSectionInternal(segments []*AddressDivision, prefixLength PrefixLen) *IPAddressSection {
	sec, _ := newIPv4SectionSingle(segments, prefixLength, false)
	return sec.ToIPAddressSection()
}

func (creator *ipv4AddressCreator) createPrefixedSectionInternalSingle(segments []*AddressDivision, prefixLength PrefixLen) *IPAddressSection {
	sec, _ := newIPv4SectionSingle(segments, prefixLength, true)
	return sec.ToIPAddressSection()
}

func (creator *ipv4AddressCreator) createSectionInternal(segments []*AddressDivision) *AddressSection {
	return newIPv4SectionParsed(segments).ToAddressSection()
}

func (creator *ipv4AddressCreator) createAddressInternalFromBytes(bytes []byte, _ Zone) *IPAddress {
	addr, _ := NewIPv4AddressFromIP(bytes)
	return addr.ToIPAddress()
}

func (creator *ipv4AddressCreator) createAddressInternalFromSection(section *IPAddressSection, _ Zone, originator HostIdentifierString) *IPAddress {
	res := newIPv4Address(section.ToIPv4AddressSection()).ToIPAddress()
	if originator != nil {
		res.cache.identifierStr = &IdentifierStr{originator}
	}
	return res
}

func (creator *ipv4AddressCreator) createAddressInternal(section *AddressSection, originator HostIdentifierString) *Address {
	res := newIPv4Address(section.ToIPv4AddressSection()).ToAddress()
	if originator != nil {
		res.cache.identifierStr = &IdentifierStr{originator}
	}
	return res
}

//
//
//
//
//

type macAddressCreator struct{}

func (creator *macAddressCreator) getMaxValuePerSegment() SegInt {
	return MACMaxValuePerSegment
}

func (creator *macAddressCreator) createSegment(lower, upper SegInt, _ PrefixLen) *AddressDivision {
	return NewMACRangeSegment(MACSegInt(lower), MACSegInt(upper)).ToAddressDivision()
}

func (creator *macAddressCreator) createRangeSegment(lower, upper SegInt) *AddressDivision {
	return NewMACRangeSegment(MACSegInt(lower), MACSegInt(upper)).ToAddressDivision()
}

func (creator *macAddressCreator) createSegmentInternal(value SegInt, _ PrefixLen, addressStr string,
	originalVal SegInt, isStandardString bool, lowerStringStartIndex, lowerStringEndIndex int) *AddressDivision {
	seg := NewMACSegment(MACSegInt(value))
	seg.setString(addressStr, isStandardString, lowerStringStartIndex, lowerStringEndIndex, originalVal)
	return seg.ToAddressDivision()
}

func (creator *macAddressCreator) createRangeSegmentInternal(lower, upper SegInt, _ PrefixLen, addressStr string,
	originalLower, originalUpper SegInt, isStandardString, isStandardRangeString bool,
	lowerStringStartIndex, lowerStringEndIndex, upperStringEndIndex int) *AddressDivision {
	seg := NewMACRangeSegment(MACSegInt(lower), MACSegInt(upper))
	seg.setRangeString(addressStr, isStandardRangeString, lowerStringStartIndex, upperStringEndIndex, originalLower, originalUpper)
	return seg.ToAddressDivision()
}

func (creator *macAddressCreator) createPrefixSegment(value SegInt, _ PrefixLen) *AddressDivision {
	return NewMACSegment(MACSegInt(value)).ToAddressDivision()
}

func (creator *macAddressCreator) createMACRangeSegment(lower, upper SegInt) *AddressDivision {
	return NewMACRangeSegment(MACSegInt(lower), MACSegInt(upper)).ToAddressDivision()
}

func (creator *macAddressCreator) createSectionInternal(segments []*AddressDivision) *AddressSection {
	return newMACSectionParsed(segments).ToAddressSection()
}

func (creator *macAddressCreator) createAddressInternal(section *AddressSection, originator HostIdentifierString) *Address {
	res := newMACAddress(section.ToMACAddressSection()).ToAddress()
	if originator != nil {
		res.cache.identifierStr = &IdentifierStr{originator}
	}
	return res
}

func (creator *macAddressCreator) createAddressInternalFromSection(section *MACAddressSection, originator HostIdentifierString) *MACAddress {
	res := newMACAddress(section)
	if originator != nil {
		res.cache.identifierStr = &IdentifierStr{originator}
	}
	return res
}
