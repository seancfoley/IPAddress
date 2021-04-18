package ipaddr

import "unsafe"

type AddressSegmentCreator interface {
	//createSegmentArray(length int) []*addressDivisionInternal

	createSegment(lower, upper SegInt, segmentPrefixLength PrefixLen) *AddressDivision

	createSegmentInternal(value SegInt, segmentPrefixLength PrefixLen, addressStr string,
		originalVal SegInt, isStandardString bool, lowerStringStartIndex, lowerStringEndIndex int) *AddressDivision

	createRangeSegmentInternal(lower, upper SegInt, segmentPrefixLength PrefixLen, addressStr string,
		originalLower, originalUpper SegInt, isStandardString, isStandardRangeString bool,
		lowerStringStartIndex, lowerStringEndIndex, upperStringEndIndex int) *AddressDivision

	// We are using more exact int types, so you might as well avoid these methods down here if you can
	//createSegment(value SegInt) *AddressDivision
	//
	//createRangeSegment(lower, upper SegInt) *AddressDivision

	createPrefixSegment(value SegInt, segmentPrefixLength PrefixLen) *AddressDivision
	//
	//createRangePrefixSegment(lower, upper SegInt, segmentPrefixLength PrefixLen) *AddressDivision

	getMaxValuePerSegment() SegInt
}

type ParsedAddressCreator interface {
	AddressSegmentCreator

	createSectionInternal(segments []*AddressDivision) *AddressSection

	//createPrefixedSectionInternalSingle(segments []*AddressDivision, prefixLength PrefixLen) *AddressSection

	//createZonedAddressInternal(section *AddressSection, zone Zone) *Address

	createAddressInternal(section *AddressSection, identifier HostIdentifierString) *Address
}

type ParsedIPAddressCreator interface {
	createPrefixedSectionInternalSingle(segments []*AddressDivision, prefixLength PrefixLen) *IPAddressSection

	createPrefixedSectionInternal(segments []*AddressDivision, prefixLength PrefixLen) *IPAddressSection

	createAddressInternalFromSection(*IPAddressSection, Zone, HostIdentifierString) *IPAddress
}

type AddressCreator interface {
	ParsedAddressCreator
}

type IPAddressCreator interface {
	AddressCreator

	ParsedIPAddressCreator

	createAddressInternalFromBytes(bytes []byte, zone string) *IPAddress
}

//TODO the methods in the creator interface that use the exact type, nammely uint16, will be public.  Those using SegInt will remain private
type IPv6AddressCreator struct{}

func (creator *IPv6AddressCreator) getMaxValuePerSegment() SegInt {
	return IPv6MaxValuePerSegment
}

func (creator *IPv6AddressCreator) createSegment(lower, upper SegInt, segmentPrefixLength PrefixLen) *AddressDivision {
	return creator.createIPv6RangePrefixSegment(ToIPv6SegInt(lower), ToIPv6SegInt(upper), segmentPrefixLength)
}

func (creator *IPv6AddressCreator) createSegmentInternal(value SegInt, segmentPrefixLength PrefixLen, addressStr string,
	originalVal SegInt, isStandardString bool, lowerStringStartIndex, lowerStringEndIndex int) *AddressDivision {
	result := creator.createIPv6PrefixSegment(ToIPv6SegInt(value), segmentPrefixLength)
	//TODO store string slices
	return result
}

func (creator *IPv6AddressCreator) createRangeSegmentInternal(lower, upper SegInt, segmentPrefixLength PrefixLen, addressStr string,
	originalLower, originalUpper SegInt, isStandardString, isStandardRangeString bool,
	lowerStringStartIndex, lowerStringEndIndex, upperStringEndIndex int) *AddressDivision {
	result := creator.createIPv6RangePrefixSegment(ToIPv6SegInt(lower), ToIPv6SegInt(upper), segmentPrefixLength)
	//TODO store string slices
	return result
}

func (creator *IPv6AddressCreator) createPrefixSegment(value SegInt, segmentPrefixLength PrefixLen) *AddressDivision {
	return creator.createIPv6PrefixSegment(ToIPv6SegInt(value), segmentPrefixLength)
}

//func (creator *IPv6AddressCreator) createSegmentArray(length int) []*AddressDivision {
//	return make([]*AddressDivision, length)
//}

//func (creator *IPv6AddressCreator) createAddressArray() [IPv6SegmentCount]*AddressDivision {
//	return [IPv6SegmentCount]*AddressDivision{}
//}

func (creator *IPv6AddressCreator) createIPv6Segment(value IPv6SegInt) *AddressDivision {
	return NewIPv6Segment(value).ToAddressDivision()
}

func (creator *IPv6AddressCreator) createIPv6PrefixSegment(value IPv6SegInt, segmentPrefixLength PrefixLen) *AddressDivision {
	return NewIPv6PrefixSegment(value, segmentPrefixLength).ToAddressDivision()
}

func (creator *IPv6AddressCreator) createIPv6RangeSegment(lower, upper IPv6SegInt) *AddressDivision {
	return NewIPv6RangeSegment(lower, upper).ToAddressDivision()
}

func (creator *IPv6AddressCreator) createIPv6RangePrefixSegment(lower, upper IPv6SegInt, segmentPrefixLength PrefixLen) *AddressDivision {
	return NewIPv6RangePrefixSegment(lower, upper, segmentPrefixLength).ToAddressDivision()
}

func (creator *IPv6AddressCreator) createPrefixedSectionInternal(segments []*AddressDivision, prefixLength PrefixLen) *IPAddressSection {
	sec, _ := newIPv6AddressSectionSingle(segments, 0, prefixLength, false)
	return sec.ToIPAddressSection()
}

func (creator *IPv6AddressCreator) createPrefixedSectionInternalSingle(segments []*AddressDivision, prefixLength PrefixLen) *IPAddressSection {
	sec, _ := newIPv6AddressSectionSingle(segments, 0, prefixLength, true)
	return sec.ToIPAddressSection()
}

func (creator *IPv6AddressCreator) createSectionInternal(segments []*AddressDivision) *AddressSection {
	return newIPv6AddressSectionParsed(segments).ToAddressSection()
}

func (creator *IPv6AddressCreator) createAddressInternalFromBytes(bytes []byte, zone string) *IPAddress {
	//TODO create address (either use "New" or create the Address and call ToIPAddress)
	return nil
}

func (creator *IPv6AddressCreator) createAddressInternalFromSection(section *IPAddressSection, zone Zone, originator HostIdentifierString) *IPAddress {
	res := NewIPv6AddressZoned(section.ToIPv6AddressSection(), zone).ToIPAddress()
	if originator != nil {
		res.cache.fromString = unsafe.Pointer(originator.(*IPAddressString))
	}
	return res
}

//func (creator *IPv6AddressCreator) createZonedAddressInternal(section *AddressSection, zone Zone) *Address {
//	return NewIPv6Address(section.ToIPv6AddressSection()).ToAddress() xxxx
//}

func (creator *IPv6AddressCreator) createAddressInternal(section *AddressSection, originator HostIdentifierString) *Address {
	res := NewIPv6Address(section.ToIPv6AddressSection()).ToAddress()
	if originator != nil {
		res.cache.fromString = unsafe.Pointer(originator.(*IPAddressString))
	}
	return res
}

//TODO creators: the methods in the creator interface that use the exact type, nammely IPv4SegInt, will be public.
// Those using SegInt will remain private (these are the ones we use after parsing IIRC)
// "Internal" will remain private, for same reasons as in Java, so we can avoid extra obj creation.
// Private methods will likely defer to base types like AddressDivision and AddressSection
// Public methods will create IPv4 types like IPv4Segment and IPv4AddressSection

type IPv4AddressCreator struct{}

func (creator *IPv4AddressCreator) getMaxValuePerSegment() SegInt {
	return IPv4MaxValuePerSegment
}

func (creator *IPv4AddressCreator) createSegment(lower, upper SegInt, segmentPrefixLength PrefixLen) *AddressDivision {
	return creator.createIPv4RangePrefixSegment(ToIPv4SegInt(lower), ToIPv4SegInt(upper), segmentPrefixLength)
}

func (creator *IPv4AddressCreator) createSegmentInternal(value SegInt, segmentPrefixLength PrefixLen, addressStr string,
	originalVal SegInt, isStandardString bool, lowerStringStartIndex, lowerStringEndIndex int) *AddressDivision {
	result := creator.createIPv4PrefixSegment(ToIPv4SegInt(value), segmentPrefixLength)
	//TODO store string slices
	return result
}

func (creator *IPv4AddressCreator) createRangeSegmentInternal(lower, upper SegInt, segmentPrefixLength PrefixLen, addressStr string,
	originalLower, originalUpper SegInt, isStandardString, isStandardRangeString bool,
	lowerStringStartIndex, lowerStringEndIndex, upperStringEndIndex int) *AddressDivision {
	result := creator.createIPv4RangePrefixSegment(ToIPv4SegInt(lower), ToIPv4SegInt(upper), segmentPrefixLength)
	//TODO store string slices
	return result
}

func (creator *IPv4AddressCreator) createPrefixSegment(value SegInt, segmentPrefixLength PrefixLen) *AddressDivision {
	return creator.createIPv4PrefixSegment(ToIPv4SegInt(value), segmentPrefixLength)
}

//func (creator *IPv4AddressCreator) createSegmentArray(length int) []*AddressDivision {
//	return make([]*AddressDivision, length)
//}

//func (creator *IPv4AddressCreator) createAddressArray() [IPv4SegmentCount]*AddressDivision {
//	return [IPv4SegmentCount]*AddressDivision{}
//}

func (creator *IPv4AddressCreator) createIPv4Segment(value IPv4SegInt) *AddressDivision {
	return NewIPv4Segment(value).ToAddressDivision()
}

func (creator *IPv4AddressCreator) createIPv4RangeSegment(lower, upper IPv4SegInt) *AddressDivision {
	return NewIPv4RangeSegment(lower, upper).ToAddressDivision()
}

func (creator *IPv4AddressCreator) createIPv4PrefixSegment(value IPv4SegInt, segmentPrefixLength PrefixLen) *AddressDivision {
	return NewIPv4PrefixSegment(value, segmentPrefixLength).ToAddressDivision()
}

func (creator *IPv4AddressCreator) createIPv4RangePrefixSegment(lower, upper IPv4SegInt, segmentPrefixLength PrefixLen) *AddressDivision {
	return NewIPv4RangePrefixSegment(lower, upper, segmentPrefixLength).ToAddressDivision()
}

func (creator *IPv4AddressCreator) createPrefixedSectionInternal(segments []*AddressDivision, prefixLength PrefixLen) *IPAddressSection {
	sec, _ := newIPv4AddressSectionSingle(segments, prefixLength, false)
	return sec.ToIPAddressSection()
}

func (creator *IPv4AddressCreator) createPrefixedSectionInternalSingle(segments []*AddressDivision, prefixLength PrefixLen) *IPAddressSection {
	sec, _ := newIPv4AddressSectionSingle(segments, prefixLength, true)
	return sec.ToIPAddressSection()
}

func (creator *IPv4AddressCreator) createSectionInternal(segments []*AddressDivision) *AddressSection {
	return newIPv4AddressSectionParsed(segments).ToAddressSection()
}

func (creator *IPv4AddressCreator) createAddressInternalFromBytes(bytes []byte, zone string) *IPAddress {
	//TODO create address, call ToIPAddress
	return nil
}

func (creator *IPv4AddressCreator) createAddressInternalFromSection(section *IPAddressSection, zone Zone, originator HostIdentifierString) *IPAddress {
	res := NewIPv4Address(section.ToIPv4AddressSection()).ToIPAddress()
	if originator != nil {
		res.cache.fromString = unsafe.Pointer(originator.(*IPAddressString))
	}
	return res
}

//func (creator *IPv4AddressCreator) createZonedAddressInternal(section *AddressSection, zone Zone) *Address {
//	return creator.createAddressInternal(section)
//}

func (creator *IPv4AddressCreator) createAddressInternal(section *AddressSection, identifierString HostIdentifierString) *Address {
	return NewIPv4Address(section.ToIPv4AddressSection()).ToAddress()
}

//
//
//
//
//

type MACAddressCreator struct{}

func (creator *MACAddressCreator) getMaxValuePerSegment() SegInt {
	return MACMaxValuePerSegment
}

func (creator *MACAddressCreator) createSegment(lower, upper SegInt, segmentPrefixLength PrefixLen) *AddressDivision {
	return creator.createMACRangePrefixSegment(ToMACSegInt(lower), ToMACSegInt(upper), segmentPrefixLength)
}

func (creator *MACAddressCreator) createSegmentInternal(value SegInt, segmentPrefixLength PrefixLen, addressStr string,
	originalVal SegInt, isStandardString bool, lowerStringStartIndex, lowerStringEndIndex int) *AddressDivision {
	result := creator.createMACPrefixSegment(ToMACSegInt(value), segmentPrefixLength)
	//TODO store string slices
	return result
}

func (creator *MACAddressCreator) createRangeSegmentInternal(lower, upper SegInt, segmentPrefixLength PrefixLen, addressStr string,
	originalLower, originalUpper SegInt, isStandardString, isStandardRangeString bool,
	lowerStringStartIndex, lowerStringEndIndex, upperStringEndIndex int) *AddressDivision {
	result := creator.createMACRangePrefixSegment(ToMACSegInt(lower), ToMACSegInt(upper), segmentPrefixLength)
	//TODO store string slices
	return result
}

func (creator *MACAddressCreator) createPrefixSegment(value SegInt, segmentPrefixLength PrefixLen) *AddressDivision {
	return creator.createMACPrefixSegment(ToMACSegInt(value), segmentPrefixLength)
}

//func (creator *MACAddressCreator) createSegmentArray(length int) []*AddressDivision {
//	return make([]*AddressDivision, length)
//}
//
//func (creator *IPv4AddressCreator) createMACAddressArray(length int) [MediaAccessControlSegmentCount]*AddressDivision {
//	return [MediaAccessControlSegmentCount]*AddressDivision{}
//}
//
//func (creator *IPv4AddressCreator) createEUI64AddressArray(length int) [ExtendedUniqueIdentifier64SegmentCount]*AddressDivision {
//	return [ExtendedUniqueIdentifier64SegmentCount]*AddressDivision{}
//}

func (creator *MACAddressCreator) createMACSegment(value MACSegInt) *AddressDivision {
	return NewMACSegment(value).ToAddressDivision()
}

func (creator *MACAddressCreator) createMACRangeSegment(lower, upper MACSegInt) *AddressDivision {
	return NewMACRangeSegment(lower, upper).ToAddressDivision()
}

func (creator *MACAddressCreator) createMACPrefixSegment(value MACSegInt, segmentPrefixLength PrefixLen) *AddressDivision {
	return NewMACSegment(value).ToAddressDivision()
}

func (creator *MACAddressCreator) createMACRangePrefixSegment(lower, upper MACSegInt, segmentPrefixLength PrefixLen) *AddressDivision {
	return NewMACRangeSegment(lower, upper).ToAddressDivision()
}

//func (creator *MACAddressCreator) createPrefixedSectionInternalSingle(segments []*AddressDivision, prefixLength PrefixLen) *AddressSection {
//	//return NewMACAddress(section.ToMACAddressSection()).ToAddress()
//	//\
//	return nil
//}

//func (creator *MACAddressCreator) createZonedAddressInternal(section *AddressSection, zone Zone) *Address {
//	return creator.createAddressInternal(section)
//}

func (creator *MACAddressCreator) createSectionInternal(segments []*AddressDivision) *AddressSection {
	return newMACAddressSectionParsed(segments).ToAddressSection()
}

func (creator *MACAddressCreator) createAddressInternal(section *AddressSection, originator HostIdentifierString) *Address {
	res := NewMACAddress(section.ToMACAddressSection()).ToAddress()
	if originator != nil {
		res.cache.fromString = unsafe.Pointer(originator.(*MACAddressString))
	}
	return res
}

func (creator *MACAddressCreator) createAddressInternalFromSection(section *MACAddressSection, originator HostIdentifierString) *MACAddress {
	res := NewMACAddress(section)
	if originator != nil {
		res.cache.fromString = unsafe.Pointer(originator.(*MACAddressString))
	}
	return res
}
