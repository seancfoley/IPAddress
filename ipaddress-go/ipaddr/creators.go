package ipaddr

import "unsafe"

type AddressSegmentCreator interface {
	createSegment(lower, upper SegInt, segmentPrefixLength PrefixLen) *AddressDivision

	createSegmentInternal(value SegInt, segmentPrefixLength PrefixLen, addressStr string,
		originalVal SegInt, isStandardString bool, lowerStringStartIndex, lowerStringEndIndex int) *AddressDivision

	createRangeSegmentInternal(lower, upper SegInt, segmentPrefixLength PrefixLen, addressStr string,
		originalLower, originalUpper SegInt, isStandardString, isStandardRangeString bool,
		lowerStringStartIndex, lowerStringEndIndex, upperStringEndIndex int) *AddressDivision

	createPrefixSegment(value SegInt, segmentPrefixLength PrefixLen) *AddressDivision

	getMaxValuePerSegment() SegInt
}

type ParsedAddressCreator interface {
	AddressSegmentCreator

	createSectionInternal(segments []*AddressDivision) *AddressSection

	createAddressInternal(section *AddressSection, identifier HostIdentifierString) *Address
}

type ParsedIPAddressCreator interface {
	createPrefixedSectionInternalSingle(segments []*AddressDivision, prefixLength PrefixLen) *IPAddressSection

	createPrefixedSectionInternal(segments []*AddressDivision, prefixLength PrefixLen) *IPAddressSection

	createAddressInternalFromSection(*IPAddressSection, Zone, HostIdentifierString) *IPAddress
}

type IPAddressCreator interface {
	ParsedAddressCreator

	ParsedIPAddressCreator

	createAddressInternalFromBytes(bytes []byte, zone string) *IPAddress
}

// TODO almost all of this should become private.
// We've created some duplication, in some cases we may use functors for creation of segments.
// IN fact, whenever you are cesting from an existing section or segment, you can use a derive function, not a creator instance.
// We also have the addrType available everywhere and this too allows you to avoid providing a functor or a creator as a callback for creating anything.
// So, typically we want to choose:
// 1. derive from existing using derive functions in sections or derive methods in segments/divisions.  Use checkIdentity in addresses.
// 2. when miving up the hierarchy, use addr type and or ToAddressSection() and the like
// 3. We use segProducer functors in a few key spots: getSubnetSegments, getOredSegments, assign prefix in section creator, iterator for ranges.
// 4. We use creators in a few places.  We use segment creators in increment functions, createSegments and createSegmentsUint64 and toSegments,
//
// Maybe we should consolidate to either functors or creator instances.  Is there a benefit to centralizing with creator interfaces?  Are functors too slow?
// Both serve the same purpose.

type IPv6AddressCreator struct{}

func (creator *IPv6AddressCreator) getMaxValuePerSegment() SegInt {
	return IPv6MaxValuePerSegment
}

func (creator *IPv6AddressCreator) createSegment(lower, upper SegInt, segmentPrefixLength PrefixLen) *AddressDivision {
	return NewIPv6RangePrefixSegment(IPv6SegInt(lower), IPv6SegInt(upper), segmentPrefixLength).ToAddressDivision()
}

func (creator *IPv6AddressCreator) createSegmentInternal(value SegInt, segmentPrefixLength PrefixLen, addressStr string,
	originalVal SegInt, isStandardString bool, lowerStringStartIndex, lowerStringEndIndex int) *AddressDivision {
	result := NewIPv6PrefixSegment(IPv6SegInt(value), segmentPrefixLength).ToAddressDivision()
	//result := creator.createIPv6PrefixSegment(ToIPv6SegInt(value), segmentPrefixLength)
	//TODO store string slices, the ones from the parsing
	return result
}

func (creator *IPv6AddressCreator) createRangeSegmentInternal(lower, upper SegInt, segmentPrefixLength PrefixLen, addressStr string,
	originalLower, originalUpper SegInt, isStandardString, isStandardRangeString bool,
	lowerStringStartIndex, lowerStringEndIndex, upperStringEndIndex int) *AddressDivision {
	result := NewIPv6RangePrefixSegment(IPv6SegInt(lower), IPv6SegInt(upper), segmentPrefixLength).ToAddressDivision()
	//TODO store string slices, the ones from the parsing
	return result
}

func (creator *IPv6AddressCreator) createPrefixSegment(value SegInt, segmentPrefixLength PrefixLen) *AddressDivision {
	return NewIPv6PrefixSegment(IPv6SegInt(value), segmentPrefixLength).ToAddressDivision()
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
	// only used by the loopback creator at the moment
	return nil
}

func (creator *IPv6AddressCreator) createAddressInternalFromSection(section *IPAddressSection, zone Zone, originator HostIdentifierString) *IPAddress {
	res := NewIPv6AddressZoned(section.ToIPv6AddressSection(), zone).ToIPAddress()
	if originator != nil {
		res.cache.fromString = unsafe.Pointer(originator.(*IPAddressString))
	}
	return res
}

func (creator *IPv6AddressCreator) createAddressInternal(section *AddressSection, originator HostIdentifierString) *Address {
	res := NewIPv6Address(section.ToIPv6AddressSection()).ToAddress()
	if originator != nil {
		res.cache.fromString = unsafe.Pointer(originator.(*IPAddressString))
	}
	return res
}

type IPv4AddressCreator struct{}

func (creator *IPv4AddressCreator) getMaxValuePerSegment() SegInt {
	return IPv4MaxValuePerSegment
}

func (creator *IPv4AddressCreator) createSegment(lower, upper SegInt, segmentPrefixLength PrefixLen) *AddressDivision {
	return NewIPv4RangePrefixSegment(IPv4SegInt(lower), IPv4SegInt(upper), segmentPrefixLength).ToAddressDivision()
	//return creator.createIPv4RangePrefixSegment(IPv4SegInt(lower), IPv4SegInt(upper), segmentPrefixLength)
}

func (creator *IPv4AddressCreator) createSegmentInternal(value SegInt, segmentPrefixLength PrefixLen, addressStr string,
	originalVal SegInt, isStandardString bool, lowerStringStartIndex, lowerStringEndIndex int) *AddressDivision {
	result := NewIPv4PrefixSegment(IPv4SegInt(value), segmentPrefixLength).ToAddressDivision()
	//result := creator.createIPv4PrefixSegment(IPv4SegInt(value), segmentPrefixLength)
	//TODO store string slices, the ones from the parsing
	return result
}

func (creator *IPv4AddressCreator) createRangeSegmentInternal(lower, upper SegInt, segmentPrefixLength PrefixLen, addressStr string,
	originalLower, originalUpper SegInt, isStandardString, isStandardRangeString bool,
	lowerStringStartIndex, lowerStringEndIndex, upperStringEndIndex int) *AddressDivision {
	result := NewIPv4RangePrefixSegment(IPv4SegInt(lower), IPv4SegInt(upper), segmentPrefixLength).ToAddressDivision()
	//result := creator.createIPv4RangePrefixSegment(ToIPv4SegInt(lower), ToIPv4SegInt(upper), segmentPrefixLength)
	//TODO store string slices, the ones from the parsing
	return result
}

func (creator *IPv4AddressCreator) createPrefixSegment(value SegInt, segmentPrefixLength PrefixLen) *AddressDivision {
	return NewIPv4PrefixSegment(IPv4SegInt(value), segmentPrefixLength).ToAddressDivision()
	//return creator.createIPv4PrefixSegment(ToIPv4SegInt(value), segmentPrefixLength)
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
	//TODO create address, call ToIPAddress (this is called from newLoopbackCreator)
	return nil
}

func (creator *IPv4AddressCreator) createAddressInternalFromSection(section *IPAddressSection, zone Zone, originator HostIdentifierString) *IPAddress {
	res := NewIPv4Address(section.ToIPv4AddressSection()).ToIPAddress()
	if originator != nil {
		res.cache.fromString = unsafe.Pointer(originator.(*IPAddressString))
	}
	return res
}

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
	return NewMACRangeSegment(MACSegInt(lower), MACSegInt(upper)).ToAddressDivision()
	//return creator.createMACRangePrefixSegment(ToMACSegInt(lower), ToMACSegInt(upper), segmentPrefixLength)
}

func (creator *MACAddressCreator) createSegmentInternal(value SegInt, segmentPrefixLength PrefixLen, addressStr string,
	originalVal SegInt, isStandardString bool, lowerStringStartIndex, lowerStringEndIndex int) *AddressDivision {
	result := NewMACSegment(MACSegInt(value)).ToAddressDivision()
	//result := creator.createMACPrefixSegment(ToMACSegInt(value), segmentPrefixLength)
	//TODO store string slices, the ones from the parsing
	return result
}

func (creator *MACAddressCreator) createRangeSegmentInternal(lower, upper SegInt, segmentPrefixLength PrefixLen, addressStr string,
	originalLower, originalUpper SegInt, isStandardString, isStandardRangeString bool,
	lowerStringStartIndex, lowerStringEndIndex, upperStringEndIndex int) *AddressDivision {
	result := NewMACRangeSegment(MACSegInt(lower), MACSegInt(upper)).ToAddressDivision()
	//result := creator.createMACRangePrefixSegment(ToMACSegInt(lower), ToMACSegInt(upper), segmentPrefixLength)
	//TODO store string slices, the ones from the parsing
	return result
}

func (creator *MACAddressCreator) createPrefixSegment(value SegInt, segmentPrefixLength PrefixLen) *AddressDivision {
	return NewMACSegment(MACSegInt(value)).ToAddressDivision()
	//return creator.createMACPrefixSegment(ToMACSegInt(value), segmentPrefixLength)
}

//func (creator *MACAddressCreator) createMACSegment(value MACSegInt) *AddressDivision {
//	return NewMACSegment(value).ToAddressDivision()
//}
//
func (creator *MACAddressCreator) createMACRangeSegment(lower, upper SegInt) *AddressDivision {
	return NewMACRangeSegment(MACSegInt(lower), MACSegInt(upper)).ToAddressDivision()
}

//
//func (creator *MACAddressCreator) createMACPrefixSegment(value MACSegInt, segmentPrefixLength PrefixLen) *AddressDivision {
//	return NewMACSegment(value).ToAddressDivision()
//}
//
//func (creator *MACAddressCreator) createMACRangePrefixSegment(lower, upper MACSegInt, segmentPrefixLength PrefixLen) *AddressDivision {
//	return NewMACRangeSegment(lower, upper).ToAddressDivision()
//}

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
