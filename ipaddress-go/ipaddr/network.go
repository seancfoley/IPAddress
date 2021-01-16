package ipaddr

type AddressNetwork interface {
	GetAddressCreator() AddressCreator
}

//TODO I think I probably want to get rid of the address creators, I realize now they make little sense
//But I will still have caching.

// IPAddressNetwork represents the full collection of addresses for a given address type and/or version.
type AddressCreator interface {
	//TODO
	ParsedAddressCreator
}

// IPAddressNetwork represents the full collection of addresses for a given IP version.
// You can create your own network objects satisfying this interface, allowing you to create your own address types,
// or to provide your own IP address conversion between IPv4 and IPv6.
// When creating your own network, for IP addresses to be associated with it, you must:
// - create each address using the creator methods in the instance creator returned from GetIPAddressCreator(),
//	which will associate each address with said network when creating the address
// - return the network object from the IPAddressStringParameters implementation used for parsing an IPAddressString,
//	which will associate the parsed address with the network
// Addresses deprived from an existing address, using masking, iterating, or any other address manipulation,
// will be associated with the same network as the original address, by using the network's address creator instance.
// Addresses created by instantiation not through the network's creator instance will be associated with the default network.
type IPAddressNetwork interface {
	AddressNetwork

	GetIPAddressCreator() IPAddressCreator

	GetLoopback() *IPAddress

	GetNetworkIPAddress(PrefixLen) *IPAddress

	GetNetworkMask(PrefixLen, bool) *IPAddress
}

type IPAddressCreator interface {
	AddressCreator

	ParsedIPAddressCreator

	createAddressInternalFromBytes(bytes []byte, zone string) *IPAddress

	//createPrefixedSectionInternal(segments []*AddressDivision, prefixLength PrefixLen, singleOnly bool)
	//TODO
}

//
//
//
//
//

type IPv6AddressNetwork struct {
	creator IPv6AddressCreator
}

func (network *IPv6AddressNetwork) GetIPv6AddressCreator() *IPv6AddressCreator {
	return &network.creator
}

func (network *IPv6AddressNetwork) GetIPAddressCreator() IPAddressCreator {
	return network.GetIPv6AddressCreator()
}

func (network *IPv6AddressNetwork) GetAddressCreator() AddressCreator {
	return network.GetIPv6AddressCreator()
}

func (network *IPv6AddressNetwork) GetLoopback() *IPAddress {
	//TODO use the creator
	return nil
}

func (network *IPv6AddressNetwork) GetNetworkIPAddress(prefLen PrefixLen) *IPAddress {
	return network.GetNetworkIPv6Address(prefLen).ToIPAddress()
}

func (network *IPv6AddressNetwork) GetNetworkMask(prefLen PrefixLen, withPrefixLength bool) *IPAddress {
	return network.GetNetworkIPv6Mask(prefLen, withPrefixLength).ToIPAddress()
}

func (network *IPv6AddressNetwork) GetNetworkIPv6Address(prefLen PrefixLen) *IPv6Address {
	//TODO
	return nil
}

func (network *IPv6AddressNetwork) GetNetworkIPv6Mask(prefLen PrefixLen, withPrefixLength bool) *IPv6Address {
	//TODO
	return nil
}

var _ IPAddressNetwork = &IPv6AddressNetwork{}

var DefaultIPv6Network IPv6AddressNetwork

//TODO the methods in the creator interface that use the exact type, nammely uint16, will be public.  Those using SegInt will remain private
type IPv6AddressCreator struct {
	//TODO
}

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

//func (creator *IPv6AddressCreator) createPrefixedSectionInternal(segments []*AddressDivision, prefixLength PrefixLen) *IPAddressSection {
//	sec, _ := newIPv6AddressSectionSingle(segments, 0, prefixLength, false)
//	return sec.ToIPAddressSection()
//}

func (creator *IPv6AddressCreator) createPrefixedSectionInternal(segments []*AddressDivision, prefixLength PrefixLen, singleOnly bool) *IPAddressSection {
	sec, _ := newIPv6AddressSectionSingle(segments, 0, prefixLength, singleOnly)
	return sec.ToIPAddressSection()
}

func (creator *IPv6AddressCreator) createSectionInternal(segment []*AddressDivision) *IPAddressSection {
	//TODO
	//return NewIPv6RangePrefixSegment(lower, upper, segmentPrefixLength).ToAddressDivision()
	return nil
}

func (creator *IPv6AddressCreator) createAddressInternalFromBytes(bytes []byte, zone string) *IPAddress {
	//TODO create address (either use "New" or create the Address and call ToIPAddress)
	return nil
}

func (creator *IPv6AddressCreator) createAddressInternalFromSection(
	section *IPAddressSection, zone Zone, originator HostIdentifierString) *IPAddress {
	return NewIPv6AddressZoned(section.ToIPv6AddressSection(), zone).ToIPAddress()
}

//
//
//
//
//

type IPv4AddressNetwork struct {
	creator IPv4AddressCreator
	//TODO
}

func (network *IPv4AddressNetwork) GetIPv4AddressCreator() *IPv4AddressCreator {
	return &network.creator
}

func (network *IPv4AddressNetwork) GetIPAddressCreator() IPAddressCreator {
	return network.GetIPv4AddressCreator()
}

func (network *IPv4AddressNetwork) GetAddressCreator() AddressCreator {
	return network.GetIPv4AddressCreator()
}

func (network *IPv4AddressNetwork) GetLoopback() *IPAddress {
	//TODO
	return nil
}

func (network *IPv4AddressNetwork) GetNetworkIPAddress(prefLen PrefixLen) *IPAddress {
	return network.GetNetworkIPv4Address(prefLen).ToIPAddress()
}

func (network *IPv4AddressNetwork) GetNetworkMask(prefLen PrefixLen, withPrefixLength bool) *IPAddress {
	return network.GetNetworkIPv4Mask(prefLen, withPrefixLength).ToIPAddress()
}

func (network *IPv4AddressNetwork) GetNetworkIPv4Address(prefLen PrefixLen) *IPv4Address {
	//TODO
	return nil
}

func (network *IPv4AddressNetwork) GetNetworkIPv4Mask(prefLen PrefixLen, withPrefixLength bool) *IPv4Address {
	//TODO
	return nil
}

var _ IPAddressNetwork = &IPv4AddressNetwork{}

var DefaultIPv4Network IPv4AddressNetwork

//TODO creators: the methods in the creator interface that use the exact type, nammely IPv4SegInt, will be public.
// Those using SegInt will remain private (these are the ones we use after parsing IIRC)
// "Internal" will remain private, for same reasons as in Java, so we can avoid extra obj creation.
// Private methods will likely defer to base types like AddressDivision and AddressSection
// Public methods will create IPv4 types like IPv4Segment and IPv4AddressSection

type IPv4AddressCreator struct {
	//TODO
}

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

func (creator *IPv4AddressCreator) createSectionInternal(segment []*AddressDivision) *IPAddressSection {
	//TODO createSectionInternal
	//return NewIPv6RangePrefixSegment(lower, upper, segmentPrefixLength).ToAddressDivision()
	return nil
}

func (creator *IPv4AddressCreator) createAddressInternalFromBytes(bytes []byte, zone string) *IPAddress {
	//TODO create address, call ToIPAddress
	return nil
}

func (creator *IPv4AddressCreator) createAddressInternalFromSection(
	section *IPAddressSection, zone Zone, originator HostIdentifierString) *IPAddress {
	return NewIPv4Address(section.ToIPv4AddressSection()).ToIPAddress()
}

//
//
//
//
//

type MACAddressNetwork struct {
	creator MACAddressCreator
}

func (network *MACAddressNetwork) GetMACAddressCreator() *MACAddressCreator {
	return &network.creator
}

func (network *MACAddressNetwork) GetAddressCreator() AddressCreator {
	return network.GetMACAddressCreator()
}

var _ AddressNetwork = &MACAddressNetwork{}

var DefaultMACNetwork MACAddressNetwork

type MACAddressCreator struct {
	//TODO
}

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
