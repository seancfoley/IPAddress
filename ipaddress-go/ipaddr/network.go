package ipaddr

type AddressNetwork interface {
	GetAddressCreator() AddressCreator
}

type AddressCreator interface {
	//TODO
	ParsedAddressCreator
}

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
	//TODO
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

func (creator *IPv6AddressCreator) createSegment(lower, upper SegInt, segmentPrefixLength PrefixLen) *AddressDivision {
	return creator.createIPv6RangePrefixSegment(lower, upper, segmentPrefixLength)
}

func (creator *IPv6AddressCreator) createSegmentInternal(value SegInt, segmentPrefixLength PrefixLen, addressStr string,
	originalVal SegInt, isStandardString bool, lowerStringStartIndex, lowerStringEndIndex int) *AddressDivision {
	result := creator.createIPv6PrefixSegment(value, segmentPrefixLength)
	//TODO store string slices
	return result
}

func (creator *IPv6AddressCreator) createRangeSegmentInternal(lower, upper SegInt, segmentPrefixLength PrefixLen, addressStr string,
	originalLower, originalUpper SegInt, isStandardString, isStandardRangeString bool,
	lowerStringStartIndex, lowerStringEndIndex, upperStringEndIndex int) *AddressDivision {
	result := creator.createIPv6RangePrefixSegment(lower, upper, segmentPrefixLength)
	//TODO store string slices
	return result
}

func (creator *IPv6AddressCreator) createPrefixSegment(value SegInt, segmentPrefixLength PrefixLen) *AddressDivision {
	return creator.createIPv6PrefixSegment(value, segmentPrefixLength)
}

func (creator *IPv6AddressCreator) createSegmentArray(length int) []*AddressDivision { //TODO remove this since identical for all seg types
	return make([]*AddressDivision, length)
}

func (creator *IPv6AddressCreator) createIPv6Segment(value uint16) *AddressDivision {
	return NewIPv6Segment(value).ToAddressDivision()
}

func (creator *IPv6AddressCreator) createIPv6PrefixSegment(value uint16, segmentPrefixLength PrefixLen) *AddressDivision {
	return NewIPv6PrefixSegment(value, segmentPrefixLength).ToAddressDivision()
}

func (creator *IPv6AddressCreator) createIPv6RangeSegment(lower, upper uint16) *AddressDivision {
	return NewIPv6RangeSegment(lower, upper).ToAddressDivision()
}

func (creator *IPv6AddressCreator) createIPv6RangePrefixSegment(lower, upper uint16, segmentPrefixLength PrefixLen) *AddressDivision {
	return NewIPv6RangePrefixSegment(lower, upper, segmentPrefixLength).ToAddressDivision()
}

func (creator *IPv6AddressCreator) createAddressInternalFromBytes(bytes []byte, zone string) *IPAddress {
	//TODO create address (either use "New" or create the Address and call ToIPAddress)
	return nil
}

func (creator *IPv6AddressCreator) createAddressInternalFromSection(
	section *IPAddressSection, zone Zone, originator HostIdentifierString) *IPAddress {
	//TODO create address
	return nil
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

//TODO the methods in the creator interface that use the exact type, nammely uint8, will be public.  Those using SegInt will remain private
type IPv4AddressCreator struct {
	//TODO
}

func (creator *IPv4AddressCreator) createSegment(lower, upper SegInt, segmentPrefixLength PrefixLen) *AddressDivision {
	return creator.createIPv4RangePrefixSegment(uint8(lower), uint8(upper), segmentPrefixLength)
}

func (creator *IPv4AddressCreator) createSegmentInternal(value SegInt, segmentPrefixLength PrefixLen, addressStr string,
	originalVal SegInt, isStandardString bool, lowerStringStartIndex, lowerStringEndIndex int) *AddressDivision {
	result := creator.createIPv4PrefixSegment(uint8(value), segmentPrefixLength)
	//TODO store string slices
	return result
}

func (creator *IPv4AddressCreator) createRangeSegmentInternal(lower, upper SegInt, segmentPrefixLength PrefixLen, addressStr string,
	originalLower, originalUpper SegInt, isStandardString, isStandardRangeString bool,
	lowerStringStartIndex, lowerStringEndIndex, upperStringEndIndex int) *AddressDivision {
	result := creator.createIPv4RangePrefixSegment(uint8(lower), uint8(upper), segmentPrefixLength)
	//TODO store string slices
	return result
}

func (creator *IPv4AddressCreator) createPrefixSegment(value SegInt, segmentPrefixLength PrefixLen) *AddressDivision {
	return creator.createIPv4PrefixSegment(uint8(value), segmentPrefixLength)
}

func (creator *IPv4AddressCreator) createSegmentArray(length int) []*AddressDivision {
	return make([]*AddressDivision, length)
}

func (creator *IPv4AddressCreator) createIPv4Segment(value uint8) *AddressDivision {
	return NewIPv4Segment(value).ToAddressDivision()
}

func (creator *IPv4AddressCreator) createIPv4RangeSegment(lower, upper uint8) *AddressDivision {
	return NewIPv4RangeSegment(lower, upper).ToAddressDivision()
}

func (creator *IPv4AddressCreator) createIPv4PrefixSegment(value uint8, segmentPrefixLength PrefixLen) *AddressDivision {
	return NewIPv4PrefixSegment(value, segmentPrefixLength).ToAddressDivision()
}

func (creator *IPv4AddressCreator) createIPv4RangePrefixSegment(lower, upper uint8, segmentPrefixLength PrefixLen) *AddressDivision {
	return NewIPv4RangePrefixSegment(lower, upper, segmentPrefixLength).ToAddressDivision()
}

func (creator *IPv4AddressCreator) createAddressInternalFromBytes(bytes []byte, zone string) *IPAddress {
	//TODO create address, call ToIPAddress
	return nil
}

func (creator *IPv4AddressCreator) createAddressInternalFromSection(
	section *IPAddressSection, zone Zone, originator HostIdentifierString) *IPAddress {
	//TODO create address
	return nil
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

func (creator *MACAddressCreator) createSegment(lower, upper SegInt, segmentPrefixLength PrefixLen) *AddressDivision {
	return creator.createMACRangePrefixSegment(uint8(lower), uint8(upper), segmentPrefixLength)
}

func (creator *MACAddressCreator) createSegmentInternal(value SegInt, segmentPrefixLength PrefixLen, addressStr string,
	originalVal SegInt, isStandardString bool, lowerStringStartIndex, lowerStringEndIndex int) *AddressDivision {
	result := creator.createMACPrefixSegment(uint8(value), segmentPrefixLength)
	//TODO store string slices
	return result
}

func (creator *MACAddressCreator) createRangeSegmentInternal(lower, upper SegInt, segmentPrefixLength PrefixLen, addressStr string,
	originalLower, originalUpper SegInt, isStandardString, isStandardRangeString bool,
	lowerStringStartIndex, lowerStringEndIndex, upperStringEndIndex int) *AddressDivision {
	result := creator.createMACRangePrefixSegment(uint8(lower), uint8(upper), segmentPrefixLength)
	//TODO store string slices
	return result
}

func (creator *MACAddressCreator) createPrefixSegment(value SegInt, segmentPrefixLength PrefixLen) *AddressDivision {
	return creator.createMACPrefixSegment(uint8(value), segmentPrefixLength)
}

func (M MACAddressCreator) createSegmentArray(length int) []*AddressDivision {
	return make([]*AddressDivision, length)
}

func (creator *MACAddressCreator) createMACSegment(value uint8) *AddressDivision {
	return NewMACSegment(value).ToAddressDivision()
}

func (creator *MACAddressCreator) createMACRangeSegment(lower, upper uint8) *AddressDivision {
	return NewMACRangeSegment(lower, upper).ToAddressDivision()
}

func (creator *MACAddressCreator) createMACPrefixSegment(value uint8, segmentPrefixLength PrefixLen) *AddressDivision {
	return NewMACSegment(value).ToAddressDivision()
}

func (creator *MACAddressCreator) createMACRangePrefixSegment(lower, upper uint8, segmentPrefixLength PrefixLen) *AddressDivision {
	return NewMACRangeSegment(lower, upper).ToAddressDivision()
}
