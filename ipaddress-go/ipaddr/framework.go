package ipaddr

import (
	"fmt"
	"math/big"
	"net"
)

type AddressItem interface {
	GetValue() *big.Int
	GetUpperValue() *big.Int

	CopyBytes(bytes []byte) []byte
	CopyUpperBytes(bytes []byte) []byte
	GetBytes() []byte // TODO maybe change to Bytes() and UpperBytes() to be consistent with https://pkg.go.dev/bytes#Buffer.Bytes and https://pkg.go.dev/reflect#Value.Bytes and https://pkg.go.dev/math/big#Int.Bytes
	GetUpperBytes() []byte

	// GetCount provides the number of address items represented by this AddressItem, for example the subnet size for IP addresses
	GetCount() *big.Int

	// IsMultiple returns whether the count is larger than 1
	IsMultiple() bool

	GetByteCount() int
	GetBitCount() BitCount

	IsFullRange() bool
	IncludesZero() bool
	IncludesMax() bool
	IsZero() bool
	IsMax() bool

	// ContainsPrefixBlock returns whether the values of this item contains the prefix block for the given prefix length.
	// If there are multiple possible prefixes in this item for the given prefix length, then this returns
	// whether this item contains the prefix block for each and every one of those prefixes.
	ContainsPrefixBlock(BitCount) bool

	// ContainsSinglePrefixBlock returns whether the values of this series contains a single prefix block for the given prefix length.
	// This means there is only one prefix of the given length in this item, and this item contains the prefix block for that given prefix.
	ContainsSinglePrefixBlock(BitCount) bool

	// GetPrefixLenForSingleBlock returns a prefix length for which there is only one prefix of that length in this item,
	// and the range of this item matches the block of all values for that prefix.
	// If the range can be dictated this way, then this method returns the same value as GetMinPrefixLenForBlock.
	// If no such prefix length exists, returns nil.
	// If this item represents a single value, this returns the bit count.
	GetPrefixLenForSingleBlock() PrefixLen

	// GetMinPrefixLenForBlock returns the smallest prefix length possible such that this item includes the block of all values for that prefix length.
	// If there are multiple possible prefixes in this item for the given prefix length,
	// this item contains the prefix block for each and every one of those prefixes.
	// If the entire range can be dictated this way, then this method returns the same value as {@link #GetPrefixLenForSingleBlock()}.
	// Otherwise, this method will return the minimal possible prefix that can be paired with this address, while {@link #GetPrefixLenForSingleBlock()} will return null.
	// In cases where the final bit is constant so there is no such block, this returns the bit count.
	GetMinPrefixLenForBlock() BitCount

	// The count of the number of distinct values within the prefix part of the range of values for this item
	GetPrefixCountLen(BitCount) *big.Int

	// Any address item is comparable to any other
	Compare(item AddressItem) int

	fmt.Stringer
}

type AddressComponent interface { //AddressSegment and above, AddressSegmentSeries and above
	TestBit(BitCount) bool
	IsOneBit(BitCount) bool

	ToHexString(bool) (string, IncompatibleAddressError)
	ToNormalizedString() string
}

type ipAddressRange interface {
	GetLowerIPAddress() *IPAddress
	GetUpperIPAddress() *IPAddress

	CopyNetIP(bytes net.IP) net.IP
	CopyUpperNetIP(bytes net.IP) net.IP

	GetNetIP() net.IP
	GetUpperNetIP() net.IP
}

type IPAddressRange interface { //IPAddress and above, IPAddressSeqRange and above
	ipAddressRange

	IsSequential() bool
}

// StandardDivGroupingType represents any standard division grouping (division groupings or address sections where all divisions are 64 bits or less)
// including AddressSection, IPAddressSection, IPv4AddressSection, IPv6AddressSection, MACAddressSection, and AddressDivisionGrouping
type StandardDivGroupingType interface {
	AddressDivisionSeries

	// IsZeroGrouping returns true if the division grouping was originally created as a zero-valued section or grouping (eg IPv4AddressSection{})
	// Such a grouping has no divisions or segments, and is convertible to any type or version, whether IPv6, IPv4, MAC, etc
	IsZeroGrouping() bool

	CompareSize(StandardDivGroupingType) int

	ToDivGrouping() *AddressDivisionGrouping
}

var _, _ StandardDivGroupingType = &AddressDivisionGrouping{},
	&IPv6v4MixedAddressGrouping{}

// AddressDivisionSeries serves as a common interface to all division groupings (including large) and addresses
type AddressDivisionSeries interface {
	AddressItem

	GetDivisionCount() int

	GetPrefixCount() *big.Int
	GetBlockCount(divisionCount int) *big.Int
	GetSequentialBlockIndex() int
	GetSequentialBlockCount() *big.Int

	IsSequential() bool

	IsPrefixBlock() bool
	IsSinglePrefixBlock() bool
	IsPrefixed() bool
	GetPrefixLen() PrefixLen

	GetGenericDivision(index int) DivisionType // useful for comparisons
}

type AddressSegmentSeries interface { // Address and above, AddressSection and above, IPAddressSegmentSeries, ExtendedIPSegmentSeries
	AddressComponent

	AddressDivisionSeries

	GetMaxSegmentValue() SegInt
	GetSegmentCount() int
	GetBitsPerSegment() BitCount
	GetBytesPerSegment() int

	ToCanonicalString() string
	ToCompressedString() string

	ToBinaryString(with0bPrefix bool) (string, IncompatibleAddressError)
	ToOctalString(withPrefix bool) (string, IncompatibleAddressError)

	GetSegmentStrings() []string

	GetGenericSegment(index int) AddressSegmentType
}

var _, _ AddressSegmentSeries = &Address{}, &AddressSection{}

type IPAddressSegmentSeries interface { // IPAddress and above, IPAddressSection and above, ExtendedIPSegmentSeries

	//TODO now you can add ToIPv6(), ToIPv4(), IsIPv6, IsIPv4

	AddressSegmentSeries

	IncludesZeroHost() bool
	IncludesZeroHostLen(prefLen BitCount) bool
	IncludesMaxHost() bool
	IncludesMaxHostLen(prefLen BitCount) bool
	IsZeroHost() bool
	IsZeroHostLen(BitCount) bool
	IsMaxHost() bool
	IsMaxHostLen(BitCount) bool
	IsSingleNetwork() bool

	GetIPVersion() IPVersion

	GetBlockMaskPrefixLen(network bool) PrefixLen

	GetLeadingBitCount(ones bool) BitCount
	GetTrailingBitCount(ones bool) BitCount

	ToFullString() string
	ToPrefixLenString() string
	ToSubnetString() string
	ToNormalizedWildcardString() string
	ToCanonicalWildcardString() string
	ToCompressedWildcardString() string
	ToSegmentedBinaryString() string
	ToSQLWildcardString() string
	ToReverseDNSString() (string, IncompatibleAddressError)
}

var _, _ IPAddressSegmentSeries = &IPAddress{}, &IPAddressSection{}

type IPv6AddressSegmentSeries interface { //TODO now you can add ToIP(), IsIP(), in fact maybe to IPAddressSegmentSeries
	IPAddressSegmentSeries

	// GetTrailingSection returns an ending subsection of the full address section
	GetTrailingSection(index int) *IPv6AddressSection

	// GetSubSection returns a subsection of the full address section
	GetSubSection(index, endIndex int) *IPv6AddressSection

	GetNetworkSection() *IPv6AddressSection
	GetHostSection() *IPv6AddressSection
	GetNetworkSectionLen(BitCount) *IPv6AddressSection
	GetHostSectionLen(BitCount) *IPv6AddressSection

	GetSegments() []*IPv6AddressSegment
	CopySegments(segs []*IPv6AddressSegment) (count int)
	CopySubSegments(start, end int, segs []*IPv6AddressSegment) (count int)

	GetSegment(index int) *IPv6AddressSegment
}

var _, _, _ IPv6AddressSegmentSeries = &IPv6Address{},
	&IPv6AddressSection{},
	&EmbeddedIPv6AddressSection{}

type IPv4AddressSegmentSeries interface { //TODO now you can add ToIP(), IsIP(), in fact maybe to IPAddressSegmentSeries
	IPAddressSegmentSeries

	// GetTrailingSection returns an ending subsection of the full address section
	GetTrailingSection(index int) *IPv4AddressSection

	// GetSubSection returns a subsection of the full address section
	GetSubSection(index, endIndex int) *IPv4AddressSection

	GetNetworkSection() *IPv4AddressSection
	GetHostSection() *IPv4AddressSection
	GetNetworkSectionLen(BitCount) *IPv4AddressSection
	GetHostSectionLen(BitCount) *IPv4AddressSection

	GetSegments() []*IPv4AddressSegment
	CopySegments(segs []*IPv4AddressSegment) (count int)
	CopySubSegments(start, end int, segs []*IPv4AddressSegment) (count int)

	GetSegment(index int) *IPv4AddressSegment
}

var _, _ IPv4AddressSegmentSeries = &IPv4Address{}, &IPv4AddressSection{}

type MACAddressSegmentSeries interface {
	AddressSegmentSeries

	// GetTrailingSection returns an ending subsection of the full address section
	GetTrailingSection(index int) *MACAddressSection

	// GetSubSection returns a subsection of the full address section
	GetSubSection(index, endIndex int) *MACAddressSection

	GetSegments() []*MACAddressSegment
	CopySegments(segs []*MACAddressSegment) (count int)
	CopySubSegments(start, end int, segs []*MACAddressSegment) (count int)

	GetSegment(index int) *MACAddressSegment
}

var _, _ MACAddressSegmentSeries = &MACAddress{}, &MACAddressSection{}

// AddressSectionType represents any address section
// that can be converted to/from the base type AddressSection,
// including AddressSection, IPAddressSection, IPv4AddressSection, IPv6AddressSection, and MACAddressSection
type AddressSectionType interface {
	StandardDivGroupingType

	Equal(AddressSectionType) bool
	Contains(AddressSectionType) bool

	ToSectionBase() *AddressSection
}

//Note: if we had an IPAddressSectionType we could add Wrap() WrappedIPAddressSection to it, but I guess not much else

var _, _, _, _, _ AddressSectionType = &AddressSection{},
	&IPAddressSection{},
	&IPv4AddressSection{},
	&IPv6AddressSection{},
	&MACAddressSection{}

// AddressType represents any address, all of which can be represented by the base type Address.
// This includes IPAddress, IPv4Address, IPv6Address, and MACAddress.
// It can be useful as a parameter for functions to take any address type, while inside the function you can convert to *Address using ToAddress()
type AddressType interface {
	AddressSegmentSeries

	Equal(AddressType) bool
	Contains(AddressType) bool
	CompareSize(AddressType) int

	PrefixEqual(AddressType) bool
	PrefixContains(AddressType) bool

	ToAddress() *Address
}

var _, _ AddressType = &Address{}, &MACAddress{}

// IPAddressType represents any IP address, all of which can be represented by the base type IPAddress.
// This includes IPv4Address, and IPv6Address.
type IPAddressType interface {
	AddressType
	ipAddressRange

	Wrap() WrappedIPAddress
	ToIPAddress() *IPAddress
	ToAddressString() *IPAddressString
}

var _, _, _ IPAddressType = &IPAddress{},
	&IPv4Address{},
	&IPv6Address{}

type IPAddressSeqRangeType interface {
	AddressItem
	IPAddressRange

	CompareSize(IPAddressSeqRangeType) int
	ContainsRange(IPAddressSeqRangeType) bool
	Contains(IPAddressType) bool
	ToIPAddressSeqRange() *IPAddressSeqRange
}

var _, _, _ IPAddressSeqRangeType = &IPAddressSeqRange{},
	&IPv4AddressSeqRange{},
	&IPv6AddressSeqRange{}

// HostIdentifierString represents a string that is used to identify a host.
type HostIdentifierString interface {

	// provides a normalized String representation for the host identified by this HostIdentifierString instance
	ToNormalizedString() string

	// returns whether the wrapped string is a valid identifier for a host
	IsValid() bool

	fmt.Stringer
}

var _, _, _ HostIdentifierString = &IPAddressString{}, &MACAddressString{}, &HostName{}
