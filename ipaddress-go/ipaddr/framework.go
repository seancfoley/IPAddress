package ipaddr

import (
	"fmt"
	"math/big"
	"net"
)

type AddressItem interface {
	IsMultiple() bool

	GetValue() *big.Int
	GetUpperValue() *big.Int

	CopyBytes(bytes []byte) []byte
	CopyUpperBytes(bytes []byte) []byte
	GetBytes() []byte
	GetUpperBytes() []byte

	GetCount() *big.Int

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

	// ContainsSinglePrefixBlock returns  whether the values of this series contains a single prefix block for the given prefix length.
	// This means there is only one prefix of the given length in this item, and this item contains the prefix block for that given prefix.
	ContainsSinglePrefixBlock(BitCount) bool

	// GetPrefixLengthForSingleBlock returns a prefix length for which there is only one prefix of that length in this item,
	// and the range of this item matches the block of all values for that prefix.
	// If the range can be dictated this way, then this method returns the same value as GetMinPrefixLengthForBlock.
	// If no such prefix length exists, returns nil.
	// If this item represents a single value, this returns the bit count.
	GetPrefixLengthForSingleBlock() PrefixLen

	// GetMinPrefixLengthForBlock returns the smallest prefix length possible such that this item includes the block of all values for that prefix length.
	// If there are multiple possible prefixes in this item for the given prefix length,
	// this item contains the prefix block for each and every one of those prefixes.
	// If the entire range can be dictated this way, then this method returns the same value as {@link #getPrefixLengthForSingleBlock()}.
	// Otherwise, this method will return the minimal possible prefix that can be paired with this address, while {@link #getPrefixLengthForSingleBlock()} will return null.
	// In cases where the final bit is constant so there is no such block, this returns the bit count.
	GetMinPrefixLengthForBlock() BitCount

	// The count of the number of distinct values within the prefix part of the range of values for this item
	GetPrefixCountLen(BitCount) *big.Int

	// Any address item is comparable to any other
	CompareTo(item AddressItem) int

	fmt.Stringer
}

// probably does not apply to golang because ranged values are always more specific, I'd have to add new methods with standard return values
// But I am keeping IPAddressRange
//type AddressComponentRange interface {
//
//	//AddressItem
//}

type AddressComponent interface { //AddressSegment and above, AddressSegmentSeries and above
	//AddressComponentRange

	TestBit(BitCount) bool
	IsOneBit(BitCount) bool

	ToHexString(bool) (string, IncompatibleAddressError)
	ToNormalizedString() string
}

type ipAddressRange interface {
	GetLowerIPAddress() *IPAddress
	GetUpperIPAddress() *IPAddress

	CopyIP(bytes net.IP) net.IP
	CopyUpperIP(bytes net.IP) net.IP

	GetIP() net.IP
	GetUpperIP() net.IP
}

type IPAddressRange interface { //IPAddress and above, IPAddressSeqRange and above
	//AddressComponentRange

	ipAddressRange

	IsSequential() bool
}

//  as discussed in stringparams.go
// Likely you will eventually merge AddressStringDivisionSeries with AddressDivisionSeries
// Likely you will merge AddressStringDivision into DivisionType too

//
//
// division series
//type AddressStringDivisionSeries interface {
//	GetDivisionCount() int
//	//GetStringDivision(index int) AddressStringDivision // useful for string generation
//}

//type IPAddressStringDivisionSeries interface {
//	AddressStringDivisionSeries
//}

// AddressDivisionSeries serves as a common interface to all division groupings (including large) and addresses
type AddressDivisionSeries interface {
	AddressItem
	//AddressStringDivisionSeries
	GetDivisionCount() int

	GetPrefixCount() *big.Int

	IsSequential() bool

	IsPrefixBlock() bool
	IsSinglePrefixBlock() bool
	IsPrefixed() bool
	GetPrefixLength() PrefixLen

	CompareSize(AddressDivisionSeries) int

	GetGenericDivision(index int) DivisionType // useful for comparisons
}

type addrSegmentSeries interface {
	AddressComponent

	GetMaxSegmentValue() SegInt
	GetSegmentCount() int
	GetBitsPerSegment() BitCount
	GetBytesPerSegment() int

	ToCanonicalString() string
	ToCompressedString() string

	GetGenericSegment(index int) AddressSegmentType
}

type AddressSegmentSeries interface { // Address and above, AddressSection and above, IPAddressSegmentSeries, ExtendedIPSegmentSeries

	AddressDivisionSeries

	addrSegmentSeries
}

type IPAddressSegmentSeries interface { // IPAddress and above, IPAddressSection and above, ExtendedIPSegmentSeries

	AddressSegmentSeries

	IncludesZeroHostLen(prefLen BitCount) bool
	IncludesMaxHostLen(prefLen BitCount) bool
	IncludesZeroHost() bool
	IncludesMaxHost() bool
	IsZeroHostLen(BitCount) bool
	IsZeroHost() bool
	IsSingleNetwork() bool

	GetSequentialBlockIndex() int
	GetSequentialBlockCount() *big.Int

	GetIPVersion() IPVersion

	GetBlockMaskPrefixLength(network bool) PrefixLen

	GetLeadingBitCount(ones bool) BitCount
	GetTrailingBitCount(ones bool) BitCount

	ToFullString() string
	//ToPrefixLenString() string //TODO seems I went most of the way but not all the way, still need this one string method
	ToSubnetString() string
	ToNormalizedWildcardString() string
	ToCanonicalWildcardString() string
	ToCompressedWildcardString() string
	ToSQLWildcardString() string
	ToReverseDNSString() string
	ToBinaryString(with0bPrefix bool) (string, IncompatibleAddressError)
	ToSegmentedBinaryString() string
	ToOctalString(withPrefix bool) (string, IncompatibleAddressError)

	//GetGenericIPDivision(index int) IPAddressGenericDivision remove this I think, we have GetGenericDivision(index int) DivisionType
}

// GenericGroupingType represents any division grouping, including groupings of both standard and large divisions
type GenericGroupingType interface {
	AddressDivisionSeries

	getAddrType() addrType

	Equals(GenericGroupingType) bool
}

// StandardDivisionGroupingType represents any standard division grouping (groupings where all divisions are 64 bits or less)
// including AddressSection, IPAddressSection, IPv4AddressSection, IPv6AddressSection, MACAddressSection, and AddressDivisionGrouping
type StandardDivisionGroupingType interface {
	GenericGroupingType

	ToAddressDivisionGrouping() *AddressDivisionGrouping
}

var _, _ StandardDivisionGroupingType = &AddressDivisionGrouping{},
	&IPv6v4MixedAddressGrouping{}

// AddressSectionType represents any address section
// that can be converted to/from the base type AddressSection,
// including AddressSection, IPAddressSection, IPv4AddressSection, IPv6AddressSection, and MACAddressSection
type AddressSectionType interface {
	StandardDivisionGroupingType
	addrSegmentSeries

	Contains(AddressSectionType) bool
	ToAddressSection() *AddressSection
}

var _, _, _, _, _ AddressSectionType = &AddressSection{},
	&IPAddressSection{},
	&IPv4AddressSection{},
	&IPv6AddressSection{},
	&MACAddressSection{}

// AddressType represents any address, all of which can be represented by the base type Address.
// This includes IPAddress, IPv4Address, IPv6Address, and MACAddress.
type AddressType interface {
	AddressSegmentSeries

	Equals(AddressType) bool
	PrefixEquals(AddressType) bool
	Contains(AddressType) bool
	PrefixContains(AddressType) bool
	ToAddress() *Address

	// toAddressString, toHostName TODO look at hostidstring.go for some thoughts on these
}

var _, _ AddressType = &Address{}, &MACAddress{}

// IPAddressType represents any IP address, all of which can be represented by the base type IPAddress.
// This includes IPv4Address, and IPv6Address.
type IPAddressType interface {
	AddressType
	ipAddressRange

	ToIPAddress() *IPAddress
}

var _, _, _ IPAddressType = &IPAddress{},
	&IPv4Address{},
	&IPv6Address{}

type IPAddressSeqRangeType interface {
	AddressItem
	IPAddressRange

	ContainsRange(other IPAddressSeqRangeType) bool
	Contains(IPAddressType) bool
	ToIPAddressSeqRange() *IPAddressSeqRange
}

var _, _, _ IPAddressSeqRangeType = &IPAddressSeqRange{},
	&IPv4AddressSeqRange{},
	&IPv6AddressSeqRange{}
