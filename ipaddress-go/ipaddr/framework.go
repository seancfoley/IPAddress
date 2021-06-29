package ipaddr

import (
	"fmt"
	"math/big"
	"net"
)

type AddressItem interface {
	IsMultiple() bool

	GetValue() *BigDivInt
	GetUpperValue() *BigDivInt

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

	ContainsPrefixBlock(BitCount) bool
	ContainsSinglePrefixBlock(BitCount) bool
	GetPrefixLengthForSingleBlock() PrefixLen
	GetMinPrefixLengthForBlock() BitCount
	// GetPrefixCount(int) TODO, I think this is the last one for AddressItem

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

type IPAddressRange interface { //IPAddress and above, IPAddressSeqRange and above
	//AddressComponentRange

	// TODO maybe you want a generic GetLowerIPAddress() *IPAddress and GetUpperIPAddress() *IPAddress in here?
	// Just to be able to get lower and upper through the interface?
	// Once again, downside is this pollute method-set, confuses with GetLower and GetUpper, so probably not.
	// This IPAddressRange interface might not be all that useful

	CopyIP(bytes net.IP) net.IP
	CopyUpperIP(bytes net.IP) net.IP
	GetIP() net.IP
	GetUpperIP() net.IP
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

type AddressSegmentSeries interface { // Address and above, AddressSection and above, IPAddressSegmentSeries

	AddressDivisionSeries

	addrSegmentSeries
}

type IPAddressSegmentSeries interface { // IPAddress and above, IPAddressSection and above

	AddressSegmentSeries

	IncludesZeroHostLen(prefLen BitCount) bool
	IncludesMaxHostLen(prefLen BitCount) bool
	IncludesZeroHost() bool
	IncludesMaxHost() bool
	IsZeroHostLen(BitCount) bool
	IsZeroHost() bool
	IsSingleNetwork() bool

	GetSequentialBlockIndex() int
	//GetSequentialBlockCount() *big.Int TODO

	GetIPVersion() IPVersion

	ToFullString() string
	//ToPrefixLenString() string //TODO
	ToSubnetString() string
	ToNormalizedWildcardString() string
	ToCanonicalWildcardString() string
	ToCompressedWildcardString() string
	ToSQLWildcardString() string
	//ToReverseDNSLookupString() string //TODO
	ToBinaryString(with0bPrefix bool) (string, IncompatibleAddressError)
	ToSegmentedBinaryString() string
	ToOctalString(withPrefix bool) (string, IncompatibleAddressError)

	//GetGenericIPDivision(index int) IPAddressGenericDivision remove this I think, we have GetGenericDivision(index int) DivisionType
}

// GenericGroupingType represents any division grouping
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

var _ StandardDivisionGroupingType = &AddressDivisionGrouping{}

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
	Contains(AddressType) bool
	ToAddress() *Address
}

var _, _ AddressType = &Address{}, &MACAddress{}

// IPAddressType represents any IP address, all of which can be represented by the base type IPAddress.
// This includes IPv4Address, and IPv6Address.
type IPAddressType interface {
	AddressType
	IPAddressRange

	ToIPAddress() *IPAddress
}

var _, _, _ IPAddressType = &IPAddress{},
	&IPv4Address{},
	&IPv6Address{}

type IPAddressSeqRangeType interface {
	IPAddressRange

	ContainsRange(other IPAddressSeqRangeType) bool
	Contains(IPAddressType) bool
	ToIPAddressSeqRange() *IPAddressSeqRange
}

var _, _, _ IPAddressSeqRangeType = &IPAddressSeqRange{},
	&IPv4AddressSeqRange{},
	&IPv6AddressSeqRange{}
