package ipaddr

import (
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

	ToHexString(bool) (string, IncompatibleAddressException)
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
// Likely you will merge AddressStringDivision into AddressGenericDivision too

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

	GetGenericDivision(index int) AddressGenericDivision // useful for comparisons
}

// IPAddressDivisionSeries serves as a common interface to all IP division groupings (including large) and IP addresses
//type IPAddressDivisionSeries interface {
//	AddressDivisionSeries
//
//	GetGenericIPDivision(index int) IPAddressGenericDivision // useful for comparisons
//}
//
//var (
//	_ IPAddressDivisionSeries = &IPAddressSection{}
//	_ IPAddressDivisionSeries = &IPv4AddressSection{}
//	_ IPAddressDivisionSeries = &IPv6AddressSection{}
//	_ IPAddressDivisionSeries = &IPAddress{}
//	_ IPAddressDivisionSeries = &IPv4Address{}
//	_ IPAddressDivisionSeries = &IPv6Address{}
//)

type addrSegmentSeries interface {
	AddressComponent

	GetMaxSegmentValue() SegInt
	GetSegmentCount() int
	GetBitsPerSegment() BitCount
	GetBytesPerSegment() int

	ToCanonicalString() string
	ToCompressedString() string

	GetGenericSegment(index int) AddressStandardSegment
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
	ToBinaryString(with0bPrefix bool) (string, IncompatibleAddressException)
	ToSegmentedBinaryString() string
	ToOctalString(withPrefix bool) (string, IncompatibleAddressException)

	//GetGenericIPDivision(index int) IPAddressGenericDivision remove this I think, we have GetGenericDivision(index int) AddressGenericDivision
}

// GenericGroupingType represents any division grouping
type GenericGroupingType interface {
	AddressDivisionSeries

	getAddrType() addrType

	Equals(GenericGroupingType) bool
}

// AddressDivisionGroupingType represents any standard division grouping (divisions are 64 bits or less)
// including AddressSection, IPAddressSection, IPv4AddressSection, IPv6AddressSection, MACAddressSection, and AddressDivisionGrouping
type AddressDivisionGroupingType interface { //TODO rename StandardDivisionGroupingType
	GenericGroupingType

	ToAddressDivisionGrouping() *AddressDivisionGrouping
}

var (
	_ AddressDivisionGroupingType = &AddressDivisionGrouping{}
)

// AddressSectionType represents any address section
// that can be converted to/from the base type AddressSection,
// including AddressSection, IPAddressSection, IPv4AddressSection, IPv6AddressSection, and MACAddressSection
type AddressSectionType interface {
	AddressDivisionGroupingType
	addrSegmentSeries

	Contains(AddressSectionType) bool
	ToAddressSection() *AddressSection
}

var (
	_ AddressSectionType = &AddressSection{}
	_ AddressSectionType = &IPAddressSection{}
	_ AddressSectionType = &IPv4AddressSection{}
	_ AddressSectionType = &IPv6AddressSection{}
	_ AddressSectionType = &MACAddressSection{}
)

// AddressType represents any address, all of which can be represented by the base type Address.
// This includes IPAddress, IPv4Address, IPv6Address, and MACAddress.
type AddressType interface {
	//AddressDivisionSeries
	AddressSegmentSeries

	Equals(AddressType) bool
	Contains(AddressType) bool
	ToAddress() *Address
}

var (
	_ AddressType = &Address{}
	_ AddressType = &MACAddress{}
)

type IPAddressType interface {
	AddressType
	IPAddressRange

	ToIPAddress() *IPAddress
}

var (
	_ IPAddressType = &IPAddress{}
	_ IPAddressType = &IPv4Address{}
	_ IPAddressType = &IPv6Address{}
)

type IPAddressSeqRangeType interface {
	IPAddressRange

	ContainsRange(other IPAddressSeqRangeType) bool
	Contains(IPAddressType) bool
	ToIPAddressSeqRange() *IPAddressSeqRange
}

var (
	_ IPAddressSeqRangeType = &IPAddressSeqRange{}
	_ IPAddressSeqRangeType = &IPv4AddressSeqRange{}
	_ IPAddressSeqRangeType = &IPv6AddressSeqRange{}
)

//
//
//
//
//
//TODO think some more about using the names GenericAddress and AddressGenericDivisionGrouping or GenericAddressDivisionGrouping
// to be consistent with AddressGenericDivision
// In fact, all the names need thought, to balance:
// 1. consistency with Java
// 2. distinguish the new interfaces that span the class hierarchies in Java
// 3. try to keep names short a la go style
// 4. try to remain descriptive
// 5. rename interfaces in Java too if it helps (1) although I am leaning away from that, at least in the short term

//Logically AddressDivisionSeries would be implemened only by AddressDivisionGrouping
//AddressSegmentSeries by AddressSection and Address
//AddressGenericDivision by AddressDivision
//
// Also, in Go, you cannot have the same function appearing in two embedded interfaces, which is lame
// But I guess in the end, since the only thing that matters is the methods themselves, can work around it,
// the embedding is really only a convenience, you could literally list every method in every interface
// Still, it's a PITA
//
// do not see the need for this interface, since I am doing away with IPAddressDivision
//type IPAddressGenericDivision interface { // IPAddressDivision, IPAddressLargeDivision
//	AddressGenericDivision
//	IPAddressStringDivision
//}
