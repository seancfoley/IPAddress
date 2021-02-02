package ipaddr

import (
	"math/big"
	"net"
)

type AddressItem interface {
	CopyBytes(bytes []byte) []byte
	CopyUpperBytes(bytes []byte) []byte
	GetBytes() []byte
	GetUpperBytes() []byte
	IsMultiple() bool
	GetCount() *big.Int
	GetByteCount() int
	GetBitCount() BitCount
	GetValue() *BigDivInt
	GetUpperValue() *BigDivInt
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

	//TODO add these two
	//toHexString
	//toNormalizedString
}

//
//
// divisions

type AddressStringDivision interface {
}

type IPAddressStringDivision interface {
	AddressStringDivision
}

// AddressGenericDivision serves as common interface to all divisions, including large divisions (> 64 bits)
type AddressGenericDivision interface {
	AddressItem
	AddressStringDivision
	// TODO seems I need something in here to make this division-specific (right now any address item satisfies the interface)
	// addressDivisionBase has nothing, check Java large and base
	// getDefaultTextualRadix()? getDigitCount(int radix)? getMaxDigitCount()? getWildcardString()?
}

// Represents any standard address division, all of which can be converted to/from AddressDivision
type AddressStandardDivision interface {
	AddressGenericDivision

	ToAddressDivision() *AddressDivision
}

//TODO ensure all framework structs X are checked on this page with a _ intf = &X{} which will assert it satisfies all necessary interfaces down to AddressItem

var (
	_ AddressStandardDivision = &AddressDivision{}
	_ AddressStandardDivision = &AddressSegment{}
	_ AddressStandardDivision = &IPAddressSegment{}
	_ AddressStandardDivision = &IPv4AddressSegment{}
	_ AddressStandardDivision = &IPv6AddressSegment{}
	_ AddressStandardDivision = &MACAddressSegment{}
)

// euqivalent to AddressSegment on Java side, serves as common interface to all segments
type AddressStandardSegment interface {
	AddressItem
	AddressStringDivision

	GetSegmentValue() SegInt
	GetUpperSegmentValue() SegInt
}

var (
	_ AddressStandardSegment = &AddressSegment{}
	_ AddressStandardSegment = &IPv6AddressSegment{}
	_ AddressStandardSegment = &MACAddressSegment{}
	_ AddressStandardSegment = &IPv4AddressSegment{}
)

//
//
// division series
type AddressStringDivisionSeries interface {
}

type IPAddressStringDivisionSeries interface {
	AddressStringDivisionSeries
}

// AddressDivisionSeries serves as a common interface to all division groupings (including large) and addresses
type AddressDivisionSeries interface {
	AddressItem
	AddressStringDivisionSeries

	IsMore(AddressDivisionSeries) int
	GetGenericDivision(index int) AddressGenericDivision
	GetDivisionCount() int
}

type AddressSegmentSeries interface { // Address and above, AddressSection and above, IPAddressSegmentSeries
	AddressComponent
	AddressDivisionSeries
}

type IPAddressSegmentSeries interface { // IPAddress and above, IPAddressSection and above
	AddressSegmentSeries
}

//
//
//
// addresses and address ranges

type IPAddressRange interface { //IPAddress and above, IPAddressSeqRange and above
	//AddressComponentRange

	// TODO maybe you want a generic GetLowerIPAddress() *IPAddress and GetUpperIPAddress() *IPAddress

	CopyIP(bytes net.IP) net.IP
	CopyUpperIP(bytes net.IP) net.IP
	GetIP() net.IP
	GetUpperIP() net.IP
}

// Represents any standard address division grouping that can be converted to/from AddressDivisionGrouping,
// including AddressSection, IPAddressSection, IPv4AddressSection, IPv6AddressSection, and MACAddressSection
type AddressDivisionGroupingType interface {
	AddressDivisionSeries

	ToAddressDivisionGrouping() *AddressDivisionGrouping
}

var (
	_ AddressDivisionGroupingType = &AddressDivisionGrouping{}
)

type AddressSectionType interface {
	AddressDivisionGroupingType

	ToAddressSection() *AddressSection
}

var (
	_ AddressSectionType = &AddressSection{}
	_ AddressSectionType = &IPAddressSection{}
	_ AddressSectionType = &IPv4AddressSection{}
	_ AddressSectionType = &IPv6AddressSection{}
	_ AddressSectionType = &MACAddressSection{}
)

// Represents any address, all of which can be converted to/from Address, including IPAddress, IPv4Address, IPv6Address, and MACAddress
type AddressType interface {
	AddressDivisionSeries

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
//
//
//
//
//
//
//
//
//
//TODO think some more about using the names GenericAddress and AddressGenericDivisionGrouping or GenericAddressDivisionGrouping
// to be consistent with AddressGenericDivision

//Logically AddressDivisionSeries would be implemened only by AddressDivisionGrouping
//AddressSegmentSeries by AddressSection and Address
//AddressGenericDivision by AddressDivision
//
// Also, in Go, you cannot have the same function appearing in two embedded interfaces, which is lame
// But I guess in the end, since the only thing that matters is the methods themselves, can work around it,
// the embedding is really only a convenience, you could literally list every method in every interface
// Still, it's a PITA
//
// do not see the need for this, since I am doing away with IPAddressDivision
//type IPAddressGenericDivision interface { // IPAddressDivision, IPAddressLargeDivision
//	AddressGenericDivision
//	IPAddressStringDivision
//}
