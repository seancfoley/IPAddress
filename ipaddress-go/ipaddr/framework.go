package ipaddr

type AddressItem interface {
	//CopyBytes(bytes []byte) []byte
	//CopyUpperBytes(bytes []byte) []byte
	GetByteCount() int
	GetBitCount() BitCount

	GetValue() *BigDivInt

	GetUpperValue() *BigDivInt
}

type AddressComponentRange interface {
	AddressItem
}

type AddressComponent interface { //AddressSegment and above, AddressSegmentSeries and above
	AddressComponentRange
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

var (
	_ AddressStandardDivision = &AddressDivision{}
	_ AddressStandardDivision = &AddressSegment{}
	_ AddressStandardDivision = &IPAddressSegment{}
	_ AddressStandardDivision = &IPv4AddressSegment{}
	_ AddressStandardDivision = &IPv6AddressSegment{}
	_ AddressStandardDivision = &MACAddressSegment{}
)

// euqivalent to AddressSegment on Java side, serves as common interface to all segments
type AddressGenericSegment interface {
	AddressItem
	AddressStringDivision

	GetSegmentValue() SegInt
	GetUpperSegmentValue() SegInt
}

var (
	_ AddressGenericSegment = &AddressSegment{}
	_ AddressGenericSegment = &IPv6AddressSegment{}
	_ AddressGenericSegment = &MACAddressSegment{}
	_ AddressGenericSegment = &IPv4AddressSegment{}
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

	GetGenericDivision(index int) AddressGenericDivision
	GetDivisionCount() int
}

type AddressSegmentSeries interface { // Address and above, AddressSection and above, IPAddressSegmentSeries
	AddressComponent
	//AddressDivisionSeries
}

type IPAddressSegmentSeries interface { // IPAddress and above, IPAddressSection and above
	AddressSegmentSeries
}

//
//
//
// addresses and address ranges

type IPAddressRange interface { //IPAddress and above, IPAddressSeqRange and above
	AddressComponentRange
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
	_ AddressType = &IPAddress{}
	_ AddressType = &IPv4Address{}
	_ AddressType = &IPv6Address{}
	_ AddressType = &MACAddress{}
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
