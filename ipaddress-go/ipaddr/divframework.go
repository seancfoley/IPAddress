package ipaddr

//type AddressStringDivision interface {
//}
//
//type IPAddressStringDivision interface {
//	AddressStringDivision
//}

// AddressGenericDivision serves as common interface to all divisions, including large divisions (> 64 bits)
type AddressGenericDivision interface { //TODO rename GenericDivisionType or GenericDivision
	AddressItem
	//AddressStringDivision

	getAddrType() addrType

	Equals(AddressGenericDivision) bool

	getStringAsLower() string
	GetString() string
	GetWildcardString() string

	divStringProvider
	// to add: getDefaultTextualRadix()? getDigitCount(int radix)? getMaxDigitCount()? getWildcardString()?
}

var (
	_ AddressGenericDivision = &AddressDivision{}
	_ AddressGenericDivision = &AddressSegment{}
	_ AddressGenericDivision = &MACAddressSegment{}
)

// IPAddressGenericDivision is a division with its own prefix length
//type IPAddressGenericDivision interface {
//	AddressGenericDivision
//
//	GetDivisionPrefixLength() PrefixLen
//
//	// Returns whether the division range includes the block of values for its prefix length
//	IsPrefixBlock() bool
//
//	// Returns whether the division range matches the block of values for its prefix length
//	IsSinglePrefixBlock() bool
//}

//var (
//	_ IPAddressGenericDivision = &IPAddressSegment{}
//	_ IPAddressGenericDivision = &IPv4AddressSegment{}
//	_ IPAddressGenericDivision = &IPv6AddressSegment{}
//)

// Represents any standard address division, all of which can be converted to/from AddressDivision
type AddressStandardDivision interface { //TODO rename StandardDivisionType.
	AddressGenericDivision

	// getDivisionValue returns the lower division value
	//getDivisionValue() DivInt

	// getUpperDivisionValue returns the upper division value
	//getUpperDivisionValue() DivInt

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
type AddressStandardSegment interface { //TODO rename AddressSegmentType or StandardSegmentType
	AddressComponent

	AddressStandardDivision

	Contains(AddressStandardSegment) bool

	// GetSegmentValue returns the lower segment value as a SegInt, the same value as the DivInt value returned by getDivisionValue()
	GetSegmentValue() SegInt

	// GetUpperSegmentValue returns the upper segment value as a SegInt, the same value as the DivInt value returned by getUpperDivisionValue()
	GetUpperSegmentValue() SegInt

	ToAddressSegment() *AddressSegment
}

var (
	_ AddressStandardSegment = &AddressSegment{}
	_ AddressStandardSegment = &IPv6AddressSegment{}
	_ AddressStandardSegment = &MACAddressSegment{}
	_ AddressStandardSegment = &IPv4AddressSegment{}
)
