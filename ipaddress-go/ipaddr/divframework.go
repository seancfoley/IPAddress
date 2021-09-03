package ipaddr

// DivisionType serves as a common interface to all divisions, including both standard divisions (<= 64 bits) and large divisions (> 64 bits)
type DivisionType interface {
	AddressItem

	getAddrType() addrType

	Equals(DivisionType) bool

	// getStringAsLower caches the string from getDefaultLowerString
	getStringAsLower() string

	// GetString produces a string that avoids wildcards when using prefix length.  Equivalent to GetWildcardString if the prefix length is not part of the string.
	GetString() string

	// GetWildcardString produces a string that uses wildcards and avoids prefix length
	GetWildcardString() string

	// Determines if the division has a single prefix for the given prefix length.  You can call GetPrefixCountLen to get the count of prefixes.
	IsSinglePrefix(BitCount) bool

	// methods for string generation used by the string params and string writer
	divStringProvider
}

// Represents any standard address division, all of which can be converted to/from AddressDivision
type StandardDivisionType interface {
	DivisionType

	ToAddressDivision() *AddressDivision
}

var _ StandardDivisionType = &AddressDivision{}

// AddressSegment serves as a common interface to all segments
type AddressSegmentType interface {
	AddressComponent

	StandardDivisionType

	Contains(AddressSegmentType) bool

	// GetSegmentValue returns the lower segment value as a SegInt, the same value as the DivInt value returned by getDivisionValue()
	GetSegmentValue() SegInt

	// GetUpperSegmentValue returns the upper segment value as a SegInt, the same value as the DivInt value returned by getUpperDivisionValue()
	GetUpperSegmentValue() SegInt

	ToAddressSegment() *AddressSegment
}

var _, _, _, _, _ AddressSegmentType = &AddressSegment{},
	&IPAddressSegment{},
	&IPv6AddressSegment{},
	&IPv4AddressSegment{},
	&MACAddressSegment{}
