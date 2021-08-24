package ipaddr

// DivisionType serves as a common interface to all divisions, including both standard divisions (<= 64 bits) and large divisions (> 64 bits)
type DivisionType interface {
	AddressItem

	getAddrType() addrType

	Equals(DivisionType) bool

	getStringAsLower() string
	GetString() string
	GetWildcardString() string

	// Determines if the division has a single prefix for the given prefix length.  You can call GetPrefixCountLen to get the count of prefixes.
	IsSinglePrefix(BitCount) bool

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
