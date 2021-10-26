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
	GetBytes() []byte // TODO maybe change to Bytes() and UpperBytes() to be consistent with https://pkg.go.dev/bytes#Buffer.Bytes and https://pkg.go.dev/reflect#Value.Bytes and https://pkg.go.dev/math/big#Int.Bytes
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

	//TODO consider renaming to Compare to be consistent with package bytes and strings - it seems sometimes methods with the right name gets special treatment https://github.com/google/go-cmp/issues/61
	// Or maybe Cmp https://pkg.go.dev/math/big#Int.Cmp
	// Since an address is more like a sequence of bytes, probably want the former, Compare

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

	CopyIP(bytes net.IP) net.IP //TODO make sure this handles the ipv4-mapped ipv4 addresses
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
	GetPrefixLen() PrefixLen

	CompareSize(AddressDivisionSeries) int

	GetGenericDivision(index int) DivisionType // useful for comparisons
}

type addrSegmentSeries interface {
	AddressComponent

	//IsZeroHost() bool

	GetMaxSegmentValue() SegInt
	GetSegmentCount() int
	GetBitsPerSegment() BitCount
	GetBytesPerSegment() int

	ToCanonicalString() string
	ToCompressedString() string

	//EqualsSeries(AddressSegmentSeries) bool

	GetGenericSegment(index int) AddressSegmentType
}

type AddressSegmentSeries interface { // Address and above, AddressSection and above, IPAddressSegmentSeries, ExtendedIPSegmentSeries

	AddressDivisionSeries

	addrSegmentSeries
}

var _, _, _, _ AddressSegmentSeries = &Address{},
	&MACAddress{},
	&AddressSection{},
	&MACAddressSection{}

type IPAddressSegmentSeries interface { // IPAddress and above, IPAddressSection and above, ExtendedIPSegmentSeries

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

	GetSequentialBlockIndex() int
	GetSequentialBlockCount() *big.Int

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
	ToSQLWildcardString() string
	//ToReverseDNSString() (string, IncompatibleAddressError)
	ToBinaryString(with0bPrefix bool) (string, IncompatibleAddressError)
	ToSegmentedBinaryString() string
	ToOctalString(withPrefix bool) (string, IncompatibleAddressError)

	//GetGenericIPDivision(index int) IPAddressGenericDivision remove this I think, we have GetGenericDivision(index int) DivisionType
}

var _, _, _, _ IPAddressSegmentSeries = &IPAddress{},
	&IPv4Address{},
	&IPAddressSection{},
	&IPv4AddressSection{}

type IPv6AddressSegmentSeries interface {
	IPAddressSegmentSeries
	// TODO we can lots more methods here, anything ipv6 specific but commone to sections and addresses
	GetSegment(index int) *IPv6AddressSegment
}

// TODO equivalent of IPv6AddressSegmentSeries for ipv4 and mac

var _, _, _ IPv6AddressSegmentSeries = &IPv6Address{},
	&IPv6AddressSection{},
	&EmbeddedIPv6AddressSection{}

// GenericGroupingType represents any division grouping, including groupings of both standard and large divisions
type GenericGroupingType interface {
	AddressDivisionSeries

	getAddrType() addrType

	Equals(GenericGroupingType) bool //TODO maybe rename to Equal() https://github.com/google/go-cmp/issues/61#issuecomment-353451627
}

// StandardDivisionGroupingType represents any standard division grouping (groupings where all divisions are 64 bits or less)
// including AddressSection, IPAddressSection, IPv4AddressSection, IPv6AddressSection, MACAddressSection, and AddressDivisionGrouping
type StandardDivisionGroupingType interface { //TODO rename to StandardDivisionGrouping
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

	//TODO I suspect this addrSegmentSeries weirdness could go away if we dropped GenericGroupingType,
	// because it extends AddressDivisionSeries,
	// and it doesn't seem to be all that useful anyway.
	// I did not use it in the comparator.  Using addressDivisionGroupingBases is just as useful, what does the interface give you?
	// Just a type to use as the argument for Equals(GenericGroupingType).
	// But equality is a loosy goosey concept anyway for divisions of varying length
	//
	// But would I need to make StandardDivisionGroupingType extend AddressDivisionSeries, and thus result in the same dual path to AddressDivisionSeries?
	// How would you avoid the dual path?  Do you need StandardDivisionGroupingType to extend AddressDivisionSeries?
	// Without it, AddressSectionType has no path to AddressDivisionSeries, but it would once we put back AddressSegmentSeries
	// Other than that, the generic grouping code is just used by the equals stuff.  So no, it is not needed, I think you're good if you remove it.
	//
	// If I remove it, then rename EqualsSection to Equals, and make it use AddressSectionType
	// So then you'd have no equals for all division groupings, just sections, but I think I do not care
	// We still have CompareTo everywhere anyway
	addrSegmentSeries
	//AddressSegmentSeries

	Contains(AddressSectionType) bool
	ToAddressSection() *AddressSection
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

	getAddrType() addrType //TODO get rid of this and make callers call ToAddress().getAddrType()

	Equals(AddressType) bool //TODO maybe rename Equal() https://github.com/google/go-cmp/issues/61#issuecomment-353451627 and then PrefixEqual should drop the 's' too
	PrefixEquals(AddressType) bool
	Contains(AddressType) bool
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

	ContainsRange(other IPAddressSeqRangeType) bool
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
}

var _, _, _ HostIdentifierString = &IPAddressString{}, &MACAddressString{}, &HostName{}
