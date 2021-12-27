package ipaddr

import (
	"fmt"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrerr"
	"math/big"
	"net"
)

const (
	IPv6SegmentSeparator            = ':'
	IPv6ZoneSeparator               = '%'
	IPv6ZoneSeparatorStr            = "%"
	IPv6AlternativeZoneSeparator    = '\u00a7'
	IPv6AlternativeZoneSeparatorStr = "\u00a7"
	IPv6BitsPerSegment              = 16
	IPv6BytesPerSegment             = 2
	IPv6SegmentCount                = 8
	IPv6MixedReplacedSegmentCount   = 2
	IPv6MixedOriginalSegmentCount   = 6
	IPv6MixedOriginalByteCount      = 12
	IPv6ByteCount                   = 16
	IPv6BitCount                    = 128
	IPv6DefaultTextualRadix         = 16
	IPv6MaxValuePerSegment          = 0xffff
	IPv6ReverseDnsSuffix            = ".ip6.arpa"
	IPv6ReverseDnsSuffixDeprecated  = ".ip6.int"

	IPv6UncSegmentSeparator  = '-'
	IPv6UncZoneSeparator     = 's'
	IPv6UncRangeSeparator    = AlternativeRangeSeparator
	IPv6UncRangeSeparatorStr = AlternativeRangeSeparatorStr
	IPv6UncSuffix            = ".ipv6-literal.net"

	IPv6SegmentMaxChars    = 4
	IPv6SegmentBitsPerChar = 4

	ipv6BitsToSegmentBitshift = 4

	IPv6AlternativeRangeSeparatorStr = AlternativeRangeSeparatorStr
)

type Zone string

func (zone Zone) IsEmpty() bool {
	return zone == ""
}

func (zone Zone) String() string {
	return string(zone)
}

const NoZone = ""

func newIPv6Address(section *IPv6AddressSection) *IPv6Address {
	return createAddress(section.ToSectionBase(), NoZone).ToIPv6()
}

func NewIPv6Address(section *IPv6AddressSection) (*IPv6Address, addrerr.AddressValueError) {
	if section == nil {
		return zeroIPv6, nil
	}
	segCount := section.GetSegmentCount()
	if segCount != IPv6SegmentCount {
		return nil, &addressValueError{
			addressError: addressError{key: "ipaddress.error.invalid.size"},
			val:          segCount,
		}
	}
	return createAddress(section.ToSectionBase(), NoZone).ToIPv6(), nil
}

func newIPv6AddressZoned(section *IPv6AddressSection, zone string) *IPv6Address {
	zoneVal := Zone(zone)
	result := createAddress(section.ToSectionBase(), zoneVal).ToIPv6()
	assignIPv6Cache(zoneVal, result.cache)
	return result
}

func assignIPv6Cache(zoneVal Zone, cache *addressCache) {
	if zoneVal != NoZone { // will need to cache its own strings
		cache.stringCache = &stringCache{ipv6StringCache: &ipv6StringCache{}, ipStringCache: &ipStringCache{}}
	}
}

func NewIPv6AddressZoned(section *IPv6AddressSection, zone string) (*IPv6Address, addrerr.AddressValueError) {
	if section == nil {
		return zeroIPv6.SetZone(zone), nil
	}
	segCount := section.GetSegmentCount()
	if segCount != IPv6SegmentCount {
		return nil, &addressValueError{
			addressError: addressError{key: "ipaddress.error.invalid.size"},
			val:          segCount,
		}
	}
	return newIPv6AddressZoned(section, zone), nil
}

func NewIPv6AddressFromBytes(bytes []byte) (addr *IPv6Address, err addrerr.AddressValueError) {
	section, err := NewIPv6SectionFromSegmentedBytes(bytes, IPv6SegmentCount)
	if err == nil {
		addr = newIPv6Address(section)
	}
	return
}

func NewIPv6AddressFromPrefixedBytes(bytes []byte, prefixLength PrefixLen) (addr *IPv6Address, err addrerr.AddressValueError) {
	section, err := NewIPv6SectionFromPrefixedBytes(bytes, IPv6SegmentCount, prefixLength)
	if err == nil {
		addr = newIPv6Address(section)
	}
	return
}

func NewIPv6AddressFromZonedBytes(bytes []byte, zone string) (addr *IPv6Address, err addrerr.AddressValueError) {
	addr, err = NewIPv6AddressFromBytes(bytes)
	if err == nil {
		addr.zone = Zone(zone)
		assignIPv6Cache(addr.zone, addr.cache)
	}
	return
}

func NewIPv6AddressFromPrefixedZonedBytes(bytes []byte, prefixLength PrefixLen, zone string) (addr *IPv6Address, err addrerr.AddressValueError) {
	addr, err = NewIPv6AddressFromPrefixedBytes(bytes, prefixLength)
	if err == nil {
		addr.zone = Zone(zone)
		assignIPv6Cache(addr.zone, addr.cache)
	}
	return
}

//
//func NewIPv6AddressFromIPAddr(ipAddr *net.IPAddr) (addr *IPv6Address, err addrerr.AddressValueError) {
//	return newIPv6AddressFromZonedIP(ipAddr.IP, ipAddr.Zone)
//}
//
//
//func NewIPv6AddressFromPrefixedIPAddr(ipAddr *net.IPAddr, prefixLen PrefixLen) (addr *IPv6Address, err addrerr.AddressValueError) {
//	addr, err = NewIPv6AddressFromPrefixedBytes(ipAddr.IP, prefixLen)
//	if err == nil {
//		addr.zone = Zone(ipAddr.Zone)
//		assignIPv6Cache(addr.zone, addr.cache)
//	}
//	return
//}

func NewIPv6AddressFromInt(val *big.Int) (addr *IPv6Address, err addrerr.AddressValueError) {
	section, err := NewIPv6SectionFromBigInt(val, IPv6SegmentCount)
	if err == nil {
		addr = newIPv6Address(section)
	}
	return
}

func NewIPv6AddressFromPrefixedInt(val *big.Int, prefixLength PrefixLen) (addr *IPv6Address, err addrerr.AddressValueError) {
	section, err := NewIPv6SectionFromPrefixedBigInt(val, IPv6SegmentCount, prefixLength)
	if err == nil {
		addr = newIPv6Address(section)
	}
	return
}

func NewIPv6AddressFromZonedInt(val *big.Int, zone string) (addr *IPv6Address, err addrerr.AddressValueError) {
	addr, err = NewIPv6AddressFromInt(val)
	if err == nil {
		addr.zone = Zone(zone)
		assignIPv6Cache(addr.zone, addr.cache)
	}
	return
}

func NewIPv6AddressFromPrefixedZonedInt(val *big.Int, prefixLength PrefixLen, zone string) (addr *IPv6Address, err addrerr.AddressValueError) {
	addr, err = NewIPv6AddressFromPrefixedInt(val, prefixLength)
	if err == nil {
		addr.zone = Zone(zone)
		assignIPv6Cache(addr.zone, addr.cache)
	}
	return
}

func NewIPv6AddressFromSegs(segments []*IPv6AddressSegment) (addr *IPv6Address, err addrerr.AddressValueError) {
	segCount := len(segments)
	if segCount != IPv6SegmentCount {
		return nil, &addressValueError{
			addressError: addressError{key: "ipaddress.error.invalid.size"},
			val:          segCount,
		}
	}
	section := NewIPv6Section(segments)
	return NewIPv6Address(section)
	//section, err := NewIPv6Section(segments)
	//if err == nil {
	//	return NewIPv6Address(section)
	//}
	//return
}

func NewIPv6AddressFromPrefixedSegs(segments []*IPv6AddressSegment, prefixLength PrefixLen) (addr *IPv6Address, err addrerr.AddressValueError) {
	segCount := len(segments)
	if segCount != IPv6SegmentCount {
		return nil, &addressValueError{
			addressError: addressError{key: "ipaddress.error.invalid.size"},
			val:          segCount,
		}
	}
	section := NewIPv6PrefixedSection(segments, prefixLength)
	return NewIPv6Address(section)
	//section, err := NewIPv6PrefixedSection(segments, prefixLength)
	//if err == nil {
	//	return NewIPv6Address(section)
	//}
	//return
}

func NewIPv6AddressFromZonedSegs(segments []*IPv6AddressSegment, zone string) (addr *IPv6Address, err addrerr.AddressValueError) {
	segCount := len(segments)
	if segCount != IPv6SegmentCount {
		return nil, &addressValueError{
			addressError: addressError{key: "ipaddress.error.invalid.size"},
			val:          segCount,
		}
	}
	section := NewIPv6Section(segments)
	return NewIPv6AddressZoned(section, zone)
	//
	//section, err := NewIPv6Section(segments)
	//if err == nil {
	//	return NewIPv6AddressZoned(section, zone)
	//}
	//return
}

func NewIPv6AddressFromPrefixedZonedSegs(segments []*IPv6AddressSegment, prefixLength PrefixLen, zone string) (addr *IPv6Address, err addrerr.AddressValueError) {
	segCount := len(segments)
	if segCount != IPv6SegmentCount {
		return nil, &addressValueError{
			addressError: addressError{key: "ipaddress.error.invalid.size"},
			val:          segCount,
		}
	}
	section := NewIPv6PrefixedSection(segments, prefixLength)
	return NewIPv6AddressZoned(section, zone)
	//section, err := NewIPv6PrefixedSection(segments, prefixLength)
	//if err == nil {
	//	return NewIPv6AddressZoned(section, zone)
	//}
	//return
}

func NewIPv6AddressFromUint64(highBytes, lowBytes uint64) *IPv6Address {
	section := NewIPv6SectionFromUint64(highBytes, lowBytes, IPv6SegmentCount)
	return newIPv6Address(section)
}

func NewIPv6AddressFromPrefixedUint64(highBytes, lowBytes uint64, prefixLength PrefixLen) *IPv6Address {
	section := NewIPv6SectionFromPrefixedUint64(highBytes, lowBytes, IPv6SegmentCount, prefixLength)
	return newIPv6Address(section)
}

func NewIPv6AddressFromZonedUint64(highBytes, lowBytes uint64, zone string) *IPv6Address {
	section := NewIPv6SectionFromUint64(highBytes, lowBytes, IPv6SegmentCount)
	return newIPv6AddressZoned(section, zone)
}

func NewIPv6AddressFromPrefixedZonedUint64(highBytes, lowBytes uint64, prefixLength PrefixLen, zone string) *IPv6Address {
	section := NewIPv6SectionFromPrefixedUint64(highBytes, lowBytes, IPv6SegmentCount, prefixLength)
	return newIPv6AddressZoned(section, zone)
}

func NewIPv6AddressFromVals(vals IPv6SegmentValueProvider) *IPv6Address {
	section := NewIPv6SectionFromVals(vals, IPv6SegmentCount)
	return newIPv6Address(section)
}

func NewIPv6AddressFromPrefixedVals(vals IPv6SegmentValueProvider, prefixLength PrefixLen) *IPv6Address {
	section := NewIPv6SectionFromPrefixedVals(vals, IPv6SegmentCount, prefixLength)
	return newIPv6Address(section)
}

func NewIPv6AddressFromRange(vals, upperVals IPv6SegmentValueProvider) *IPv6Address {
	section := NewIPv6SectionFromRangeVals(vals, upperVals, IPv6SegmentCount)
	return newIPv6Address(section)
}

func NewIPv6AddressFromPrefixedRange(vals, upperVals IPv6SegmentValueProvider, prefixLength PrefixLen) *IPv6Address {
	section := NewIPv6SectionFromPrefixedRangeVals(vals, upperVals, IPv6SegmentCount, prefixLength)
	return newIPv6Address(section)
}

func NewIPv6AddressFromZonedRange(vals, upperVals IPv6SegmentValueProvider, zone string) *IPv6Address {
	section := NewIPv6SectionFromRangeVals(vals, upperVals, IPv6SegmentCount)
	return newIPv6AddressZoned(section, zone)
}

func NewIPv6AddressFromPrefixedZonedRange(vals, upperVals IPv6SegmentValueProvider, prefixLength PrefixLen, zone string) *IPv6Address {
	section := NewIPv6SectionFromPrefixedRangeVals(vals, upperVals, IPv6SegmentCount, prefixLength)
	return newIPv6AddressZoned(section, zone)
}

// NewIPv6AddressFromMACSection constructs an IPv6 address from a modified EUI-64 (Extended Unique Identifier) address and an IPv6 address 64-bit prefix.
//
// If the supplied MACSize address section is an 8 byte EUI-64, then it must match the required EUI-64 format of xx-xx-ff-fe-xx-xx
// with the ff-fe section in the middle.
//
// If the supplied MACSize address section is a 6 byte MACSize-48 or EUI-48, then the ff-fe pattern will be inserted when converting to IPv6.
//
// The constructor will toggle the MACSize U/L (universal/local) bit as required with EUI-64.
//
// The IPv6 address section must be at least 8 bytes.
//
// Any prefix length in the MACSize address is ignored, while a prefix length in the IPv6 address is preserved but only up to the first 4 segments.
//
// The error is either an addrerr.AddressValueError for sections that are of insufficient segment count,
// oraddrerr.IncompatibleAddressError when attempting to join two MACSize segments, at least one with ranged values, into an equivalent IPV6 segment range.
func NewIPv6AddressFromMAC(prefix *IPv6Address, suffix *MACAddress) (*IPv6Address, addrerr.IncompatibleAddressError) {
	zone := prefix.GetZone()
	zoneStr := NoZone
	if len(zone) > 0 {
		zoneStr = string(zone)
	}
	prefixSection := prefix.GetSection()
	return newIPv6AddressFromMAC(prefixSection, suffix.GetSection(), zoneStr)
}

// when this is called, we know the sections are sufficient length
func newIPv6AddressFromMAC(prefixSection *IPv6AddressSection, suffix *MACAddressSection, zone string) (*IPv6Address, addrerr.IncompatibleAddressError) {
	prefixLen := prefixSection.getPrefixLen()
	if prefixLen != nil && prefixLen.bitCount() > getNetworkPrefixLen(IPv6BitsPerSegment, 0, 4).bitCount() {
		prefixLen = nil
	}
	segments := createSegmentArray(8)
	if err := toIPv6SegmentsFromEUI(segments, 4, suffix, prefixLen); err != nil {
		return nil, err
	}
	prefixSection.copySubSegmentsToSlice(0, 4, segments)
	res := createIPv6Section(segments)
	res.prefixLength = prefixLen
	res.isMult = suffix.isMultiple() || prefixSection.isMultipleTo(4)
	return newIPv6AddressZoned(res, zone), nil
}

// NewIPv6AddressFromMACSection constructs an IPv6 address from a modified EUI-64 (Extended Unique Identifier) address section and an IPv6 address section network prefix.
//
// If the supplied MACSize address section is an 8 byte EUI-64, then it must match the required EUI-64 format of xx-xx-ff-fe-xx-xx
// with the ff-fe section in the middle.
//
// If the supplied MACSize address section is a 6 byte MACSize-48 or EUI-48, then the ff-fe pattern will be inserted when converting to IPv6.
//
// The constructor will toggle the MACSize U/L (universal/local) bit as required with EUI-64.
//
// The IPv6 address section must be at least 8 bytes.
//
// Any prefix length in the MACSize address is ignored, while a prefix length in the IPv6 address is preserved but only up to the first 4 segments.
//
// The error is either an addrerr.AddressValueError for sections that are of insufficient segment count,
// oraddrerr.IncompatibleAddressError when attempting to join two MACSize segments, at least one with ranged values, into an equivalent IPV6 segment range.
func NewIPv6AddressFromMACSection(prefix *IPv6AddressSection, suffix *MACAddressSection) (*IPv6Address, addrerr.AddressError) {
	return newIPv6AddressFromZonedMAC(prefix, suffix, NoZone)
	//suffixSegCount := suffix.GetSegmentCount()
	//if prefix.GetSegmentCount() < 4 || (suffixSegCount != ExtendedUniqueIdentifier48SegmentCount && suffixSegCount != ExtendedUniqueIdentifier64SegmentCount) {
	//	return nil, &addressValueError{addressError: addressError{key: "ipaddress.mac.error.not.eui.convertible"}}
	//}
	//return newIPv6AddressFromMAC(prefix, suffix, NoZone)
}

func NewIPv6AddressFromZonedMAC(prefix *IPv6AddressSection, suffix *MACAddressSection, zone string) (*IPv6Address, addrerr.AddressError) {
	return newIPv6AddressFromZonedMAC(prefix, suffix, zone)
	//suffixSegCount := suffix.GetSegmentCount()
	//if prefix.GetSegmentCount() < 4 || (suffixSegCount != ExtendedUniqueIdentifier48SegmentCount && suffixSegCount != ExtendedUniqueIdentifier64SegmentCount) {
	//	return nil, &addressValueError{addressError: addressError{key: "ipaddress.mac.error.not.eui.convertible"}}
	//}
	//return newIPv6AddressFromMAC(prefix, suffix, zone)
}

func newIPv6AddressFromZonedMAC(prefix *IPv6AddressSection, suffix *MACAddressSection, zone string) (*IPv6Address, addrerr.AddressError) {
	suffixSegCount := suffix.GetSegmentCount()
	if prefix.GetSegmentCount() < 4 || (suffixSegCount != ExtendedUniqueIdentifier48SegmentCount && suffixSegCount != ExtendedUniqueIdentifier64SegmentCount) {
		return nil, &addressValueError{addressError: addressError{key: "ipaddress.mac.error.not.eui.convertible"}}
	}
	return newIPv6AddressFromMAC(prefix, suffix, zone)
}

var zeroIPv6 = initZeroIPv6()

func initZeroIPv6() *IPv6Address {
	div := zeroIPv6Seg
	segs := []*IPv6AddressSegment{div, div, div, div, div, div, div, div}
	section := NewIPv6Section(segs)
	return newIPv6Address(section)
}

//
//
// IPv6Address is an IPv6 address, or a subnet of multiple IPv6 addresses.  Each segment can represent a single value or a range of values.
// The zero value is ::
type IPv6Address struct {
	ipAddressInternal
}

func (addr *IPv6Address) init() *IPv6Address {
	if addr.section == nil {
		return zeroIPv6
	}
	return addr
}

func (addr *IPv6Address) GetCount() *big.Int {
	if addr == nil {
		return bigZero()
	}
	return addr.getCount()
}

func (addr *IPv6Address) IsMultiple() bool {
	return addr != nil && addr.isMultiple()
}

func (addr *IPv6Address) IsPrefixed() bool {
	return addr != nil && addr.isPrefixed()
}

func (addr *IPv6Address) GetBitCount() BitCount {
	return IPv6BitCount
}

func (addr *IPv6Address) GetByteCount() int {
	return IPv6ByteCount
}

func (addr *IPv6Address) GetBitsPerSegment() BitCount {
	return IPv6BitsPerSegment
}

func (addr *IPv6Address) GetBytesPerSegment() int {
	return IPv6BytesPerSegment
}

func (addr *IPv6Address) HasZone() bool {
	return addr != nil && addr.zone != NoZone
}

func (addr *IPv6Address) GetZone() Zone {
	if addr == nil {
		return NoZone
	}
	return addr.zone
}

func (addr *IPv6Address) GetSection() *IPv6AddressSection {
	return addr.init().section.ToIPv6()
}

// Gets the subsection from the series starting from the given index
// The first segment is at index 0.
func (addr *IPv6Address) GetTrailingSection(index int) *IPv6AddressSection {
	return addr.GetSection().GetTrailingSection(index)
}

//// Gets the subsection from the series starting from the given index and ending just before the give endIndex
//// The first segment is at index 0.
func (addr *IPv6Address) GetSubSection(index, endIndex int) *IPv6AddressSection {
	return addr.GetSection().GetSubSection(index, endIndex)
}

func (addr *IPv6Address) GetNetworkSection() *IPv6AddressSection {
	return addr.GetSection().GetNetworkSection()
}

func (addr *IPv6Address) GetNetworkSectionLen(prefLen BitCount) *IPv6AddressSection {
	return addr.GetSection().GetNetworkSectionLen(prefLen)
}

func (addr *IPv6Address) GetHostSection() *IPv6AddressSection {
	return addr.GetSection().GetHostSection()
}

func (addr *IPv6Address) GetHostSectionLen(prefLen BitCount) *IPv6AddressSection {
	return addr.GetSection().GetHostSectionLen(prefLen)
}

func (addr *IPv6Address) GetNetworkMask() *IPv6Address {
	return addr.getNetworkMask(IPv6Network).ToIPv6()
}

func (addr *IPv6Address) GetHostMask() *IPv6Address {
	return addr.getHostMask(IPv6Network).ToIPv6()
}

func (addr *IPv6Address) GetMixedAddressGrouping() (*IPv6v4MixedAddressGrouping, addrerr.IncompatibleAddressError) {
	return addr.init().GetSection().getMixedAddressGrouping()
}

// GetEmbeddedIPv4AddressSection gets the IPv4 section corresponding to the lowest (least-significant) 4 bytes in the original address,
// which will correspond to between 0 and 4 bytes in this address.
// Many IPv4 to IPv6 mapping schemes (but not all) use these 4 bytes for a mapped IPv4 address.
// An error can result when one of the associated IPv6 segments has a range of values that cannot be split into two ranges.
func (addr *IPv6Address) GetEmbeddedIPv4AddressSection() (*IPv4AddressSection, addrerr.IncompatibleAddressError) {
	return addr.init().GetSection().getEmbeddedIPv4AddressSection()
}

// GetEmbeddedIPv4Address gets the IPv4 address corresponding to the lowest (least-significant) 4 bytes in the original address,
// which will correspond to between 0 and 4 bytes in this address.
// Many IPv4 to IPv6 mapping schemes (but not all) use these 4 bytes for a mapped IPv4 address.
// An error can result when one of the associated IPv6 segments has a range of values that cannot be split into two ranges.
func (addr *IPv6Address) GetEmbeddedIPv4Address() (*IPv4Address, addrerr.IncompatibleAddressError) {
	section, err := addr.GetEmbeddedIPv4AddressSection()
	if err != nil {
		return nil, err
	}
	return newIPv4Address(section), nil
}

// GetIPv4AddressSection produces an IPv4 address section from any sequence of bytes in this IPv6 address section
func (addr *IPv6Address) GetIPv4AddressSection(startIndex, endIndex int) (*IPv4AddressSection, addrerr.IncompatibleAddressError) {
	return addr.init().GetSection().GetIPv4AddressSection(startIndex, endIndex)
}

// Get6To4IPv4Address Returns the second and third segments as an {@link IPv4Address}.
func (addr *IPv6Address) Get6To4IPv4Address() (*IPv4Address, addrerr.IncompatibleAddressError) {
	return addr.GetEmbeddedIPv4AddressAt(2)
}

//Produces an IPv4 address from any sequence of 4 bytes in this IPv6 address, starting at the given index.
func (addr *IPv6Address) GetEmbeddedIPv4AddressAt(byteIndex int) (*IPv4Address, addrerr.IncompatibleAddressError) {
	if byteIndex == IPv6MixedOriginalSegmentCount*IPv6BytesPerSegment {
		return addr.GetEmbeddedIPv4Address()
	}
	if byteIndex > IPv6ByteCount-IPv4ByteCount {
		return nil, &addressValueError{
			addressError: addressError{key: "ipaddress.error.invalid.size"},
			val:          byteIndex,
		}
	}
	section, err := addr.init().GetSection().GetIPv4AddressSection(byteIndex, byteIndex+IPv4ByteCount)
	if err != nil {
		return nil, err
	}
	return newIPv4Address(section), nil
}

// GetIPv6Address creates an IPv6 mixed address using the given address for the trailing embedded IPv4 segments
func (addr *IPv6Address) GetIPv6Address(embedded IPv4Address) (*IPv6Address, addrerr.IncompatibleAddressError) {
	return embedded.getIPv6Address(addr.WithoutPrefixLen().getDivisionsInternal())
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (addr *IPv6Address) CopySubSegments(start, end int, segs []*IPv6AddressSegment) (count int) {
	return addr.GetSection().CopySubSegments(start, end, segs)
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (addr *IPv6Address) CopySegments(segs []*IPv6AddressSegment) (count int) {
	return addr.GetSection().CopySegments(segs)
}

// GetSegments returns a slice with the address segments.  The returned slice is not backed by the same array as this address.
func (addr *IPv6Address) GetSegments() []*IPv6AddressSegment {
	return addr.GetSection().GetSegments()
}

// GetSegment returns the segment at the given index
func (addr *IPv6Address) GetSegment(index int) *IPv6AddressSegment {
	return addr.init().getSegment(index).ToIPv6()
}

// GetSegmentCount returns the segment count
func (addr *IPv6Address) GetSegmentCount() int {
	return addr.GetDivisionCount()
}

// GetGenericDivision returns the segment at the given index as an DivisionType
func (addr *IPv6Address) GetGenericDivision(index int) DivisionType {
	return addr.init().getDivision(index)
}

// GetGenericSegment returns the segment at the given index as an AddressSegmentType
func (addr *IPv6Address) GetGenericSegment(index int) AddressSegmentType {
	return addr.init().getSegment(index)
}

// GetDivisionCount returns the segment count
func (addr *IPv6Address) GetDivisionCount() int {
	return addr.init().getDivisionCount()
}

func (addr *IPv6Address) GetIPVersion() IPVersion {
	return IPv6
}

func (addr *IPv6Address) checkIdentity(section *IPv6AddressSection) *IPv6Address {
	if section == nil {
		return nil
	}
	sec := section.ToSectionBase()
	if sec == addr.section {
		return addr
	}
	return newIPv6AddressZoned(section, string(addr.zone))
	//return &IPv6Address{ipAddressInternal{addressInternal{section: sec, zone: addr.zone, cache: &addressCache{}}}}
}

func (addr *IPv6Address) Mask(other *IPv6Address) (masked *IPv6Address, err addrerr.IncompatibleAddressError) {
	return addr.maskPrefixed(other, true)
}

//func (addr *IPv6Address) MaskPrefixed(other *IPv6Address) (masked *IPv6Address, err addrerr.IncompatibleAddressError) {
//	return addr.maskPrefixed(other, true)
//}

func (addr *IPv6Address) maskPrefixed(other *IPv6Address, retainPrefix bool) (masked *IPv6Address, err addrerr.IncompatibleAddressError) {
	addr = addr.init()
	sect, err := addr.GetSection().maskPrefixed(other.GetSection(), retainPrefix)
	if err == nil {
		masked = addr.checkIdentity(sect)
	}
	return
}

func (addr *IPv6Address) BitwiseOr(other *IPv6Address) (masked *IPv6Address, err addrerr.IncompatibleAddressError) {
	return addr.bitwiseOrPrefixed(other, true)
}

//func (addr *IPv6Address) BitwiseOrPrefixed(other *IPv6Address) (masked *IPv6Address, err addrerr.IncompatibleAddressError) {
//	return addr.bitwiseOrPrefixed(other, true)
//}

func (addr *IPv6Address) bitwiseOrPrefixed(other *IPv6Address, retainPrefix bool) (masked *IPv6Address, err addrerr.IncompatibleAddressError) {
	addr = addr.init()
	sect, err := addr.GetSection().bitwiseOrPrefixed(other.GetSection(), retainPrefix)
	if err == nil {
		masked = addr.checkIdentity(sect)
	}
	return
}

func (addr *IPv6Address) Subtract(other *IPv6Address) []*IPv6Address {
	addr = addr.init()
	sects, _ := addr.GetSection().Subtract(other.GetSection())
	sectLen := len(sects)
	if sectLen == 1 {
		sec := sects[0]
		if sec.ToSectionBase() == addr.section {
			return []*IPv6Address{addr}
		}
	}
	res := make([]*IPv6Address, sectLen)
	for i, sect := range sects {
		res[i] = newIPv6AddressZoned(sect, string(addr.zone))
	}
	return res
}

func (addr *IPv6Address) Intersect(other *IPv6Address) *IPv6Address {
	addr = addr.init()
	section, _ := addr.GetSection().Intersect(other.GetSection())
	if section == nil {
		return nil
	}
	return addr.checkIdentity(section)
}

func (addr *IPv6Address) SpanWithRange(other *IPv6Address) *IPv6AddressSeqRange {
	return NewIPv6SeqRange(addr.init(), other.init())
}

func (addr *IPv6Address) GetLower() *IPv6Address {
	return addr.init().getLower().ToIPv6()
}

func (addr *IPv6Address) GetUpper() *IPv6Address {
	return addr.init().getUpper().ToIPv6()
}

// GetLowerIPAddress implements the IPAddressRange interface
func (addr *IPv6Address) GetLowerIPAddress() *IPAddress {
	return addr.GetLower().ToIP()
}

// GetUpperIPAddress implements the IPAddressRange interface
func (addr *IPv6Address) GetUpperIPAddress() *IPAddress {
	return addr.GetUpper().ToIP()
}

func (addr *IPv6Address) IsZeroHostLen(prefLen BitCount) bool {
	return addr.init().isZeroHostLen(prefLen)
}

func (addr *IPv6Address) ToZeroHost() (*IPv6Address, addrerr.IncompatibleAddressError) {
	res, err := addr.init().toZeroHost(false)
	return res.ToIPv6(), err
}

func (addr *IPv6Address) ToZeroHostLen(prefixLength BitCount) (*IPv6Address, addrerr.IncompatibleAddressError) {
	res, err := addr.init().toZeroHostLen(prefixLength)
	return res.ToIPv6(), err
}

func (addr *IPv6Address) ToZeroNetwork() *IPv6Address {
	return addr.init().toZeroNetwork().ToIPv6()
}

func (addr *IPv6Address) IsMaxHostLen(prefLen BitCount) bool {
	return addr.init().isMaxHostLen(prefLen)
}

func (addr *IPv6Address) ToMaxHost() (*IPv6Address, addrerr.IncompatibleAddressError) {
	res, err := addr.init().toMaxHost()
	return res.ToIPv6(), err
}

func (addr *IPv6Address) ToMaxHostLen(prefixLength BitCount) (*IPv6Address, addrerr.IncompatibleAddressError) {
	res, err := addr.init().toMaxHostLen(prefixLength)
	return res.ToIPv6(), err
}

func (addr *IPv6Address) ToPrefixBlock() *IPv6Address {
	return addr.init().toPrefixBlock().ToIPv6()
}

func (addr *IPv6Address) ToPrefixBlockLen(prefLen BitCount) *IPv6Address {
	return addr.init().toPrefixBlockLen(prefLen).ToIPv6()
}

func (addr *IPv6Address) ToBlock(segmentIndex int, lower, upper SegInt) *IPv6Address {
	return addr.init().toBlock(segmentIndex, lower, upper).ToIPv6()
}

func (addr *IPv6Address) WithoutPrefixLen() *IPv6Address {
	if !addr.IsPrefixed() {
		return addr
	}
	return addr.init().withoutPrefixLen().ToIPv6()
}

func (addr *IPv6Address) SetPrefixLen(prefixLen BitCount) *IPv6Address {
	return addr.init().setPrefixLen(prefixLen).ToIPv6()
}

func (addr *IPv6Address) SetPrefixLenZeroed(prefixLen BitCount) (*IPv6Address, addrerr.IncompatibleAddressError) {
	res, err := addr.init().setPrefixLenZeroed(prefixLen)
	return res.ToIPv6(), err
}

func (addr *IPv6Address) AdjustPrefixLen(prefixLen BitCount) *IPv6Address {
	return addr.init().adjustPrefixLen(prefixLen).ToIPv6()
}

func (addr *IPv6Address) AdjustPrefixLenZeroed(prefixLen BitCount) (*IPv6Address, addrerr.IncompatibleAddressError) {
	res, err := addr.init().adjustPrefixLenZeroed(prefixLen)
	return res.ToIPv6(), err
}

func (addr *IPv6Address) AssignPrefixForSingleBlock() *IPv6Address {
	return addr.init().assignPrefixForSingleBlock().ToIPv6()
}

func (addr *IPv6Address) AssignMinPrefixForBlock() *IPv6Address {
	return addr.init().assignMinPrefixForBlock().ToIPv6()
}

func (addr *IPv6Address) ContainsPrefixBlock(prefixLen BitCount) bool {
	return addr.init().ipAddressInternal.ContainsPrefixBlock(prefixLen)
}

func (addr *IPv6Address) ContainsSinglePrefixBlock(prefixLen BitCount) bool {
	return addr.init().ipAddressInternal.ContainsSinglePrefixBlock(prefixLen)
}

func (addr *IPv6Address) GetMinPrefixLenForBlock() BitCount {
	return addr.init().ipAddressInternal.GetMinPrefixLenForBlock()
}

func (addr *IPv6Address) GetPrefixLenForSingleBlock() PrefixLen {
	return addr.init().ipAddressInternal.GetPrefixLenForSingleBlock()
}

func (addr *IPv6Address) GetValue() *big.Int {
	return addr.init().section.GetValue()
}

func (addr *IPv6Address) GetUpperValue() *big.Int {
	return addr.init().section.GetUpperValue()
}

func (addr *IPv6Address) GetNetIPAddr() net.IPAddr {
	return net.IPAddr{
		IP:   addr.GetNetIP(),
		Zone: string(addr.GetZone()),
	}
}

func (addr *IPv6Address) GetNetIP() net.IP {
	return addr.Bytes()
}

func (addr *IPv6Address) CopyNetIP(bytes net.IP) net.IP {
	return addr.CopyBytes(bytes)
}

func (addr *IPv6Address) GetUpperNetIP() net.IP {
	return addr.UpperBytes()
}

func (addr *IPv6Address) CopyUpperNetIP(bytes net.IP) net.IP {
	return addr.CopyUpperBytes(bytes)
}

func (addr *IPv6Address) Bytes() []byte {
	return addr.init().section.Bytes()
}

func (addr *IPv6Address) UpperBytes() []byte {
	return addr.init().section.UpperBytes()
}

func (addr *IPv6Address) CopyBytes(bytes []byte) []byte {
	return addr.init().section.CopyBytes(bytes)
}

func (addr *IPv6Address) CopyUpperBytes(bytes []byte) []byte {
	return addr.init().section.CopyUpperBytes(bytes)
}

func (addr *IPv6Address) IsMax() bool {
	return addr.init().section.IsMax()
}

func (addr *IPv6Address) IncludesMax() bool {
	return addr.init().section.IncludesMax()
}

// TestBit computes (this & (1 << n)) != 0), using the lower value of this segment.
func (addr *IPv6Address) TestBit(n BitCount) bool {
	return addr.init().testBit(n)
}

// Returns true if the bit in the lower value of this segment at the given index is 1, where index 0 is the most significant bit.
func (addr *IPv6Address) IsOneBit(bitIndex BitCount) bool {
	return addr.init().isOneBit(bitIndex)
}

func (addr *IPv6Address) PrefixEqual(other AddressType) bool {
	return addr.init().prefixEquals(other)
}

func (addr *IPv6Address) PrefixContains(other AddressType) bool {
	return addr.init().prefixContains(other)
}

func (addr *IPv6Address) Contains(other AddressType) bool {
	if other == nil || other.ToAddressBase() == nil {
		return true
	} else if addr == nil {
		return false
	}
	addr = addr.init()
	otherAddr := other.ToAddressBase()
	if addr.ToAddressBase() == otherAddr {
		return true
	}
	return otherAddr.getAddrType() == ipv6Type && addr.section.sameCountTypeContains(otherAddr.GetSection()) &&
		addr.isSameZone(other.ToAddressBase())
}

func (addr *IPv6Address) Compare(item AddressItem) int {
	return CountComparator.Compare(addr, item)
}

func (addr *IPv6Address) Equal(other AddressType) bool {
	if addr == nil {
		return other == nil || other.ToAddressBase() == nil
	}
	return other.ToAddressBase().getAddrType() == ipv6Type && addr.init().section.sameCountTypeEquals(other.ToAddressBase().GetSection()) &&
		addr.isSameZone(other.ToAddressBase())
}

// CompareSize returns whether this subnet has more elements than the other, returning -1 if this subnet has less, 1 if more, and 0 if both have the same count of individual addresses
func (addr *IPv6Address) CompareSize(other AddressType) int {
	if addr == nil {
		if other != nil && other.ToAddressBase() != nil {
			// we have size 0, other has size >= 1
			return -1
		}
		return 0
	}
	return addr.init().compareSize(other)
}

func (addr *IPv6Address) MatchesWithMask(other *IPv6Address, mask *IPv6Address) bool {
	return addr.init().GetSection().MatchesWithMask(other.GetSection(), mask.GetSection())
}

func (addr *IPv6Address) GetMaxSegmentValue() SegInt {
	return addr.init().getMaxSegmentValue()
}

func (addr *IPv6Address) WithoutZone() *IPv6Address {
	if addr.HasZone() {
		return newIPv6Address(addr.GetSection())
	}
	return addr
}

func (addr *IPv6Address) SetZone(zone string) *IPv6Address {
	if Zone(zone) == addr.GetZone() {
		return addr
	}
	return newIPv6AddressZoned(addr.GetSection(), zone)
}

func (addr *IPv6Address) ToSequentialRange() *IPv6AddressSeqRange {
	if addr == nil {
		return nil
	}
	addr = addr.init().WithoutPrefixLen().WithoutZone()
	return newSeqRangeUnchecked(
		addr.GetLowerIPAddress(),
		addr.GetUpperIPAddress(),
		addr.isMultiple()).ToIPv6()
}

func (addr *IPv6Address) ToAddressString() *IPAddressString {
	return addr.init().ToIP().ToAddressString()
}

func (addr *IPv6Address) IncludesZeroHostLen(networkPrefixLength BitCount) bool {
	return addr.init().includesZeroHostLen(networkPrefixLength)
}

func (addr *IPv6Address) IncludesMaxHostLen(networkPrefixLength BitCount) bool {
	return addr.init().includesMaxHostLen(networkPrefixLength)
}

// IsLinkLocal returns whether the address is link local, whether unicast or multicast.
func (addr *IPv6Address) IsLinkLocal() bool {
	firstSeg := addr.GetSegment(0)
	return (addr.IsMulticast() && firstSeg.matchesWithMask(2, 0xf)) || // ffx2::/16
		//1111 1110 10 .... fe8x currently only in use
		firstSeg.MatchesWithPrefixMask(0xfe80, 10)
}

// IsLocal returns true if the address is link local, site local, organization local, administered locally, or unspecified.
// This includes both unicast and multicast.
func (addr *IPv6Address) IsLocal() bool {
	if addr.IsMulticast() {
		/*
				 [RFC4291][RFC7346]
				 11111111|flgs|scop
					scope 4 bits
					 1  Interface-Local scope
			         2  Link-Local scope
			         3  Realm-Local scope
			         4  Admin-Local scope
			         5  Site-Local scope
			         8  Organization-Local scope
			         E  Global scope
		*/
		firstSeg := addr.GetSegment(0)
		if firstSeg.matchesWithMask(8, 0xf) {
			return true
		}
		if firstSeg.GetValueCount() <= 5 &&
			(firstSeg.getSegmentValue()&0xf) >= 1 && (firstSeg.getUpperSegmentValue()&0xf) <= 5 {
			//all values fall within the range from interface local to site local
			return true
		}
		//source specific multicast
		//rfc4607 and https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml
		//FF3X::8000:0 - FF3X::FFFF:FFFF	Reserved for local host allocation	[RFC4607]
		if firstSeg.MatchesWithPrefixMask(0xff30, 12) && addr.GetSegment(6).MatchesWithPrefixMask(0x8000, 1) {
			return true
		}
	}
	return addr.IsLinkLocal() || addr.IsSiteLocal() || addr.IsUniqueLocal() || addr.IsAnyLocal()
}

// The unspecified address is the address that is all zeros.
func (addr *IPv6Address) IsUnspecified() bool {
	return addr.section == nil || addr.IsZero()
}

// Returns whether this address is the address which binds to any address on the local host.
// This is the address that has the value of 0, aka the unspecified address.
func (addr *IPv6Address) IsAnyLocal() bool {
	return addr.section == nil || addr.IsZero()
}

func (addr *IPv6Address) IsSiteLocal() bool {
	firstSeg := addr.GetSegment(0)
	return (addr.IsMulticast() && firstSeg.matchesWithMask(5, 0xf)) || // ffx5::/16
		//1111 1110 11 ...
		firstSeg.MatchesWithPrefixMask(0xfec0, 10) // deprecated RFC 3879
}

func (addr *IPv6Address) IsUniqueLocal() bool {
	//RFC 4193
	return addr.GetSegment(0).MatchesWithPrefixMask(0xfc00, 7)
}

// IsIPv4Mapped returns whether the address is IPv4-mapped
//
// ::ffff:x:x/96 indicates IPv6 address mapped to IPv4
func (addr *IPv6Address) IsIPv4Mapped() bool {
	//::ffff:x:x/96 indicates IPv6 address mapped to IPv4
	if addr.GetSegment(5).Matches(IPv6MaxValuePerSegment) {
		for i := 0; i < 5; i++ {
			if !addr.GetSegment(i).IsZero() {
				return false
			}
		}
		return true
	}
	return false
}

// IsIPv4Compatible returns whether the address is IPv4-compatible
func (addr *IPv6Address) IsIPv4Compatible() bool {
	return addr.GetSegment(0).IsZero() && addr.GetSegment(1).IsZero() && addr.GetSegment(2).IsZero() &&
		addr.GetSegment(3).IsZero() && addr.GetSegment(4).IsZero() && addr.GetSegment(5).IsZero()
}

// Is6To4 returns whether the address is IPv6 to IPv4 relay
func (addr *IPv6Address) Is6To4() bool {
	//2002::/16
	return addr.GetSegment(0).Matches(0x2002)
}

// Is6Over4 returns whether the address is 6over4
func (addr *IPv6Address) Is6Over4() bool {
	return addr.GetSegment(0).Matches(0xfe80) &&
		addr.GetSegment(1).IsZero() && addr.GetSegment(2).IsZero() &&
		addr.GetSegment(3).IsZero() && addr.GetSegment(4).IsZero() &&
		addr.GetSegment(5).IsZero()
}

// IsTeredo returns whether the address is Teredo
func (addr *IPv6Address) IsTeredo() bool {
	//2001::/32
	return addr.GetSegment(0).Matches(0x2001) && addr.GetSegment(1).IsZero()
}

// IsIsatap returns whether the address is ISATAP
func (addr *IPv6Address) IsIsatap() bool {
	// 0,1,2,3 is fe80::
	// 4 can be 0200
	return addr.GetSegment(0).Matches(0xfe80) &&
		addr.GetSegment(1).IsZero() &&
		addr.GetSegment(2).IsZero() &&
		addr.GetSegment(3).IsZero() &&
		(addr.GetSegment(4).IsZero() || addr.GetSegment(4).Matches(0x200)) &&
		addr.GetSegment(5).Matches(0x5efe)
}

// IsIPv4Translatable returns whether the address is IPv4 translatable as in rfc 2765
func (addr *IPv6Address) IsIPv4Translatable() bool { //rfc 2765
	//::ffff:0:x:x/96 indicates IPv6 addresses translated from IPv4
	return addr.GetSegment(4).Matches(0xffff) &&
		addr.GetSegment(5).IsZero() &&
		addr.GetSegment(0).IsZero() &&
		addr.GetSegment(1).IsZero() &&
		addr.GetSegment(2).IsZero() &&
		addr.GetSegment(3).IsZero()
}

// IsWellKnownIPv4Translatable returns whether the address has the well-known prefix for IPv4 translatable addresses as in rfc 6052 and 6144
func (addr *IPv6Address) IsWellKnownIPv4Translatable() bool { //rfc 6052 rfc 6144
	//64:ff9b::/96 prefix for auto ipv4/ipv6 translation
	if addr.GetSegment(0).Matches(0x64) && addr.GetSegment(1).Matches(0xff9b) {
		for i := 2; i <= 5; i++ {
			if !addr.GetSegment(i).IsZero() {
				return false
			}
		}
		return true
	}
	return false
}

func (addr *IPv6Address) IsMulticast() bool {
	// 11111111...
	return addr.GetSegment(0).MatchesWithPrefixMask(0xff00, 8)
}

// IsLoopback returns whether this address is a loopback address, such as
// [::1] (aka [0:0:0:0:0:0:0:1]) or 127.0.0.1
func (addr *IPv6Address) IsLoopback() bool {
	if addr.section == nil {
		return false
	}
	//::1
	i := 0
	lim := addr.GetSegmentCount() - 1
	for ; i < lim; i++ {
		if !addr.GetSegment(i).IsZero() {
			return false
		}
	}
	return addr.GetSegment(i).Matches(1)
}

func (addr *IPv6Address) Iterator() IPv6AddressIterator {
	if addr == nil {
		return ipv6AddressIterator{nilAddrIterator()}
	}
	return ipv6AddressIterator{addr.init().addrIterator(nil)}
}

func (addr *IPv6Address) PrefixIterator() IPv6AddressIterator {
	return ipv6AddressIterator{addr.init().prefixIterator(false)}
}

func (addr *IPv6Address) PrefixBlockIterator() IPv6AddressIterator {
	return ipv6AddressIterator{addr.init().prefixIterator(true)}
}

func (addr *IPv6Address) BlockIterator(segmentCount int) IPv6AddressIterator {
	return ipv6AddressIterator{addr.init().blockIterator(segmentCount)}
}

func (addr *IPv6Address) SequentialBlockIterator() IPv6AddressIterator {
	return ipv6AddressIterator{addr.init().sequentialBlockIterator()}
}

func (addr *IPv6Address) GetSequentialBlockIndex() int {
	return addr.init().getSequentialBlockIndex()
}

func (addr *IPv6Address) GetSequentialBlockCount() *big.Int {
	return addr.getSequentialBlockCount()
}

func (addr *IPv6Address) IncrementBoundary(increment int64) *IPv6Address {
	return addr.init().incrementBoundary(increment).ToIPv6()
}

func (addr *IPv6Address) Increment(increment int64) *IPv6Address {
	return addr.init().increment(increment).ToIPv6()
}

func (addr *IPv6Address) SpanWithPrefixBlocks() []*IPv6Address {
	if addr.IsSequential() {
		if addr.IsSinglePrefixBlock() {
			return []*IPv6Address{addr}
		}
		wrapped := WrapIPAddress(addr.ToIP())
		spanning := getSpanningPrefixBlocks(wrapped, wrapped)
		return cloneToIPv6Addrs(spanning)
	}
	wrapped := WrapIPAddress(addr.ToIP())
	return cloneToIPv6Addrs(spanWithPrefixBlocks(wrapped))
}

func (addr *IPv6Address) SpanWithPrefixBlocksTo(other *IPv6Address) []*IPv6Address {
	return cloneToIPv6Addrs(
		getSpanningPrefixBlocks(
			WrapIPAddress(addr.ToIP()),
			WrapIPAddress(other.ToIP()),
		),
	)
}

func (addr *IPv6Address) SpanWithSequentialBlocks() []*IPv6Address {
	if addr.IsSequential() {
		return []*IPv6Address{addr}
	}
	wrapped := WrapIPAddress(addr.ToIP())
	return cloneToIPv6Addrs(spanWithSequentialBlocks(wrapped))
}

func (addr *IPv6Address) SpanWithSequentialBlocksTo(other *IPv6Address) []*IPv6Address {
	return cloneToIPv6Addrs(
		getSpanningSequentialBlocks(
			WrapIPAddress(addr.ToIP()),
			WrapIPAddress(other.ToIP()),
		),
	)
}

func (addr *IPv6Address) CoverWithPrefixBlockTo(other *IPv6Address) *IPv6Address {
	return addr.init().coverWithPrefixBlockTo(other.ToIP()).ToIPv6()
}

func (addr *IPv6Address) CoverWithPrefixBlock() *IPv6Address {
	return addr.init().coverWithPrefixBlock().ToIPv6()
}

// MergeToSequentialBlocks merges this with the list of addresses to produce the smallest array of blocks that are sequential
//
// The resulting array is sorted from lowest address value to highest, regardless of the size of each prefix block.
func (addr *IPv6Address) MergeToSequentialBlocks(addrs ...*IPv6Address) []*IPv6Address {
	series := cloneIPv6Addrs(addr, addrs)
	blocks := getMergedSequentialBlocks(series)
	return cloneToIPv6Addrs(blocks)
}

// MergeToPrefixBlocks merges this with the list of sections to produce the smallest array of prefix blocks.
//
// The resulting array is sorted from lowest address value to highest, regardless of the size of each prefix block.
func (addr *IPv6Address) MergeToPrefixBlocks(addrs ...*IPv6Address) []*IPv6Address {
	series := cloneIPv6Addrs(addr, addrs)
	blocks := getMergedPrefixBlocks(series)
	return cloneToIPv6Addrs(blocks)
}

func (addr *IPv6Address) ReverseBytes() (*IPv6Address, addrerr.IncompatibleAddressError) {
	res, err := addr.GetSection().ReverseBytes()
	if err != nil {
		return nil, err
	}
	return addr.checkIdentity(res), nil
}

func (addr *IPv6Address) ReverseBits(perByte bool) (*IPv6Address, addrerr.IncompatibleAddressError) {
	res, err := addr.GetSection().ReverseBits(perByte)
	if err != nil {
		return nil, err
	}
	return addr.checkIdentity(res), nil
}

func (addr *IPv6Address) ReverseSegments() *IPv6Address {
	return addr.checkIdentity(addr.GetSection().ReverseSegments())
}

// ReplaceLen replaces segments starting from startIndex and ending before endIndex with the same number of segments starting at replacementStartIndex from the replacement section
func (addr *IPv6Address) ReplaceLen(startIndex, endIndex int, replacement *IPv6Address, replacementIndex int) *IPv6Address {
	startIndex, endIndex, replacementIndex =
		adjust1To1Indices(startIndex, endIndex, IPv6SegmentCount, replacementIndex, IPv6SegmentCount)
	if startIndex == endIndex {
		return addr
	}
	count := endIndex - startIndex
	return addr.checkIdentity(addr.GetSection().ReplaceLen(startIndex, endIndex, replacement.GetSection(), replacementIndex, replacementIndex+count))
}

// Replace replaces segments starting from startIndex with segments from the replacement section
func (addr *IPv6Address) Replace(startIndex int, replacement *IPv6AddressSection) *IPv6Address {
	startIndex, endIndex, replacementIndex :=
		adjust1To1Indices(startIndex, startIndex+replacement.GetSegmentCount(), IPv6SegmentCount, 0, replacement.GetSegmentCount())
	count := endIndex - startIndex
	return addr.checkIdentity(addr.GetSection().ReplaceLen(startIndex, endIndex, replacement, replacementIndex, replacementIndex+count))
}

func (addr *IPv6Address) GetLeadingBitCount(ones bool) BitCount {
	return addr.GetSection().GetLeadingBitCount(ones)
}

func (addr *IPv6Address) GetTrailingBitCount(ones bool) BitCount {
	return addr.GetSection().GetTrailingBitCount(ones)
}

func (addr *IPv6Address) GetNetwork() IPAddressNetwork {
	return IPv6Network
}

func (addr *IPv6Address) IsEUI64() bool {
	return addr.GetSegment(6).MatchesWithPrefixMask(0xfe00, 8) &&
		addr.GetSegment(5).MatchesWithMask(0xff, 0xff)
}

// ToEUI converts to the associated MACAddress.
// An error is returned if the 0xfffe pattern is missing in segments 5 and 6,
// or if an IPv6 segment's range of values cannot be split into two ranges of values.
func (addr *IPv6Address) ToEUI(extended bool) (*MACAddress, addrerr.IncompatibleAddressError) {
	segs, err := addr.toEUISegments(extended)
	if err != nil {
		return nil, err
	}
	sect := newMACSectionEUI(segs)
	return newMACAddress(sect), nil
}

//prefix length in this section is ignored when converting to MACSize
func (addr *IPv6Address) toEUISegments(extended bool) ([]*AddressDivision, addrerr.IncompatibleAddressError) {
	seg1 := addr.GetSegment(5)
	seg2 := addr.GetSegment(6)
	if !seg1.MatchesWithMask(0xff, 0xff) || !seg2.MatchesWithPrefixMask(0xfe00, 8) {
		return nil, &incompatibleAddressError{addressError{key: "ipaddress.mac.error.not.eui.convertible"}}
	}
	macStartIndex := 0
	var macSegCount int
	if extended {
		macSegCount = ExtendedUniqueIdentifier64SegmentCount
	} else {
		macSegCount = ExtendedUniqueIdentifier48SegmentCount
	}
	newSegs := createSegmentArray(macSegCount)
	seg0 := addr.GetSegment(4)
	if err := seg0.splitIntoMACSegments(newSegs, macStartIndex); err != nil {
		return nil, err
	}
	//toggle the u/l bit
	macSegment0 := newSegs[0].ToMAC()
	lower0 := macSegment0.GetSegmentValue()
	upper0 := macSegment0.GetUpperSegmentValue()
	mask2ndBit := SegInt(0x2)
	if !macSegment0.MatchesWithMask(mask2ndBit&lower0, mask2ndBit) { // ensures that bit remains constant
		return nil, &incompatibleAddressError{addressError{key: "ipaddress.mac.error.not.eui.convertible"}}
	}
	lower0 ^= mask2ndBit //flip the universal/local bit
	upper0 ^= mask2ndBit
	newSegs[0] = NewMACRangeSegment(MACSegInt(lower0), MACSegInt(upper0)).ToDiv()
	macStartIndex += 2
	if err := seg1.splitIntoMACSegments(newSegs, macStartIndex); err != nil { //a ff fe b
		return nil, err
	}
	if extended {
		macStartIndex += 2
		if err := seg2.splitIntoMACSegments(newSegs, macStartIndex); err != nil {
			return nil, err
		}
	} else {
		first := newSegs[macStartIndex]
		if err := seg2.splitIntoMACSegments(newSegs, macStartIndex); err != nil {
			return nil, err
		}
		newSegs[macStartIndex] = first
	}
	macStartIndex += 2
	seg3 := addr.GetSegment(7)
	if err := seg3.splitIntoMACSegments(newSegs, macStartIndex); err != nil {
		return nil, err
	}
	return newSegs, nil
}

func (addr IPv6Address) Format(state fmt.State, verb rune) {
	addr.init().format(state, verb)
}

func (addr *IPv6Address) String() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().addressInternal.toString()
}

func (addr *IPv6Address) GetSegmentStrings() []string {
	if addr == nil {
		return nil
	}
	return addr.init().getSegmentStrings()
}

func (addr *IPv6Address) ToCanonicalString() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().toCanonicalString()
}

func (addr *IPv6Address) ToNormalizedString() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().toNormalizedString()
}

func (addr *IPv6Address) ToCompressedString() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().toCompressedString()
}

func (addr *IPv6Address) ToCanonicalWildcardString() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().toCanonicalWildcardString()
}

func (addr *IPv6Address) ToNormalizedWildcardString() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().toNormalizedWildcardString()
}

func (addr *IPv6Address) ToSegmentedBinaryString() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().toSegmentedBinaryString()
}

func (addr *IPv6Address) ToSQLWildcardString() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().toSQLWildcardString()
}

func (addr *IPv6Address) ToFullString() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().toFullString()
}

func (addr *IPv6Address) ToPrefixLenString() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().toPrefixLenString()
}

func (addr *IPv6Address) ToSubnetString() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().toSubnetString()
}

func (addr *IPv6Address) ToCompressedWildcardString() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().toCompressedWildcardString()
}

func (addr *IPv6Address) ToReverseDNSString() (string, addrerr.IncompatibleAddressError) {
	if addr == nil {
		return nilString(), nil
	}
	return addr.init().toReverseDNSString()
}

func (addr *IPv6Address) ToHexString(with0xPrefix bool) (string, addrerr.IncompatibleAddressError) {
	if addr == nil {
		return nilString(), nil
	}
	return addr.init().toHexString(with0xPrefix)
}

func (addr *IPv6Address) ToOctalString(with0Prefix bool) (string, addrerr.IncompatibleAddressError) {
	if addr == nil {
		return nilString(), nil
	}
	return addr.init().toOctalString(with0Prefix)
}

func (addr *IPv6Address) ToBinaryString(with0bPrefix bool) (string, addrerr.IncompatibleAddressError) {
	if addr == nil {
		return nilString(), nil
	}
	return addr.init().toBinaryString(with0bPrefix)
}

// ToMixedString produces the mixed IPv6/IPv4 string.  It is the shortest such string (ie fully compressed).
// For some address sections with ranges of values in the IPv4 part of the address, there is not mixed string, and an error is returned.
func (addr *IPv6Address) ToMixedString() (string, addrerr.IncompatibleAddressError) {
	if addr == nil {
		return nilString(), nil
	}
	if addr.hasZone() {
		cache := addr.getStringCache()
		if cache == nil {
			return addr.GetSection().toMixedStringZoned(addr.zone)
		}
		var cacheField **string
		cacheField = &cache.mixedString
		return cacheStrErr(cacheField,
			func() (string, addrerr.IncompatibleAddressError) {
				return addr.GetSection().toMixedStringZoned(addr.zone)
			})
	}
	return addr.GetSection().toMixedString()

}

// ToCustomString produces a string given the string options.
// Errors can result from split digits with ranged values, or mixed IPv4/v6 with ranged values, when a range cannot be split up.
// Options without split digits or mixed addresses do not produce errors.
// Single addresses do not produce errors.
func (addr *IPv6Address) ToCustomString(stringOptions IPv6StringOptions) (string, addrerr.IncompatibleAddressError) {
	if addr == nil {
		return nilString(), nil
	}
	return addr.GetSection().toCustomString(stringOptions, addr.zone)
}

func (addr *IPv6Address) ToAddressBase() *Address {
	return addr.ToIP().ToAddressBase()
}

func (addr *IPv6Address) ToIP() *IPAddress {
	if addr != nil {
		addr = addr.init()
	}
	return (*IPAddress)(addr)
}

func (addr *IPv6Address) Wrap() WrappedIPAddress {
	return WrapIPAddress(addr.ToIP())
}
