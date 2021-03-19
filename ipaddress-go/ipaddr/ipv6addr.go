package ipaddr

import (
	"math/big"
	"net"
	"unsafe"
)

const (
	IPv6SegmentSeparator           = ':'
	IPv6ZoneSeparator              = '%'
	IPv6AlternativeZoneSeparator   = '\u00a7'
	IPv6BitsPerSegment             = 16
	IPv6BytesPerSegment            = 2
	IPv6SegmentCount               = 8
	IPv6MixedReplacedSegmentCount  = 2
	IPv6MixedOriginalSegmentCount  = 6
	IPv6ByteCount                  = 16
	IPv6BitCount                   = 128
	IPv6DefaultTextualRadix        = 16
	IPv6MaxValuePerSegment         = 0xffff
	IPv6ReverseDnsSuffix           = ".ip6.arpa"
	IPv6ReverseDnsSuffixDeprecated = ".ip6.int"

	IPv6UncSegmentSeparator = '-'
	IPv6UncZoneSeparator    = 's'
	IPv6UncRangeSeparator   = AlternativeRangeSeparator
	IPv6UncSuffix           = ".ipv6-literal.net"

	IPv6SegmentMaxChars    = 4
	IPv6SegmentBitsPerChar = 4
)

type Zone string

func (zone Zone) IsEmpty() bool {
	return zone == ""
}

const noZone Zone = ""

func NewIPv6Address(section *IPv6AddressSection) *IPv6Address {
	return NewIPv6AddressZoned(section, noZone)
}

func NewIPv6AddressZoned(section *IPv6AddressSection, zone Zone) *IPv6Address {
	return createAddress(section.ToAddressSection(), zone).ToIPv6Address()
	//return &IPv6Address{
	//	ipAddressInternal{
	//		addressInternal{
	//			section: section.ToAddressSection(),
	//			zone:    zone,
	//			cache:   &addressCache{},
	//		},
	//	},
	//}
}

func NewIPv6AddressFromIP(bytes net.IP) (addr *IPv6Address, err AddressValueException) {
	section, err := NewIPv6AddressSectionFromSegmentedBytes(bytes, IPv6SegmentCount)
	if err == nil {
		addr = NewIPv6Address(section)
	}
	return
}

func NewIPv6AddressFromPrefixedIP(bytes []byte, prefixLength PrefixLen) (addr *IPv6Address, err AddressValueException) {
	section, err := NewIPv6AddressSectionFromPrefixedBytes(bytes, IPv6SegmentCount, prefixLength)
	if err == nil {
		addr = NewIPv6Address(section)
	}
	return
}

func NewIPv6AddressFromIPAddr(ipAddr net.IPAddr) (addr *IPv6Address, err AddressValueException) {
	addr, err = NewIPv6AddressFromIP(ipAddr.IP)
	if err == nil {
		addr.zone = Zone(ipAddr.Zone)
	}
	return
}

func NewIPv6AddressFromValues(vals SegmentValueProvider) (addr *IPv6Address) {
	section := NewIPv6AddressSectionFromValues(vals, IPv6SegmentCount)
	addr = NewIPv6Address(section)
	return
}

func NewIPv6AddressFromPrefixedValues(vals SegmentValueProvider, prefixLength PrefixLen) (addr *IPv6Address, err AddressValueException) {
	section := NewIPv6AddressSectionFromPrefixedValues(vals, IPv6SegmentCount, prefixLength)
	addr = NewIPv6Address(section)
	return
}

func NewIPv6AddressFromRange(vals, upperVals SegmentValueProvider) (addr *IPv6Address) {
	section := NewIPv6AddressSectionFromRangeValues(vals, upperVals, IPv6SegmentCount)
	addr = NewIPv6Address(section)
	return
}

func NewIPv6AddressFromPrefixedRange(vals, upperVals SegmentValueProvider, prefixLength PrefixLen) (addr *IPv6Address, err AddressValueException) {
	section := NewIPv6AddressSectionFromPrefixedRangeValues(vals, upperVals, IPv6SegmentCount, prefixLength)
	addr = NewIPv6Address(section)
	return
}

func NewIPv6AddressFromZonedRange(vals, upperVals SegmentValueProvider, zone Zone) (addr *IPv6Address) {
	section := NewIPv6AddressSectionFromRangeValues(vals, upperVals, IPv6SegmentCount)
	addr = NewIPv6AddressZoned(section, zone)
	return
}

var zeroIPv6 = initZeroIPv6()

func initZeroIPv6() *IPv6Address {
	div := NewIPv6Segment(0).ToAddressDivision()
	segs := []*AddressDivision{div, div, div, div, div, div, div, div}
	section, _ := newIPv6AddressSection(segs, 0, false)
	return NewIPv6Address(section)
}

//
//
// IPv6Address is an IPv6 address, or a subnet of multiple IPv6 addresses.  Each segment can represent a single value or a range of values.
// The zero value is ::
type IPv6Address struct {
	ipAddressInternal
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

func (addr IPv6Address) String() string {
	address := addr.init()
	//TODO a different default string
	return address.addressInternal.String()
}

func (addr *IPv6Address) init() *IPv6Address {
	if addr.section == nil {
		return zeroIPv6
	}
	return addr
}

func (addr *IPv6Address) HasZone() bool {
	return addr.zone != noZone
}

func (addr *IPv6Address) GetSection() *IPv6AddressSection {
	return addr.init().section.ToIPv6AddressSection()
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
	return addr.init().getSegment(index).ToIPv6AddressSegment()
}

// GetSegmentCount returns the segment count
func (addr *IPv6Address) GetSegmentCount() int {
	return addr.GetDivisionCount()
}

// GetGenericDivision returns the segment at the given index as an AddressGenericDivision
func (addr *IPv6Address) GetGenericDivision(index int) AddressGenericDivision {
	return addr.init().getDivision(index)
}

// GetDivisionCount returns the segment count
func (addr *IPv6Address) GetDivisionCount() int {
	return addr.init().GetDivisionCount()
}

func (addr *IPv6Address) GetIPVersion() IPVersion {
	return IPv6
}

func (addr *IPv6Address) checkIdentity(section *IPv6AddressSection) *IPv6Address {
	sec := section.ToAddressSection()
	if sec == addr.section {
		return addr
	}
	return &IPv6Address{ipAddressInternal{addressInternal{section: sec, zone: addr.zone, cache: &addressCache{}}}}
}

func (addr *IPv6Address) Mask(other *IPv6Address) (masked *IPv6Address, err error) {
	addr = addr.init()
	sect, err := addr.GetSection().Mask(other.GetSection())
	if err == nil {
		masked = addr.checkIdentity(sect)
	}
	return
}

func (addr *IPv6Address) SpanWithRange(other *IPv6Address) *IPv6AddressSeqRange {
	return NewIPv6SeqRange(addr.init(), other.init())
}

func (addr *IPv6Address) GetLower() *IPv6Address {
	return addr.init().getLower().ToIPv6Address()
}

func (addr *IPv6Address) GetUpper() *IPv6Address {
	return addr.init().getUpper().ToIPv6Address()
}

func (addr *IPv6Address) ToPrefixBlock() *IPv6Address {
	return addr.init().toPrefixBlock().ToIPv6Address()
}

func (addr *IPv6Address) ToPrefixBlockLen(prefLen BitCount) *IPv6Address {
	return addr.init().toPrefixBlockLen(prefLen).ToIPv6Address()
}

func (addr *IPv6Address) WithoutPrefixLength() *IPv6Address {
	return addr.init().withoutPrefixLength().ToIPv6Address()
}

func (addr *IPv6Address) ContainsPrefixBlock(prefixLen BitCount) bool {
	return addr.init().ipAddressInternal.ContainsPrefixBlock(prefixLen)
}

func (addr *IPv6Address) ContainsSinglePrefixBlock(prefixLen BitCount) bool {
	return addr.init().ipAddressInternal.ContainsSinglePrefixBlock(prefixLen)
}

func (addr *IPv6Address) GetMinPrefixLengthForBlock() BitCount {
	return addr.init().ipAddressInternal.GetMinPrefixLengthForBlock()
}

func (addr *IPv6Address) GetPrefixLengthForSingleBlock() PrefixLen {
	return addr.init().ipAddressInternal.GetPrefixLengthForSingleBlock()
}

func (addr *IPv6Address) GetValue() *big.Int {
	return addr.init().section.GetValue()
}

func (addr *IPv6Address) GetUpperValue() *big.Int {
	return addr.init().section.GetUpperValue()
}

func (addr *IPv6Address) GetIP() net.IP {
	return addr.GetBytes()
}

func (addr *IPv6Address) CopyIP(bytes net.IP) net.IP {
	return addr.CopyBytes(bytes)
}

func (addr *IPv6Address) GetUpperIP() net.IP {
	return addr.GetUpperBytes()
}

func (addr *IPv6Address) CopyUpperIP(bytes net.IP) net.IP {
	return addr.CopyUpperBytes(bytes)
}

func (addr *IPv6Address) GetBytes() []byte {
	return addr.init().section.GetBytes()
}

func (addr *IPv6Address) GetUpperBytes() []byte {
	return addr.init().section.GetUpperBytes()
}

func (addr *IPv6Address) CopyBytes(bytes []byte) []byte {
	return addr.init().section.CopyBytes(bytes)
}

func (addr *IPv6Address) CopyUpperBytes(bytes []byte) []byte {
	return addr.init().section.CopyUpperBytes(bytes)
}

func (addr *IPv6Address) Contains(other AddressType) bool {
	return addr.init().contains(other) // the base method handles zone too
}

func (addr *IPv6Address) Equals(other AddressType) bool {
	return addr.init().equals(other) // the base method handles zone too
}

func (addr *IPv6Address) GetMaxSegmentValue() SegInt {
	return addr.init().getMaxSegmentValue()
}

func (addr *IPv6Address) WithoutZone() *IPv6Address {
	if addr.HasZone() {
		return NewIPv6Address(addr.GetSection())
	}
	return addr
}

func (addr *IPv6Address) ToSequentialRange() *IPv6AddressSeqRange {
	if addr == nil {
		return nil
	}
	addr = addr.init().WithoutPrefixLength().WithoutZone()
	return newSeqRangeUnchecked(
		addr.GetLower().ToIPAddress(),
		addr.GetUpper().ToIPAddress(),
		addr.IsMultiple()).ToIPv6SequentialRange()
}

func (addr *IPv6Address) ToAddressString() *IPAddressString {
	return addr.init().ToIPAddress().ToAddressString()
}

func (addr *IPv6Address) IncludesZeroHostLen(networkPrefixLength BitCount) bool {
	return addr.init().includesZeroHostLen(networkPrefixLength)
}

func (addr *IPv6Address) IncludesMaxHostLen(networkPrefixLength BitCount) bool {
	return addr.init().includesMaxHostLen(networkPrefixLength)
}

func (addr *IPv6Address) Iterator() IPv6AddressIterator {
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

//func (addr *IPv6Address) IsMore(other *IPv6Address) int {
//	return addr.init().isMore(other.ToIPAddress())
//}

func (addr *IPv6Address) ToAddress() *Address {
	if addr != nil {
		addr = addr.init()
	}
	return (*Address)(unsafe.Pointer(addr))
}

func (addr *IPv6Address) ToIPAddress() *IPAddress {
	if addr != nil {
		addr = addr.init()
	}
	return (*IPAddress)(unsafe.Pointer(addr))
}
