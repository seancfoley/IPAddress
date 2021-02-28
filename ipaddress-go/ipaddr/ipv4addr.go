package ipaddr

import (
	"math/big"
	"net"
	"unsafe"
)

const (
	IPv4SegmentSeparator    = '.'
	IPv4BitsPerSegment      = 8
	IPv4BytesPerSegment     = 1
	IPv4SegmentCount        = 4
	IPv4ByteCount           = 4
	IPv4BitCount            = 32
	IPv4DefaultTextualRadix = 10
	IPv4MaxValuePerSegment  = 0xff
	IPv4MaxValue            = 0xffffffff
	IPv4ReverseDnsSuffix    = ".in-addr.arpa"
	IPv4SegmentMaxChars     = 3
)

// TODO there is 1 other categories:  uint32

func NewIPv4Address(section *IPv4AddressSection) *IPv4Address {
	return &IPv4Address{
		ipAddressInternal{
			addressInternal{
				section: section.ToAddressSection(),
				cache:   &addressCache{},
			},
		},
	}
}

func NewIPv4AddressFromIP(bytes net.IP) (addr *IPv4Address, err AddressValueException) {
	section, err := NewIPv4AddressSectionFromSegmentedBytes(bytes, IPv4SegmentCount)
	if err == nil {
		addr = NewIPv4Address(section)
	}
	return
}

func NewIPv4AddressFromPrefixedIP(bytes net.IP, prefixLength PrefixLen) (addr *IPv4Address, err AddressValueException) {
	section, err := NewIPv4AddressSectionFromPrefixedBytes(bytes, IPv4SegmentCount, prefixLength)
	if err == nil {
		addr = NewIPv4Address(section)
	}
	return
}

func NewIPv4AddressFromValues(vals SegmentValueProvider) (addr *IPv4Address) {
	section := NewIPv4AddressSectionFromValues(vals, IPv4SegmentCount)
	addr = NewIPv4Address(section)
	return
}

func NewIPv4AddressFromPrefixedValues(vals SegmentValueProvider, prefixLength PrefixLen) (addr *IPv4Address, err AddressValueException) {
	section := NewIPv4AddressSectionFromPrefixedValues(vals, IPv4SegmentCount, prefixLength)
	addr = NewIPv4Address(section)
	return
}

func NewIPv4AddressFromRange(vals, upperVals SegmentValueProvider) (addr *IPv4Address) {
	section := NewIPv4AddressSectionFromRangeValues(vals, upperVals, IPv4SegmentCount)
	addr = NewIPv4Address(section)
	return
}

func NewIPv4AddressFromPrefixedRange(vals, upperVals SegmentValueProvider, prefixLength PrefixLen) (addr *IPv4Address, err AddressValueException) {
	section := NewIPv4AddressSectionFromPrefixedRangeValues(vals, upperVals, IPv4SegmentCount, prefixLength)
	addr = NewIPv4Address(section)
	return
}

var zeroIPv4 *IPv4Address

func init() {
	div := NewIPv4Segment(0).ToAddressDivision()
	segs := []*AddressDivision{div, div, div, div}
	section, _ := newIPv4AddressSection(segs, false)
	zeroIPv4 = NewIPv4Address(section)
}

//
//
// IPv4Address is an IPv4 address, or a subnet of multiple IPv4 addresses.  Each segment can represent a single value or a range of values.
// The zero value is 0.0.0.0
type IPv4Address struct {
	ipAddressInternal
}

func (addr *IPv4Address) GetBitCount() BitCount {
	return IPv4BitCount
}

func (addr *IPv4Address) GetByteCount() int {
	return IPv4ByteCount
}

func (addr IPv4Address) String() string {
	address := addr.init()
	//TODO a different default string
	return address.ipAddressInternal.String()
}

func (addr *IPv4Address) ToAddress() *Address {
	if addr != nil {
		addr = addr.init()
	}
	return (*Address)(unsafe.Pointer(addr))
}

func (addr *IPv4Address) ToIPAddress() *IPAddress {
	if addr != nil {
		addr = addr.init()
	}
	return (*IPAddress)(unsafe.Pointer(addr))
}

func (addr *IPv4Address) init() *IPv4Address {
	if addr.section == nil {
		return zeroIPv4
	}
	return addr
}

func (addr *IPv4Address) GetSection() *IPv4AddressSection {
	return addr.init().section.ToIPv4AddressSection()
}

// Gets the subsection from the series starting from the given index
// The first segment is at index 0.
func (addr *IPv4Address) GetTrailingSection(index int) *IPv4AddressSection {
	return addr.GetSection().GetTrailingSection(index)
}

//// Gets the subsection from the series starting from the given index and ending just before the give endIndex
//// The first segment is at index 0.
func (addr *IPv4Address) GetSubSection(index, endIndex int) *IPv4AddressSection {
	return addr.GetSection().GetSubSection(index, endIndex)
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (addr *IPv4Address) CopySubSegments(start, end int, segs []*IPv4AddressSegment) (count int) {
	return addr.GetSection().CopySubSegments(start, end, segs)
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (addr *IPv4Address) CopySegments(segs []*IPv4AddressSegment) (count int) {
	return addr.GetSection().CopySegments(segs)
}

// GetSegments returns a slice with the address segments.  The returned slice is not backed by the same array as this address.
func (addr *IPv4Address) GetSegments() []*IPv4AddressSegment {
	return addr.GetSection().GetSegments()
}

// GetSegment returns the segment at the given index
func (addr *IPv4Address) GetSegment(index int) *IPv4AddressSegment {
	return addr.init().getSegment(index).ToIPv4AddressSegment()
}

// GetSegmentCount returns the segment count
func (addr *IPv4Address) GetSegmentCount() int {
	return addr.GetDivisionCount()
}

// GetGenericDivision returns the segment at the given index as an AddressGenericDivision
func (addr *IPv4Address) GetGenericDivision(index int) AddressGenericDivision {
	return addr.init().getDivision(index)
}

// GetDivisionCount returns the segment count
func (addr *IPv4Address) GetDivisionCount() int {
	return addr.init().getDivisionCount()
}

func (addr *IPv4Address) GetIPVersion() IPVersion {
	return IPv4
}

func (addr *IPv4Address) checkIdentity(section *IPv4AddressSection) *IPv4Address {
	sec := section.ToAddressSection()
	if sec == addr.section {
		return addr
	}
	return &IPv4Address{ipAddressInternal{addressInternal{section: sec, cache: &addressCache{}}}}
}

func (addr *IPv4Address) Mask(other *IPv4Address) (masked *IPv4Address, err error) {
	addr = addr.init()
	sect, err := addr.GetSection().Mask(other.GetSection())
	if err == nil {
		masked = addr.checkIdentity(sect)
	}
	return
}

func (addr *IPv4Address) SpanWithRange(other *IPv4Address) *IPv4AddressSeqRange {
	return NewIPv4SeqRange(addr.init(), other.init())
}

func (addr *IPv4Address) GetLower() *IPv4Address {
	return addr.init().getLower().ToIPv4Address()
}

func (addr *IPv4Address) GetUpper() *IPv4Address {
	return addr.init().getUpper().ToIPv4Address()
}

func (addr *IPv4Address) IntValue() uint32 {
	return addr.GetSection().IntValue()
}

func (addr *IPv4Address) UpperIntValue() uint32 {
	return addr.GetSection().UpperIntValue()
}

func (addr *IPv4Address) ToPrefixBlock() *IPv4Address {
	return addr.init().toPrefixBlock().ToIPv4Address()
}

func (addr *IPv4Address) ToPrefixBlockLen(prefLen BitCount) *IPv4Address {
	return addr.init().toPrefixBlockLen(prefLen).ToIPv4Address()
}

func (addr *IPv4Address) GetValue() *big.Int {
	return addr.init().section.GetValue()
}

func (addr *IPv4Address) GetUpperValue() *big.Int {
	return addr.init().section.GetUpperValue()
}

func (addr *IPv4Address) GetIP() net.IP {
	return addr.GetBytes()
}

func (addr *IPv4Address) CopyIP(bytes net.IP) net.IP {
	return addr.CopyBytes(bytes)
}

func (addr *IPv4Address) GetUpperIP() net.IP {
	return addr.GetUpperBytes()
}

func (addr *IPv4Address) CopyUpperIP(bytes net.IP) net.IP {
	return addr.CopyUpperBytes(bytes)
}

func (addr *IPv4Address) GetBytes() []byte {
	return addr.init().section.GetBytes()
}

func (addr *IPv4Address) GetUpperBytes() []byte {
	return addr.init().section.GetUpperBytes()
}

func (addr *IPv4Address) CopyBytes(bytes []byte) []byte {
	return addr.init().section.CopyBytes(bytes)
}

func (addr *IPv4Address) CopyUpperBytes(bytes []byte) []byte {
	return addr.init().section.CopyUpperBytes(bytes)
}

func (addr *IPv4Address) Contains(other AddressType) bool {
	return addr.init().contains(other)
}

func (addr *IPv4Address) Equals(other AddressType) bool {
	return addr.init().equals(other)
}

func (addr *IPv4Address) ToSequentialRange() *IPv4AddressSeqRange {
	if addr == nil {
		return nil
	}
	addr = addr.init()
	return NewIPv4SeqRange(addr.GetLower(), addr.GetUpper())
}

func (addr *IPv4Address) ToAddressString() *IPAddressString {
	return addr.init().ToIPAddress().ToAddressString()
}

//func (addr *IPv4Address) IsMore(other *IPv4Address) int {
//	return addr.init().isMore(other.ToIPAddress())
//}
