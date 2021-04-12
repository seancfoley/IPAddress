package ipaddr

import (
	"math/big"
	"net"
	"sync/atomic"
	"unsafe"
)

const (
	//IPv4SegmentSeparator             = '.'
	MACBitsPerSegment  = 8
	MACBytesPerSegment = 1
	//MACByteCount                    = 4
	//MACBitCount             = 32
	MACDefaultTextualRadix      = 16
	MACMaxValuePerSegment       = 0xff
	MACMaxValuePerDottedSegment = 0xffff
	//IPv4MaxValue                 = 0xffffffff

	MediaAccessControlSegmentCount         = 6
	MediaAccessControlDottedSegmentCount   = 3
	MediaAccessControlDotted64SegmentCount = 4
	ExtendedUniqueIdentifier48SegmentCount = MediaAccessControlSegmentCount
	ExtendedUniqueIdentifier64SegmentCount = 8

	MACSegmentMaxChars = 2

	MACDashSegmentSeparator   = dash
	MACColonSegmentSeparator  = colon
	MacSpaceSegmentSeparator  = space
	MacDottedSegmentSeparator = dot

	MacDashedSegmentRangeSeparator           = '|'
	MacDashedSegmentRangeSeparatorStr string = string(MacDashedSegmentRangeSeparator)
)

func NewMACAddress(section *MACAddressSection) *MACAddress {
	return &MACAddress{
		addressInternal{
			section: section.ToAddressSection(),
			cache:   &addressCache{},
		},
	}
}

var zeroMAC = initMACZero()

func initMACZero() *MACAddress {
	return nil
	// TODO reinstate when all these methods are in place
	//div := NewMACSegment(0).ToAddressDivision()
	//segs := []*AddressDivision{div, div, div, div, div, div, div, div}
	//section, _ := newMACAddressSection(segs, false)
	//zeroMAC = NewMACAddress(section)
}

type MACAddress struct {
	addressInternal
}

func (addr *MACAddress) GetBitCount() BitCount {
	return addr.init().addressInternal.GetBitCount()
}

func (addr *MACAddress) GetByteCount() int {
	return addr.init().addressInternal.GetByteCount()
}

func (addr *MACAddress) GetBitsPerSegment() BitCount {
	return MACBitsPerSegment
}

func (addr *MACAddress) GetBytesPerSegment() int {
	return MACBytesPerSegment
}

func (addr *MACAddress) ToAddress() *Address {
	if addr != nil {
		addr = addr.init()
	}
	return (*Address)(unsafe.Pointer(addr))
}

func (addr *MACAddress) init() *MACAddress {
	if addr.section == nil {
		return zeroMAC
	}
	return addr
}

func (addr *MACAddress) GetValue() *big.Int {
	return addr.init().section.GetValue()
}

func (addr *MACAddress) GetUpperValue() *big.Int {
	return addr.init().section.GetUpperValue()
}

func (addr *MACAddress) GetHardwareAddr() net.HardwareAddr {
	return addr.GetBytes()
}

func (addr *MACAddress) CopyHardwareAddr(bytes net.HardwareAddr) net.HardwareAddr {
	return addr.CopyBytes(bytes)
}

func (addr *MACAddress) GetUpperHardwareAddr() net.HardwareAddr {
	return addr.GetUpperBytes()
}

func (addr *MACAddress) CopyUpperHardwareAddr(bytes net.HardwareAddr) net.HardwareAddr {
	return addr.CopyUpperBytes(bytes)
}

func (addr *MACAddress) GetBytes() []byte {
	return addr.init().section.GetBytes()
}

func (addr *MACAddress) GetUpperBytes() []byte {
	return addr.init().section.GetUpperBytes()
}

func (addr *MACAddress) CopyBytes(bytes []byte) []byte {
	return addr.init().section.CopyBytes(bytes)
}

func (addr *MACAddress) CopyUpperBytes(bytes []byte) []byte {
	return addr.init().section.CopyUpperBytes(bytes)
}

func (addr *MACAddress) GetSection() *MACAddressSection {
	return addr.init().section.ToMACAddressSection()
}

// Gets the subsection from the series starting from the given index
// The first segment is at index 0.
func (addr *MACAddress) GetTrailingSection(index int) *MACAddressSection {
	return addr.GetSection().GetTrailingSection(index)
}

//// Gets the subsection from the series starting from the given index and ending just before the give endIndex
//// The first segment is at index 0.
func (addr *MACAddress) GetSubSection(index, endIndex int) *MACAddressSection {
	return addr.GetSection().GetSubSection(index, endIndex)
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (addr *MACAddress) CopySubSegments(start, end int, segs []*MACAddressSegment) (count int) {
	return addr.GetSection().CopySubSegments(start, end, segs)
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (addr *MACAddress) CopySegments(segs []*MACAddressSegment) (count int) {
	return addr.GetSection().CopySegments(segs)
}

// GetSegments returns a slice with the address segments.  The returned slice is not backed by the same array as this address.
func (addr *MACAddress) GetSegments() []*MACAddressSegment {
	return addr.GetSection().GetSegments()
}

// GetSegment returns the segment at the given index
func (addr *MACAddress) GetSegment(index int) *MACAddressSegment {
	return addr.init().getSegment(index).ToMACAddressSegment()
}

// GetSegmentCount returns the segment/division count
func (addr *MACAddress) GetSegmentCount() int {
	return addr.GetDivisionCount()
}

// GetGenericDivision returns the segment at the given index as an AddressGenericDivision
func (addr *MACAddress) GetGenericDivision(index int) AddressGenericDivision {
	return addr.init().getDivision(index)
}

// GetDivision returns the segment count, implementing the interface AddressDivisionSeries
func (addr *MACAddress) GetDivisionCount() int {
	return addr.init().getDivisionCount()
}

func (addr *MACAddress) ToPrefixBlock() *MACAddress {
	return addr.init().toPrefixBlock().ToMACAddress()
}

func (addr *MACAddress) WithoutPrefixLength() *MACAddress {
	return addr.init().withoutPrefixLength().ToMACAddress()
}

func (addr *MACAddress) ContainsPrefixBlock(prefixLen BitCount) bool {
	return addr.init().addressInternal.ContainsPrefixBlock(prefixLen)
}

func (addr *MACAddress) ContainsSinglePrefixBlock(prefixLen BitCount) bool {
	return addr.init().addressInternal.ContainsSinglePrefixBlock(prefixLen)
}

func (addr *MACAddress) GetMinPrefixLengthForBlock() BitCount {
	return addr.init().addressInternal.GetMinPrefixLengthForBlock()
}

func (addr *MACAddress) GetPrefixLengthForSingleBlock() PrefixLen {
	return addr.init().addressInternal.GetPrefixLengthForSingleBlock()
}

func (addr *MACAddress) Contains(other AddressType) bool {
	return addr.init().contains(other)
}

func (addr *MACAddress) Equals(other AddressType) bool {
	return addr.init().equals(other)
}

func (addr *MACAddress) GetMaxSegmentValue() SegInt {
	return addr.init().getMaxSegmentValue()
}

func (addr *MACAddress) Iterator() MACAddressIterator {
	return macAddressIterator{addr.init().addrIterator(nil)}
}

func (addr *MACAddress) PrefixIterator() MACAddressIterator {
	return macAddressIterator{addr.init().prefixIterator(false)}
}

func (addr *MACAddress) PrefixBlockIterator() MACAddressIterator {
	return macAddressIterator{addr.init().prefixIterator(true)}
}

func (addr MACAddress) String() string {
	return addr.init().addressInternal.String()
}

func (addr *MACAddress) ToCanonicalString() string {
	return addr.init().toCanonicalString()
}

func (addr *MACAddress) ToNormalizedString() string {
	return addr.init().toNormalizedString()
}

func (addr *MACAddress) ToCompressedString() string {
	return addr.init().toCompressedString()
}

func (addr *MACAddress) ToHexString(with0xPrefix bool) (string, IncompatibleAddressException) {
	return addr.init().toHexString(with0xPrefix)
}

// ToDottedString produces the dotted hexadecimal format aaaa.bbbb.cccc
func (addr *MACAddress) ToDottedString() string {
	return addr.init().GetSection().ToDottedString()
}

// ToSpaceDelimitedString produces a string delimited by spaces: aa bb cc dd ee ff
func (addr *MACAddress) ToSpaceDelimitedString() string {
	return addr.init().GetSection().ToSpaceDelimitedString()
}

func (addr *MACAddress) ToDashedString() string {
	return addr.init().GetSection().ToDashedString()
}

func (addr *MACAddress) ToColonDelimitedString() string {
	return addr.init().GetSection().ToColonDelimitedString()
}

func (addr *MACAddress) ToAddressString() *MACAddressString {
	addr = addr.init()
	res := addr.cache.fromString
	if res == nil {
		str := NewMACAddressString(addr.ToCanonicalString(), nil)
		dataLoc := &addr.cache.fromString
		atomic.StorePointer(dataLoc, unsafe.Pointer(str))
		return str
	}
	return (*MACAddressString)(res)
}

//func (addr *MACAddress) IsMore(other *MACAddress) int {
//	return addr.init().isMore(other.ToAddress())
//}
