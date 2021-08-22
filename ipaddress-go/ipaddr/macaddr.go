package ipaddr

import (
	"math/big"
	"net"
	"sync/atomic"
	"unsafe"
)

const (
	MACBitsPerSegment  BitCount = 8
	MACBytesPerSegment          = 1
	//MACByteCount                    = 4
	//MACBitCount             = 32
	MACDefaultTextualRadix      = 16
	MACMaxValuePerSegment       = 0xff
	MACMaxValuePerDottedSegment = 0xffff

	MediaAccessControlSegmentCount         = 6
	MediaAccessControlDottedSegmentCount   = 3
	MediaAccessControlDotted64SegmentCount = 4
	ExtendedUniqueIdentifier48SegmentCount = MediaAccessControlSegmentCount
	ExtendedUniqueIdentifier64SegmentCount = 8

	MACOrganizationalUniqueIdentifierSegmentCount = 3
	//public static final int ORGANIZATIONAL_UNIQUE_IDENTIFIER_BIT_COUNT = ORGANIZATIONAL_UNIQUE_IDENTIFIER_SEGMENT_COUNT * BITS_PER_SEGMENT;

	MACSegmentMaxChars = 2

	MACDashSegmentSeparator   = dash
	MACColonSegmentSeparator  = colon
	MacSpaceSegmentSeparator  = space
	MacDottedSegmentSeparator = dot

	MacDashedSegmentRangeSeparator           = '|'
	MacDashedSegmentRangeSeparatorStr string = string(MacDashedSegmentRangeSeparator)

	macBitsToSegmentBitshift = 3
)

func NewMACAddress(section *MACAddressSection) *MACAddress {
	return createAddress(section.ToAddressSection(), NoZone).ToMACAddress()
}

func NewMACAddressFromBytes(bytes net.HardwareAddr) (*MACAddress, AddressValueError) {
	section, err := createMACSectionFromBytes(bytes)
	if err != nil {
		return nil, err
	}
	return createAddress(section.ToAddressSection(), NoZone).ToMACAddress(), nil
}

func NewMACAddressFromUint64(val uint64) *MACAddress {
	return NewMACAddressFromUint64Ext(val, false)
}

func NewMACAddressFromUint64Ext(val uint64, isExtended bool) *MACAddress {
	section := NewMACSectionFromUint64(val, getMacSegCount(isExtended))
	return createAddress(section.ToAddressSection(), NoZone).ToMACAddress()
}

func NewMACAddressFromSegments(segments []*MACAddressSegment) (*MACAddress, AddressValueError) {
	segsLen := len(segments)
	if segsLen != MediaAccessControlSegmentCount && segsLen != ExtendedUniqueIdentifier64SegmentCount {
		return nil, &addressValueError{val: segsLen, addressError: addressError{key: "ipaddress.error.mac.invalid.segment.count"}}
	}
	section, err := NewMACSection(segments)
	if err != nil {
		return nil, err
	}
	return createAddress(section.ToAddressSection(), NoZone).ToMACAddress(), nil
}

func NewMACAddressFromVals(vals SegmentValueProvider) (addr *MACAddress) {
	return NewMACAddressFromValsExt(vals, false)
}

func NewMACAddressFromValsExt(vals SegmentValueProvider, isExtended bool) (addr *MACAddress) {
	section := NewMACSectionFromVals(vals, getMacSegCount(isExtended))
	addr = NewMACAddress(section)
	return
}

func NewMACAddressFromRange(vals, upperVals SegmentValueProvider) (addr *MACAddress) {
	return NewMACAddressFromRangeExt(vals, upperVals, false)
}

func NewMACAddressFromRangeExt(vals, upperVals SegmentValueProvider, isExtended bool) (addr *MACAddress) {
	section := NewMACSectionFromRange(vals, upperVals, getMacSegCount(isExtended))
	addr = NewMACAddress(section)
	return
}

func createMACSectionFromBytes(bytes []byte) (*MACAddressSection, AddressValueError) {
	var segCount int
	length := len(bytes)
	//We round down the bytes to 6 bytes if we can.  Otherwise, we round up.
	if length < ExtendedUniqueIdentifier64SegmentCount {
		segCount = MediaAccessControlSegmentCount
		if length > MediaAccessControlSegmentCount {
			for i := 0; ; i++ {
				if bytes[i] != 0 {
					segCount = ExtendedUniqueIdentifier64SegmentCount
					break
				}
				length--
				if length > MediaAccessControlSegmentCount {
					break
				}
			}
		}
	} else {
		segCount = ExtendedUniqueIdentifier64SegmentCount
	}
	return NewMACSectionFromBytes(bytes, segCount)
}

func getMacSegCount(isExtended bool) (segmentCount int) {
	if isExtended {
		segmentCount = ExtendedUniqueIdentifier64SegmentCount
	} else {
		segmentCount = MediaAccessControlSegmentCount
	}
	return
}

// TODO survey the MAC API

//func NewMACAddressInternal(section *MACAddressSection, originator *MACAddressString) *MACAddress {
//	res := NewMACAddress(section)
//	if originator != nil {
//		res.cache.fromString = unsafe.Pointer(originator)
//	}
//	return res
//}

var zeroMAC = createMACZero()

func createMACZero() *MACAddress {
	div := NewMACSegment(0).ToAddressDivision()
	segs := []*AddressDivision{div, div, div, div, div, div}
	section, _ := newMACSection(segs)
	return NewMACAddress(section)
}

type MACAddress struct {
	addressInternal
}

//func (addr *MACAddress) IsExtended() bool {
//	return addr.GetSection().IsExtended()
//}

func (addr *MACAddress) IsAllAddresses() bool {
	return addr.GetSection().IsFullRange()
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
	return (*Address)(addr)
}

func (addr *MACAddress) init() *MACAddress {
	if addr.section == nil {
		return zeroMAC
	}
	return addr
}

func (addr *MACAddress) checkIdentity(section *MACAddressSection) *MACAddress {
	sec := section.ToAddressSection()
	if sec == addr.section {
		return addr
	}
	return NewMACAddress(section)
}

func (addr *MACAddress) GetValue() *big.Int {
	return addr.init().section.GetValue()
}

func (addr *MACAddress) GetUpperValue() *big.Int {
	return addr.init().section.GetUpperValue()
}

func (addr *MACAddress) GetLower() *Address {
	return addr.init().getLower()
}

func (addr *MACAddress) GetUpper() *Address {
	return addr.init().getUpper()
}

func (addr *MACAddress) Uint64Value() uint64 {
	return addr.GetSection().Uint64Value()
}

func (addr *MACAddress) UpperUint64Value() uint64 {
	return addr.GetSection().UpperUint64Value()
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

// GetGenericDivision returns the segment at the given index as an DivisionType
func (addr *MACAddress) GetGenericDivision(index int) DivisionType {
	return addr.init().getDivision(index)
}

// GetGenericSegment returns the segment at the given index as an AddressSegmentType
func (addr *MACAddress) GetGenericSegment(index int) AddressSegmentType {
	return addr.init().getSegment(index)
}

// TestBit computes (this & (1 << n)) != 0), using the lower value of this segment.
func (addr *MACAddress) TestBit(n BitCount) bool {
	return addr.init().testBit(n)
}

// Returns true if the bit in the lower value of this segment at the given index is 1, where index 0 is the most significant bit.
func (addr *MACAddress) IsOneBit(bitIndex BitCount) bool {
	return addr.init().isOneBit(bitIndex)
}

func (addr *MACAddress) IsMax() bool {
	return addr.init().section.IsMax()
}

func (addr *MACAddress) IncludesMax() bool {
	return addr.init().section.IncludesMax()
}

// GetDivision returns the segment count, implementing the interface AddressDivisionSeries
func (addr *MACAddress) GetDivisionCount() int {
	return addr.init().getDivisionCount()
}

func (addr *MACAddress) ToPrefixBlock() *MACAddress {
	return addr.init().toPrefixBlock().ToMACAddress()
}

func (addr *MACAddress) ToBlock(segmentIndex int, lower, upper SegInt) *MACAddress {
	return addr.init().toBlock(segmentIndex, lower, upper).ToMACAddress()
}

func (addr *MACAddress) WithoutPrefixLen() *MACAddress {
	return addr.init().withoutPrefixLen().ToMACAddress()
}

func (addr *MACAddress) SetPrefixLen(prefixLen BitCount) *MACAddress {
	return addr.init().setPrefixLen(prefixLen).ToMACAddress()
}

func (addr *MACAddress) SetPrefixLenZeroed(prefixLen BitCount) (*MACAddress, IncompatibleAddressError) {
	res, err := addr.init().setPrefixLenZeroed(prefixLen)
	return res.ToMACAddress(), err
}

func (addr *MACAddress) AssignPrefixForSingleBlock() *MACAddress {
	return addr.init().assignPrefixForSingleBlock().ToMACAddress()
}

func (addr *MACAddress) AssignMinPrefixForBlock() *MACAddress {
	return addr.init().assignMinPrefixForBlock().ToMACAddress()
}

func (addr *MACAddress) ContainsPrefixBlock(prefixLen BitCount) bool {
	return addr.init().addressInternal.ContainsPrefixBlock(prefixLen)
}

func (addr *MACAddress) ContainsSinglePrefixBlock(prefixLen BitCount) bool {
	return addr.init().addressInternal.ContainsSinglePrefixBlock(prefixLen)
}

func (addr *MACAddress) GetMinPrefixLenForBlock() BitCount {
	return addr.init().addressInternal.GetMinPrefixLenForBlock()
}

func (addr *MACAddress) GetPrefixLenForSingleBlock() PrefixLen {
	return addr.init().addressInternal.GetPrefixLenForSingleBlock()
}

func (addr *MACAddress) CompareTo(item AddressItem) int {
	return CountComparator.Compare(addr.init(), item)
}

func (addr *MACAddress) PrefixEquals(other AddressType) bool {
	return addr.init().prefixEquals(other)
}

func (addr *MACAddress) PrefixContains(other AddressType) bool {
	return addr.init().prefixContains(other)
}

func (addr *MACAddress) Contains(other AddressType) bool {
	// note: we don't use the same optimization is in IPv4/6 because we do need to check segment count with MAC
	return addr.init().contains(other)
}

func (addr *MACAddress) Equals(other AddressType) bool {
	// note: we don't use the same optimization is in IPv4/6 because we do need to check segment count with MAC
	return addr.init().equals(other)
}

func (addr *MACAddress) GetMaxSegmentValue() SegInt {
	return addr.init().getMaxSegmentValue()
}

// Multicast MAC addresses have the least significant bit of the first octet set to 1.
func (addr *MACAddress) IsMulticast() bool {
	return addr.GetSegment(0).MatchesWithMask(1, 0x1)
}

func (addr *MACAddress) IsUnicast() bool {
	return !addr.IsMulticast()
}

// Universal MAC addresses have second the least significant bit of the first octet set to 0.
func (addr *MACAddress) IsUniversal() bool {
	return !addr.IsLocal()
}

// Local MAC addresses have the second least significant bit of the first octet set to 1.
func (addr *MACAddress) IsLocal() bool {
	return addr.GetSegment(0).MatchesWithMask(2, 0x2)
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

func (addr *MACAddress) IncrementBoundary(increment int64) *MACAddress {
	return addr.init().incrementBoundary(increment).ToMACAddress()
}

func (addr *MACAddress) Increment(increment int64) *MACAddress {
	return addr.init().increment(increment).ToMACAddress()
}

func (addr *MACAddress) ReverseBytes() *MACAddress {
	return addr.checkIdentity(addr.GetSection().ReverseBytes())
}

func (addr *MACAddress) ReverseBits(perByte bool) (*MACAddress, IncompatibleAddressError) {
	res, err := addr.GetSection().ReverseBits(perByte)
	if err != nil {
		return nil, err
	}
	return addr.checkIdentity(res), nil
}

func (addr *MACAddress) ReverseSegments() *MACAddress {
	return addr.checkIdentity(addr.GetSection().ReverseSegments())
}

// ReplaceLen replaces segments starting from startIndex and ending before endIndex with the same number of segments starting at replacementStartIndex from the replacement section
func (addr *MACAddress) ReplaceLen(startIndex, endIndex int, replacement *MACAddress, replacementIndex int) *MACAddress {
	startIndex, endIndex, replacementIndex =
		adjust1To1Indices(startIndex, endIndex, addr.GetSegmentCount(), replacementIndex, replacement.GetSegmentCount())
	if startIndex == endIndex {
		return addr
	}
	count := endIndex - startIndex
	return addr.checkIdentity(addr.GetSection().ReplaceLen(startIndex, endIndex, replacement.GetSection(), replacementIndex, replacementIndex+count))
}

// Replace replaces segments starting from startIndex with segments from the replacement section
func (addr *MACAddress) Replace(startIndex int, replacement *MACAddressSection) *MACAddress {
	startIndex, endIndex, replacementIndex :=
		adjust1To1Indices(startIndex, startIndex+replacement.GetSegmentCount(), addr.GetSegmentCount(), 0, replacement.GetSegmentCount())
	count := endIndex - startIndex
	return addr.checkIdentity(addr.GetSection().ReplaceLen(startIndex, endIndex, replacement, replacementIndex, replacementIndex+count))
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

func (addr *MACAddress) ToHexString(with0xPrefix bool) (string, IncompatibleAddressError) {
	return addr.init().toHexString(with0xPrefix)
}

// ToDottedString produces the dotted hexadecimal format aaaa.bbbb.cccc
func (addr *MACAddress) ToDottedString() (string, IncompatibleAddressError) {
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
	res := addr.cache.identifierStr
	if res == nil {
		str := newMACAddressStringFromAddr(addr.toCanonicalString(), addr)
		res = &IdentifierStr{str}
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&addr.cache.identifierStr))
		atomic.StorePointer(dataLoc, unsafe.Pointer(res))
	}
	hostIdStr := res.idStr
	return hostIdStr.(*MACAddressString)
}

//func (addr *MACAddress) CompareSize(other *MACAddress) int {
//	return addr.initMultAndPrefLen().CompareSize(other.ToAddress())
//}
