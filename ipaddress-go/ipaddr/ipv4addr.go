package ipaddr

import (
	"math/big"
	"net"
	"unsafe"
)

const (
	IPv4SegmentSeparator               = '.'
	IPv4BitsPerSegment        BitCount = 8
	IPv4BytesPerSegment                = 1
	IPv4SegmentCount                   = 4
	IPv4ByteCount                      = 4
	IPv4BitCount              BitCount = 32
	IPv4DefaultTextualRadix            = 10
	IPv4MaxValuePerSegment             = 0xff
	IPv4MaxValue                       = 0xffffffff
	IPv4ReverseDnsSuffix               = ".in-addr.arpa"
	IPv4SegmentMaxChars                = 3
	ipv4BitsToSegmentBitshift          = 3
)

func NewIPv4Address(section *IPv4AddressSection) *IPv4Address {
	return createAddress(section.ToAddressSection(), NoZone).ToIPv4Address()
}

func NewIPv4AddressFromSegments(segments []*IPv4AddressSegment) (*IPv4Address, AddressValueError) {
	section, err := NewIPv4Section(segments)
	if err != nil {
		return nil, err
	}
	return createAddress(section.ToAddressSection(), NoZone).ToIPv4Address(), nil
}

func NewIPv4AddressFromPrefixedSegments(segments []*IPv4AddressSegment, prefixLength PrefixLen) (*IPv4Address, AddressValueError) {
	section, err := NewIPv4AddressPrefixedSection(segments, prefixLength)
	if err != nil {
		return nil, err
	}
	return createAddress(section.ToAddressSection(), NoZone).ToIPv4Address(), nil
}

func NewIPv4AddressFromUint32(val uint32) *IPv4Address {
	section := NewIPv4SectionFromUint32(val, IPv4SegmentCount)
	return createAddress(section.ToAddressSection(), NoZone).ToIPv4Address()
}

func NewIPv4AddressFromPrefixedUint32(val uint32, prefixLength PrefixLen) *IPv4Address {
	section := NewIPv4SectionFromPrefixedUint32(val, IPv4SegmentCount, prefixLength)
	return createAddress(section.ToAddressSection(), NoZone).ToIPv4Address()
}

func NewIPv4AddressFromIP(bytes net.IP) (addr *IPv4Address, err AddressValueError) {
	section, err := NewIPv4SectionFromSegmentedBytes(bytes, IPv4SegmentCount)
	if err == nil {
		addr = NewIPv4Address(section)
	}
	return
}

func NewIPv4AddressFromPrefixedIP(bytes net.IP, prefixLength PrefixLen) (addr *IPv4Address, err AddressValueError) {
	section, err := NewIPv4SectionFromPrefixedBytes(bytes, IPv4SegmentCount, prefixLength)
	if err == nil {
		addr = NewIPv4Address(section)
	}
	return
}

func NewIPv4AddressFromVals(vals SegmentValueProvider) (addr *IPv4Address) {
	section := NewIPv4SectionFromVals(vals, IPv4SegmentCount)
	addr = NewIPv4Address(section)
	return
}

func NewIPv4AddressFromPrefixedVals(vals SegmentValueProvider, prefixLength PrefixLen) (addr *IPv4Address, err AddressValueError) {
	section := NewIPv4SectionFromPrefixedVals(vals, IPv4SegmentCount, prefixLength)
	addr = NewIPv4Address(section)
	return
}

func NewIPv4AddressFromRange(vals, upperVals SegmentValueProvider) (addr *IPv4Address) {
	section := NewIPv4SectionFromRange(vals, upperVals, IPv4SegmentCount)
	addr = NewIPv4Address(section)
	return
}

func NewIPv4AddressFromPrefixedRange(vals, upperVals SegmentValueProvider, prefixLength PrefixLen) (addr *IPv4Address, err AddressValueError) {
	section := NewIPv4SectionFromPrefixedRange(vals, upperVals, IPv4SegmentCount, prefixLength)
	addr = NewIPv4Address(section)
	return
}

var zeroIPv4 = initZeroIPv4()

func initZeroIPv4() *IPv4Address {
	div := NewIPv4Segment(0).ToAddressDivision()
	segs := []*AddressDivision{div, div, div, div}
	section, _ := newIPv4Section(segs, false)
	return NewIPv4Address(section)
}

// TODO survey the  IPv4 API, I've already surveyed IPAddress API

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

func (addr *IPv4Address) GetBitsPerSegment() BitCount {
	return IPv4BitsPerSegment
}

func (addr *IPv4Address) GetBytesPerSegment() int {
	return IPv4BytesPerSegment
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

func (addr *IPv4Address) GetNetworkSection() *IPv4AddressSection {
	return addr.GetSection().GetNetworkSection()
}

func (addr *IPv4Address) GetNetworkSectionLen(prefLen BitCount) *IPv4AddressSection {
	return addr.GetSection().GetNetworkSectionLen(prefLen)
}

func (addr *IPv4Address) GetHostSection() *IPv4AddressSection {
	return addr.GetSection().GetHostSection()
}

func (addr *IPv4Address) GetHostSectionLen(prefLen BitCount) *IPv4AddressSection {
	return addr.GetSection().GetHostSectionLen(prefLen)
}

func (addr *IPv4Address) GetNetworkMask() *IPv4Address {
	return addr.getNetworkMask(DefaultIPv4Network).ToIPv4Address()
}

func (addr *IPv4Address) GetHostMask() *IPv4Address {
	return addr.getHostMask(DefaultIPv4Network).ToIPv4Address()
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

// GetGenericDivision returns the segment at the given index as an DivisionType
func (addr *IPv4Address) GetGenericDivision(index int) DivisionType {
	return addr.init().getDivision(index)
}

// GetGenericSegment returns the segment at the given index as an AddressSegmentType
func (addr *IPv4Address) GetGenericSegment(index int) AddressSegmentType {
	return addr.init().getSegment(index)
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
	return NewIPv4Address(section)
}

func (addr *IPv4Address) Mask(other *IPv4Address) (masked *IPv4Address, err IncompatibleAddressError) {
	return addr.maskPrefixed(other, false)
}

func (addr *IPv4Address) MaskPrefixed(other *IPv4Address) (masked *IPv4Address, err IncompatibleAddressError) {
	return addr.maskPrefixed(other, true)
}

func (addr *IPv4Address) maskPrefixed(other *IPv4Address, retainPrefix bool) (masked *IPv4Address, err IncompatibleAddressError) {
	addr = addr.init()
	sect, err := addr.GetSection().maskPrefixed(other.GetSection(), retainPrefix)
	if err == nil {
		masked = addr.checkIdentity(sect)
	}
	return
}

func (addr *IPv4Address) BitwiseOr(other *IPv4Address) (masked *IPv4Address, err IncompatibleAddressError) {
	return addr.bitwiseOrPrefixed(other, false)
}

func (addr *IPv4Address) BitwiseOrPrefixed(other *IPv4Address) (masked *IPv4Address, err IncompatibleAddressError) {
	return addr.bitwiseOrPrefixed(other, true)
}

func (addr *IPv4Address) bitwiseOrPrefixed(other *IPv4Address, retainPrefix bool) (masked *IPv4Address, err IncompatibleAddressError) {
	addr = addr.init()
	sect, err := addr.GetSection().bitwiseOrPrefixed(other.GetSection(), retainPrefix)
	if err == nil {
		masked = addr.checkIdentity(sect)
	}
	return
}

func (addr *IPv4Address) Subtract(other *IPv4Address) []*IPv4Address {
	addr = addr.init()
	sects, _ := addr.GetSection().Subtract(other.GetSection())
	sectLen := len(sects)
	if sectLen == 1 {
		sec := sects[0]
		if sec.ToAddressSection() == addr.section {
			return []*IPv4Address{addr}
		}
	}
	res := make([]*IPv4Address, sectLen)
	for i, sect := range sects {
		res[i] = NewIPv4Address(sect)
	}
	return res
}

func (addr *IPv4Address) Intersect(other *IPv4Address) *IPv4Address {
	addr = addr.init()
	section, _ := addr.GetSection().Intersect(other.GetSection())
	return addr.checkIdentity(section)
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

// GetLowerIPAddress implements the IPAddressRange interface
func (addr *IPv4Address) GetLowerIPAddress() *IPAddress {
	return addr.GetLower().ToIPAddress()
}

// GetUpperIPAddress implements the IPAddressRange interface
func (addr *IPv4Address) GetUpperIPAddress() *IPAddress {
	return addr.GetUpper().ToIPAddress()
}

func (addr *IPv4Address) ToZeroHost() (*IPv4Address, IncompatibleAddressError) {
	res, err := addr.init().toZeroHost(false)
	return res.ToIPv4Address(), err
}

func (addr *IPv4Address) ToZeroHostLen(prefixLength BitCount) (*IPv4Address, IncompatibleAddressError) {
	res, err := addr.init().toZeroHostLen(prefixLength)
	return res.ToIPv4Address(), err
}

func (addr *IPv4Address) ToZeroNetwork() *IPv4Address {
	return addr.init().toZeroNetwork().ToIPv4Address()
}

func (addr *IPv4Address) ToMaxHost() (*IPv4Address, IncompatibleAddressError) {
	res, err := addr.init().toMaxHost()
	return res.ToIPv4Address(), err
}

func (addr *IPv4Address) ToMaxHostLen(prefixLength BitCount) (*IPv4Address, IncompatibleAddressError) {
	res, err := addr.init().toMaxHostLen(prefixLength)
	return res.ToIPv4Address(), err
}

func (addr *IPv4Address) Uint32Value() uint32 {
	return addr.GetSection().Uint32Value()
}

func (addr *IPv4Address) UpperUint32Value() uint32 {
	return addr.GetSection().UpperUint32Value()
}

//func (addr *IPv4Address) Uint64Value() uint64 {
//	return addr.GetSection().Uint64Value()
//}
//
//func (addr *IPv4Address) UpperUint64Value() uint64 {
//	return addr.GetSection().UpperUint64Value()
//}

func (addr *IPv4Address) ToPrefixBlock() *IPv4Address {
	return addr.init().toPrefixBlock().ToIPv4Address()
}

func (addr *IPv4Address) ToPrefixBlockLen(prefLen BitCount) *IPv4Address {
	return addr.init().toPrefixBlockLen(prefLen).ToIPv4Address()
}

func (addr *IPv4Address) ToBlock(segmentIndex int, lower, upper SegInt) *IPv4Address {
	return addr.init().toBlock(segmentIndex, lower, upper).ToIPv4Address()
}

func (addr *IPv4Address) WithoutPrefixLen() *IPv4Address {
	return addr.init().withoutPrefixLen().ToIPv4Address()
}

func (addr *IPv4Address) SetPrefixLen(prefixLen BitCount) *IPv4Address {
	return addr.init().setPrefixLen(prefixLen).ToIPv4Address()
}

func (addr *IPv4Address) SetPrefixLenZeroed(prefixLen BitCount) (*IPv4Address, IncompatibleAddressError) {
	res, err := addr.init().setPrefixLenZeroed(prefixLen)
	return res.ToIPv4Address(), err
}

func (addr *IPv4Address) AdjustPrefixLen(prefixLen BitCount) *IPv4Address {
	return addr.init().adjustPrefixLen(prefixLen).ToIPv4Address()
}

func (addr *IPv4Address) AdjustPrefixLenZeroed(prefixLen BitCount) (*IPv4Address, IncompatibleAddressError) {
	res, err := addr.init().adjustPrefixLenZeroed(prefixLen)
	return res.ToIPv4Address(), err
}

func (addr *IPv4Address) AssignPrefixForSingleBlock() *IPv4Address {
	return addr.init().assignPrefixForSingleBlock().ToIPv4Address()
}

func (addr *IPv4Address) AssignMinPrefixForBlock() *IPv4Address {
	return addr.init().assignMinPrefixForBlock().ToIPv4Address()
}

func (addr *IPv4Address) ContainsPrefixBlock(prefixLen BitCount) bool {
	return addr.init().ipAddressInternal.ContainsPrefixBlock(prefixLen)
}

func (addr *IPv4Address) ContainsSinglePrefixBlock(prefixLen BitCount) bool {
	return addr.init().ipAddressInternal.ContainsSinglePrefixBlock(prefixLen)
}

func (addr *IPv4Address) GetMinPrefixLengthForBlock() BitCount {
	return addr.init().ipAddressInternal.GetMinPrefixLengthForBlock()
}

func (addr *IPv4Address) GetPrefixLengthForSingleBlock() PrefixLen {
	return addr.init().ipAddressInternal.GetPrefixLengthForSingleBlock()
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

func (addr *IPv4Address) IsMax() bool {
	return addr.init().section.IsMax()
}

func (addr *IPv4Address) IncludesMax() bool {
	return addr.init().section.IncludesMax()
}

// TestBit computes (this & (1 << n)) != 0), using the lower value of this address.
func (addr *IPv4Address) TestBit(n BitCount) bool {
	return addr.init().testBit(n)
}

// Returns true if the bit in the lower value of this segment at the given index is 1, where index 0 is the most significant bit.
func (addr *IPv4Address) IsOneBit(bitIndex BitCount) bool {
	return addr.init().isOneBit(bitIndex)
}

func (addr *IPv4Address) CompareTo(item AddressItem) int {
	return CountComparator.Compare(addr.init(), item)
}

func (addr *IPv4Address) PrefixEquals(other AddressType) bool {
	return addr.init().prefixEquals(other)
}

func (addr *IPv4Address) PrefixContains(other AddressType) bool {
	return addr.init().prefixContains(other)
}

func (addr *IPv4Address) Contains(other AddressType) bool {
	return other.getAddrType() == ipv4Type && addr.init().section.sameCountTypeContains(other.ToAddress().GetSection())
}

func (addr *IPv4Address) Equals(other AddressType) bool {
	return other.getAddrType() == ipv4Type && addr.init().section.sameCountTypeEquals(other.ToAddress().GetSection())
}

func (addr *IPv4Address) GetMaxSegmentValue() SegInt {
	return addr.init().getMaxSegmentValue()
}

func (addr *IPv4Address) ToSequentialRange() *IPv4AddressSeqRange {
	if addr == nil {
		return nil
	}
	addr = addr.init().WithoutPrefixLen()
	return newSeqRangeUnchecked(addr.GetLower().ToIPAddress(), addr.GetUpper().ToIPAddress(), addr.IsMultiple()).ToIPv4SequentialRange()
}

func (addr *IPv4Address) ToAddressString() *IPAddressString {
	return addr.init().ToIPAddress().ToAddressString()
}

func (addr *IPv4Address) IncludesZeroHostLen(networkPrefixLength BitCount) bool {
	return addr.init().includesZeroHostLen(networkPrefixLength)
}

func (addr *IPv4Address) IncludesMaxHostLen(networkPrefixLength BitCount) bool {
	return addr.init().includesMaxHostLen(networkPrefixLength)
}

// IsLoopback returns whether this address is a loopback address, such as
// [::1] (aka [0:0:0:0:0:0:0:1]) or 127.0.0.1
func (addr *IPv4Address) IsLoopback() bool {
	if addr.section == nil {
		return false
	}
	return addr.GetSegment(0).Matches(127)
}

func (addr *IPv4Address) Iterator() IPv4AddressIterator {
	return ipv4AddressIterator{addr.init().addrIterator(nil)}
}

func (addr *IPv4Address) PrefixIterator() IPv4AddressIterator {
	return ipv4AddressIterator{addr.init().prefixIterator(false)}
}

func (addr *IPv4Address) PrefixBlockIterator() IPv4AddressIterator {
	return ipv4AddressIterator{addr.init().prefixIterator(true)}
}

func (addr *IPv4Address) BlockIterator(segmentCount int) IPv4AddressIterator {
	return ipv4AddressIterator{addr.init().blockIterator(segmentCount)}
}

func (addr *IPv4Address) SequentialBlockIterator() IPv4AddressIterator {
	return ipv4AddressIterator{addr.init().sequentialBlockIterator()}
}

func (addr *IPv4Address) GetSequentialBlockIndex() int {
	return addr.init().getSequentialBlockIndex()
}

func (addr *IPv4Address) GetSequentialBlockCount() *big.Int {
	return addr.getSequentialBlockCount()
}

func (addr *IPv4Address) IncrementBoundary(increment int64) *IPv4Address {
	return addr.init().incrementBoundary(increment).ToIPv4Address()
}

func (addr *IPv4Address) Increment(increment int64) *IPv4Address {
	return addr.init().increment(increment).ToIPv4Address()
}

func (addr *IPv4Address) SpanWithPrefixBlocks() []*IPv4Address {
	if addr.IsSequential() {
		if addr.IsSinglePrefixBlock() {
			return []*IPv4Address{addr}
		}
		wrapped := WrappedIPAddress{addr.ToIPAddress()}
		spanning := getSpanningPrefixBlocks(wrapped, wrapped)
		return cloneToIPv4Addrs(spanning)
	}
	wrapped := WrappedIPAddress{addr.ToIPAddress()}
	return cloneToIPv4Addrs(spanWithPrefixBlocks(wrapped))
}

func (addr *IPv4Address) SpanWithPrefixBlocksTo(other *IPv4Address) []*IPv4Address {
	return cloneToIPv4Addrs(
		getSpanningPrefixBlocks(
			WrappedIPAddress{addr.ToIPAddress()},
			WrappedIPAddress{other.ToIPAddress()},
		),
	)
}

func (addr *IPv4Address) SpanWithSequentialBlocks() []*IPv4Address {
	if addr.IsSequential() {
		return []*IPv4Address{addr}
	}
	wrapped := WrappedIPAddress{addr.ToIPAddress()}
	return cloneToIPv4Addrs(spanWithSequentialBlocks(wrapped))
}

func (addr *IPv4Address) SpanWithSequentialBlocksTo(other *IPv4Address) []*IPv4Address {
	return cloneToIPv4Addrs(
		getSpanningSequentialBlocks(
			WrappedIPAddress{addr.ToIPAddress()},
			WrappedIPAddress{other.ToIPAddress()},
		),
	)
}

func (addr *IPv4Address) CoverWithPrefixBlockTo(other *IPv4Address) *IPv4Address {
	return addr.init().coverWithPrefixBlockTo(other.ToIPAddress()).ToIPv4Address()
}

func (addr *IPv4Address) CoverWithPrefixBlock() *IPv4Address {
	return addr.init().coverWithPrefixBlock().ToIPv4Address()
}

//
// MergeToSequentialBlocks merges this with the list of addresses to produce the smallest array of blocks that are sequential
//
// The resulting array is sorted from lowest address value to highest, regardless of the size of each prefix block.
func (addr *IPv4Address) MergeToSequentialBlocks(addrs ...*IPv4Address) []*IPv4Address {
	series := cloneIPv4Addrs(addr, addrs)
	blocks := getMergedSequentialBlocks(series)
	return cloneToIPv4Addrs(blocks)
}

//
// MergeToPrefixBlocks merges this with the list of sections to produce the smallest array of prefix blocks.
//
// The resulting array is sorted from lowest address value to highest, regardless of the size of each prefix block.
func (addr *IPv4Address) MergeToPrefixBlocks(addrs ...*IPv4Address) []*IPv4Address {
	series := cloneIPv4Addrs(addr, addrs)
	blocks := getMergedPrefixBlocks(series)
	return cloneToIPv4Addrs(blocks)
}

func (addr *IPv4Address) ReverseBytes() *IPv4Address {
	addr = addr.init()
	return addr.checkIdentity(addr.GetSection().ReverseBytes())
}

func (addr *IPv4Address) ReverseBits(perByte bool) (*IPv4Address, IncompatibleAddressError) {
	addr = addr.init()
	res, err := addr.GetSection().ReverseBits(perByte)
	if err != nil {
		return nil, err
	}
	return addr.checkIdentity(res), nil
}

func (addr *IPv4Address) ReverseSegments() *IPv4Address {
	addr = addr.init()
	return addr.checkIdentity(addr.GetSection().ReverseSegments())
}

// ReplaceLen replaces segments starting from startIndex and ending before endIndex with the same number of segments starting at replacementStartIndex from the replacement section
func (addr *IPv4Address) ReplaceLen(startIndex, endIndex int, replacement *IPv4Address, replacementIndex int) *IPv4Address {
	startIndex, endIndex, replacementIndex =
		adjust1To1Indices(startIndex, endIndex, IPv4SegmentCount, replacementIndex, IPv4SegmentCount)
	if startIndex == endIndex {
		return addr
	}
	count := endIndex - startIndex
	return addr.checkIdentity(addr.GetSection().ReplaceLen(startIndex, endIndex, replacement.GetSection(), replacementIndex, replacementIndex+count))
}

// Replace replaces segments starting from startIndex with segments from the replacement section
func (addr *IPv4Address) Replace(startIndex int, replacement *IPv4AddressSection) *IPv4Address {
	startIndex, endIndex, replacementIndex :=
		adjust1To1Indices(startIndex, startIndex+replacement.GetSegmentCount(), IPv4SegmentCount, 0, replacement.GetSegmentCount())
	count := endIndex - startIndex
	return addr.checkIdentity(addr.GetSection().ReplaceLen(startIndex, endIndex, replacement, replacementIndex, replacementIndex+count))
}

func (addr *IPv4Address) GetLeadingBitCount(ones bool) BitCount {
	return addr.GetSection().GetLeadingBitCount(ones)
}

func (addr *IPv4Address) GetTrailingBitCount(ones bool) BitCount {
	return addr.GetSection().GetTrailingBitCount(ones)
}

func (addr IPv4Address) String() string {
	return addr.init().ipAddressInternal.String()
}

func (addr *IPv4Address) ToCanonicalString() string {
	return addr.init().toCanonicalString()
}

func (addr *IPv4Address) ToNormalizedString() string {
	return addr.init().toNormalizedString()
}

func (addr *IPv4Address) ToCompressedString() string {
	return addr.init().toCompressedString()
}

func (addr *IPv4Address) ToCanonicalWildcardString() string {
	return addr.init().toCanonicalWildcardString()
}

func (addr *IPv4Address) ToNormalizedWildcardString() string {
	return addr.init().toNormalizedWildcardString()
}

func (addr *IPv4Address) ToSegmentedBinaryString() string {
	return addr.init().toSegmentedBinaryString()
}

func (addr *IPv4Address) ToSQLWildcardString() string {
	return addr.init().toSQLWildcardString()
}

func (addr *IPv4Address) ToFullString() string {
	return addr.init().toFullString()
}

func (addr *IPv4Address) ToReverseDNSString() string {
	str, _ := addr.init().toReverseDNSString()
	return str
}

func (addr *IPv4Address) ToPrefixLenString() string {
	return addr.init().toPrefixLenString()
}

func (addr *IPv4Address) ToSubnetString() string {
	return addr.init().toSubnetString()
}

func (addr *IPv4Address) ToCompressedWildcardString() string {
	return addr.init().toCompressedWildcardString()
}

func (addr *IPv4Address) ToHexString(with0xPrefix bool) (string, IncompatibleAddressError) {
	return addr.init().toHexString(with0xPrefix)
}

func (addr *IPv4Address) ToOctalString(with0Prefix bool) (string, IncompatibleAddressError) {
	return addr.init().toOctalString(with0Prefix)
}

func (addr *IPv4Address) ToBinaryString(with0bPrefix bool) (string, IncompatibleAddressError) {
	return addr.init().toBinaryString(with0bPrefix)
}

func (addr *IPv4Address) ToInetAtonString(radix Inet_aton_radix) string {
	return addr.init().GetSection().ToInetAtonString(radix)
}

func (addr *IPv4Address) ToInetAtonJoinedString(radix Inet_aton_radix, joinedCount int) (string, IncompatibleAddressError) {
	return addr.init().GetSection().ToInetAtonJoinedString(radix, joinedCount)
}

//func (addr *IPv4Address) CompareSize(other *IPv4Address) int {
//	return addr.initMultAndPrefLen().CompareSize(other.ToIPAddress())
//}

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
