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

// TODO there is 1 other categories:  uint32 (not sure what I was thinking with this comment, probably just talking about constructor for uint32 needed)

func NewIPv4Address(section *IPv4AddressSection) *IPv4Address {
	return createAddress(section.ToAddressSection(), noZone).ToIPv4Address()
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

func NewIPv4AddressFromVals(vals SegmentValueProvider) (addr *IPv4Address) {
	section := NewIPv4AddressSectionFromVals(vals, IPv4SegmentCount)
	addr = NewIPv4Address(section)
	return
}

func NewIPv4AddressFromPrefixedVals(vals SegmentValueProvider, prefixLength PrefixLen) (addr *IPv4Address, err AddressValueException) {
	section := NewIPv4AddressSectionFromPrefixedVals(vals, IPv4SegmentCount, prefixLength)
	addr = NewIPv4Address(section)
	return
}

func NewIPv4AddressFromRange(vals, upperVals SegmentValueProvider) (addr *IPv4Address) {
	section := NewIPv4AddressSectionFromRangeVals(vals, upperVals, IPv4SegmentCount)
	addr = NewIPv4Address(section)
	return
}

func NewIPv4AddressFromPrefixedRange(vals, upperVals SegmentValueProvider, prefixLength PrefixLen) (addr *IPv4Address, err AddressValueException) {
	section := NewIPv4AddressSectionFromPrefixedRangeVals(vals, upperVals, IPv4SegmentCount, prefixLength)
	addr = NewIPv4Address(section)
	return
}

var zeroIPv4 = initZeroIPv4()

func initZeroIPv4() *IPv4Address {
	div := NewIPv4Segment(0).ToAddressDivision()
	segs := []*AddressDivision{div, div, div, div}
	section, _ := newIPv4AddressSection(segs, false)
	return NewIPv4Address(section)
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

// GetGenericSegment returns the segment at the given index as an AddressStandardSegment
func (addr *IPv4Address) GetGenericSegment(index int) AddressStandardSegment {
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

func (addr *IPv4Address) ToZeroHost() (*IPv4Address, IncompatibleAddressException) {
	res, err := addr.init().toZeroHost()
	return res.ToIPv4Address(), err
}

func (addr *IPv4Address) ToZeroHostLen(prefixLength BitCount) (*IPv4Address, IncompatibleAddressException) {
	res, err := addr.init().toZeroHostLen(prefixLength)
	return res.ToIPv4Address(), err
}

func (addr *IPv4Address) ToZeroNetwork() *IPv4Address {
	return addr.init().toZeroNetwork().ToIPv4Address()
}

func (addr *IPv4Address) ToMaxHost() (*IPv4Address, IncompatibleAddressException) {
	res, err := addr.init().toMaxHost()
	return res.ToIPv4Address(), err
}

func (addr *IPv4Address) ToMaxHostLen(prefixLength BitCount) (*IPv4Address, IncompatibleAddressException) {
	res, err := addr.init().toMaxHostLen(prefixLength)
	return res.ToIPv4Address(), err
}

func (addr *IPv4Address) IntValue() uint32 {
	return addr.GetSection().IntValue()
}

func (addr *IPv4Address) UpperIntValue() uint32 {
	return addr.GetSection().UpperIntValue()
}

func (addr *IPv4Address) LongValue() uint64 {
	return addr.GetSection().LongValue()
}

func (addr *IPv4Address) UpperLongValue() uint64 {
	return addr.GetSection().UpperLongValue()
}

func (addr *IPv4Address) ToPrefixBlock() *IPv4Address {
	return addr.init().toPrefixBlock().ToIPv4Address()
}

func (addr *IPv4Address) ToPrefixBlockLen(prefLen BitCount) *IPv4Address {
	return addr.init().toPrefixBlockLen(prefLen).ToIPv4Address()
}

func (addr *IPv4Address) ToBlock(segmentIndex int, lower, upper SegInt) *IPv4Address {
	return addr.init().toBlock(segmentIndex, lower, upper).ToIPv4Address()
}

func (addr *IPv4Address) WithoutPrefixLength() *IPv4Address {
	return addr.init().withoutPrefixLength().ToIPv4Address()
}

func (addr *IPv4Address) SetPrefixLen(prefixLen BitCount) *IPv4Address {
	return addr.init().setPrefixLen(prefixLen).ToIPv4Address()
}

func (addr *IPv4Address) SetPrefixLenZeroed(prefixLen BitCount) (*IPv4Address, IncompatibleAddressException) {
	res, err := addr.init().setPrefixLenZeroed(prefixLen)
	return res.ToIPv4Address(), err
}

func (addr *IPv4Address) AssignPrefixForSingleBlock() *IPv4Address {
	return addr.init().assignPrefixForSingleBlock().ToIPv4Address()
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

func (addr *IPv4Address) Contains(other AddressType) bool {
	return addr.init().contains(other)
}

func (addr *IPv4Address) Equals(other AddressType) bool {
	return addr.init().equals(other)
}

//TODO would it make sense to have an Equals and a Contains that took the same type, IPv4Address?
// Because the type checks can be avoided, so can section segment counts, etc
// WEll, I did add seriesValsSame, which avoids type checks

func (addr *IPv4Address) GetMaxSegmentValue() SegInt {
	return addr.init().getMaxSegmentValue()
}

func (addr *IPv4Address) ToSequentialRange() *IPv4AddressSeqRange {
	if addr == nil {
		return nil
	}
	addr = addr.init().WithoutPrefixLength()
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

func (addr *IPv4Address) Iterator() IPv4AddrIterator {
	return ipv4AddressIterator{addr.init().addrIterator(nil)}
}

func (addr *IPv4Address) PrefixIterator() IPv4AddrIterator {
	return ipv4AddressIterator{addr.init().prefixIterator(false)}
}

func (addr *IPv4Address) PrefixBlockIterator() IPv4AddrIterator {
	return ipv4AddressIterator{addr.init().prefixIterator(true)}
}

func (addr *IPv4Address) BlockIterator(segmentCount int) IPv4AddrIterator {
	return ipv4AddressIterator{addr.init().blockIterator(segmentCount)}
}

func (addr *IPv4Address) SequentialBlockIterator() IPv4AddrIterator {
	return ipv4AddressIterator{addr.init().sequentialBlockIterator()}
}

func (addr *IPv4Address) GetSequentialBlockIndex() int {
	return addr.init().getSequentialBlockIndex()
}

func (addr *IPv4Address) IncrementBoundary(increment int64) *IPv4Address {
	return addr.init().incrementBoundary(increment).ToIPv4Address()
}

func (addr *IPv4Address) Increment(increment int64) *IPv4Address {
	return addr.init().increment(increment).ToIPv4Address()
}

//func (addr *IPv4Address) spanWithPrefixBlocks() []ExtendedIPSegmentSeries {
//	xxx
//	wrapped := WrappedIPAddress{addr.ToIPAddress()}
//	if addr.IsSequential() {
//		if addr.IsSinglePrefixBlock() {
//			return []ExtendedIPSegmentSeries{wrapped}
//		}
//		return getSpanningPrefixBlocks(wrapped, wrapped)
//	}
//	return spanWithPrefixBlocks(wrapped)
//}
//
//func (addr *IPv4Address) spanWithPrefixBlocksTo(other *IPv4Address) []ExtendedIPSegmentSeries {
//	return getSpanningPrefixBlocks(
//		WrappedIPAddress{addr.ToIPAddress()},
//		WrappedIPAddress{other.ToIPAddress()},
//	)
//}

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
	return addr.init().toReverseDNSString()
}

func (addr *IPv4Address) ToPrefixLengthString() string {
	return addr.init().toPrefixLengthString()
}

func (addr *IPv4Address) ToSubnetString() string {
	return addr.init().toSubnetString()
}

func (addr *IPv4Address) ToCompressedWildcardString() string {
	return addr.init().toCompressedWildcardString()
}

func (addr *IPv4Address) ToHexString(with0xPrefix bool) (string, IncompatibleAddressException) {
	return addr.init().toHexString(with0xPrefix)
}

func (addr *IPv4Address) ToOctalString(with0Prefix bool) (string, IncompatibleAddressException) {
	return addr.init().toOctalString(with0Prefix)
}

func (addr *IPv4Address) ToBinaryString(with0bPrefix bool) (string, IncompatibleAddressException) {
	return addr.init().toBinaryString(with0bPrefix)
}

func (addr *IPv4Address) ToInetAtonString(radix Inet_aton_radix) string {
	return addr.init().GetSection().ToInetAtonString(radix)
}

func (addr *IPv4Address) ToInetAtonJoinedString(radix Inet_aton_radix, joinedCount int) (string, IncompatibleAddressException) {
	return addr.init().GetSection().ToInetAtonJoinedString(radix, joinedCount)
}

//func (addr *IPv4Address) CompareSize(other *IPv4Address) int {
//	return addr.init().CompareSize(other.ToIPAddress())
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
