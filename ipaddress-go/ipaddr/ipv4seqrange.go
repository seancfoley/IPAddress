package ipaddr

import (
	"math/big"
	"net"
	"unsafe"
)

func NewIPv4SeqRange(one, two *IPv4Address) *IPv4AddressSeqRange {
	return newSeqRange(one.ToIPAddress(), two.ToIPAddress()).ToIPv4SequentialRange()
}

var zeroIPv4Range = NewIPv4SeqRange(zeroIPv4, zeroIPv4)

type IPv4AddressSeqRange struct {
	ipAddressSeqRangeInternal
}

func (rng *IPv4AddressSeqRange) init() *IPv4AddressSeqRange {
	if rng.lower == nil {
		return zeroIPv4Range
	}
	return rng
}

func (rng IPv4AddressSeqRange) String() string {
	return rng.ToString((*IPv4Address).String, DefaultSeqRangeSeparator, (*IPv4Address).String)
}

func (rng *IPv4AddressSeqRange) ToString(lowerStringer func(*IPv4Address) string, separator string, upperStringer func(*IPv4Address) string) string {
	return rng.init().toString(
		func(addr *IPAddress) string {
			return lowerStringer(addr.ToIPv4Address())
		},
		separator,
		func(addr *IPAddress) string {
			return upperStringer(addr.ToIPv4Address())
		},
	)
}

func (rng *IPv4AddressSeqRange) ToNormalizedString() string {
	return rng.ToString((*IPv4Address).ToNormalizedString, DefaultSeqRangeSeparator, (*IPv4Address).ToNormalizedString)
}

func (rng *IPv4AddressSeqRange) ToCanonicalString() string {
	return rng.ToString((*IPv4Address).ToCanonicalString, DefaultSeqRangeSeparator, (*IPv4Address).ToNormalizedString)
}

func (rng *IPv4AddressSeqRange) GetBitCount() BitCount {
	return rng.GetLower().GetBitCount()
}

func (rng *IPv4AddressSeqRange) GetByteCount() int {
	return rng.GetLower().GetByteCount()
}

func (rng *IPv4AddressSeqRange) GetLowerIPAddress() *IPAddress {
	return rng.init().lower
}

func (rng *IPv4AddressSeqRange) GetUpperIPAddress() *IPAddress {
	return rng.init().upper
}

func (rng *IPv4AddressSeqRange) GetLower() *IPv4Address {
	return rng.init().lower.ToIPv4Address()
}

func (rng *IPv4AddressSeqRange) GetUpper() *IPv4Address {
	return rng.init().upper.ToIPv4Address()
}

func (rng *IPv4AddressSeqRange) GetIP() net.IP {
	return rng.GetBytes()
}

func (rng *IPv4AddressSeqRange) CopyIP(bytes net.IP) net.IP {
	return rng.CopyBytes(bytes)
}

func (rng *IPv4AddressSeqRange) GetUpperIP() net.IP {
	return rng.GetUpperBytes()
}

func (rng *IPv4AddressSeqRange) CopyUpperIP(bytes net.IP) net.IP {
	return rng.CopyUpperBytes(bytes)
}

func (rng *IPv4AddressSeqRange) GetBytes() []byte {
	return rng.GetLower().GetBytes()
}

func (rng *IPv4AddressSeqRange) CopyBytes(bytes []byte) []byte {
	return rng.GetLower().CopyBytes(bytes)
}

func (rng *IPv4AddressSeqRange) GetUpperBytes() []byte {
	return rng.GetUpper().GetUpperBytes()
}

func (rng *IPv4AddressSeqRange) CopyUpperBytes(bytes []byte) []byte {
	return rng.GetUpper().CopyUpperBytes(bytes)
}

func (rng *IPv4AddressSeqRange) GetValue() *big.Int {
	return rng.GetLower().GetValue()
}

func (rng *IPv4AddressSeqRange) GetUpperValue() *big.Int {
	return rng.GetUpper().GetValue()
}

func (rng *IPv4AddressSeqRange) Contains(other IPAddressType) bool {
	return rng.init().contains(other)
}

func (rng *IPv4AddressSeqRange) ContainsRange(other IPAddressSeqRangeType) bool {
	return rng.init().containsRange(other)
}

func (rng *IPv4AddressSeqRange) Equals(other IPAddressSeqRangeType) bool {
	return rng.init().equals(other)
}

func (rng *IPv4AddressSeqRange) ContainsPrefixBlock(prefixLen BitCount) bool {
	return rng.init().ipAddressSeqRangeInternal.ContainsPrefixBlock(prefixLen)
}

func (rng *IPv4AddressSeqRange) ContainsSinglePrefixBlock(prefixLen BitCount) bool {
	return rng.init().ipAddressSeqRangeInternal.ContainsSinglePrefixBlock(prefixLen)
}

func (rng *IPv4AddressSeqRange) GetPrefixLengthForSingleBlock() PrefixLen {
	return rng.init().ipAddressSeqRangeInternal.GetPrefixLengthForSingleBlock()
}

func (rng *IPv4AddressSeqRange) GetMinPrefixLengthForBlock() BitCount {
	return rng.init().ipAddressSeqRangeInternal.GetMinPrefixLengthForBlock()
}

func (rng *IPv4AddressSeqRange) Iterator() IPv4AddressIterator {
	return ipv4AddressIterator{rng.init().iterator()}
}

func (rng *IPv4AddressSeqRange) PrefixBlockIterator(prefLength BitCount) IPv4AddressIterator {
	return &ipv4AddressIterator{rng.init().prefixBlockIterator(prefLength)}
}

func (rng *IPv4AddressSeqRange) PrefixIterator(prefLength BitCount) IPv4AddressSeqRangeIterator {
	return &ipv4RangeIterator{rng.init().prefixIterator(prefLength)}
}

func (rng *IPv4AddressSeqRange) ToIPAddressSeqRange() *IPAddressSeqRange {
	return (*IPAddressSeqRange)(unsafe.Pointer(rng))
}

func (rng *IPv4AddressSeqRange) Overlaps(other *IPv4AddressSeqRange) bool {
	return rng.init().overlaps(other.ToIPAddressSeqRange())
}

func (rng *IPv4AddressSeqRange) Intersect(other *IPv4AddressSeqRange) *IPAddressSeqRange {
	return rng.init().intersect(other.toIPSequentialRange())
}

func (rng *IPv4AddressSeqRange) CoverWithPrefixBlock() *IPv4Address {
	return rng.GetLower().CoverWithPrefixBlockTo(rng.GetUpper())
}

func (rng *IPv4AddressSeqRange) SpanWithPrefixBlocks() []*IPv4Address {
	return rng.GetLower().SpanWithPrefixBlocksTo(rng.GetUpper())
}

func (rng *IPv4AddressSeqRange) SpanWithSequentialBlocks() []*IPv4Address {
	return rng.GetLower().SpanWithSequentialBlocksTo(rng.GetUpper())
}

// Joins the given ranges into the fewest number of ranges.
// The returned array will be sorted by ascending lowest range value.
func (rng *IPv4AddressSeqRange) Join(ranges ...*IPAddressSeqRange) []*IPv4AddressSeqRange {
	origLen := len(ranges)
	ranges = append(make([]*IPAddressSeqRange, 0, origLen+1), ranges...)
	ranges[origLen] = rng.ToIPAddressSeqRange()
	return cloneToIPv4SeqRange(join(ranges))
}

// JoinTo joins this range to the other.  If this range overlaps with the given range,
// or if the highest value of the lower range is one below the lowest value of the higher range,
// then the two are joined into a new larger range that is returned.
// Otherwise nil is returned.
func (rng *IPv4AddressSeqRange) JoinTo(other *IPv4AddressSeqRange) *IPv4AddressSeqRange {
	return rng.init().joinTo(other.init().ToIPAddressSeqRange()).ToIPv4SequentialRange()
}

// Extend extends this sequential range to include all address in the given range.
// If the argument has a different IP version than this, nil is returned.
// Otherwise, this method returns the range that includes this range, the given range, and all addresses in-between.
func (rng *IPv4AddressSeqRange) Extend(other *IPv4AddressSeqRange) *IPv4AddressSeqRange {
	return rng.init().extend(other.init().ToIPAddressSeqRange()).ToIPv4SequentialRange()
}

// Subtract Subtracts the given range from this range, to produce either zero, one, or two address ranges that contain the addresses in this range and not in the given range.
// If the result has length 2, the two ranges are ordered by ascending lowest range value.
func (rng *IPv4AddressSeqRange) Subtract(other *IPv4AddressSeqRange) []*IPv4AddressSeqRange {
	return cloneToIPv4SeqRange(rng.init().subtract(other.init().ToIPAddressSeqRange()))
}

// GetIPv4Count is equivalent to GetCount() but returns a uint64
func (rng *IPv4AddressSeqRange) GetIPv4Count() uint64 {
	return rng.GetUpper().Uint64Value() - rng.GetLower().Uint64Value() + 1
}

// GetIPv4PrefixCount is equivalent to GetPrefixCountLen(int) but returns a uint64
func (rng *IPv4AddressSeqRange) GetIPv4PrefixCount(prefixLength BitCount) uint64 {
	prefixLength = checkBitCount(prefixLength, IPv4BitCount)
	bitCount := IPv4BitCount
	if bitCount <= prefixLength {
		return rng.GetIPv4Count()
	}
	shiftAdjustment := bitCount - prefixLength
	upperAdjusted := rng.GetUpper().Uint64Value() >> shiftAdjustment
	lowerAdjusted := rng.GetLower().Uint64Value() >> shiftAdjustment
	return upperAdjusted - lowerAdjusted + 1
}