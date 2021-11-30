package ipaddr

import (
	"fmt"
	"math/big"
	"net"
	"unsafe"
)

func NewIPv6SeqRange(one, two *IPv6Address) *IPv6AddressSeqRange {
	one = one.WithoutZone()
	two = two.WithoutZone()
	return newSeqRange(one.ToIPAddress(), two.ToIPAddress()).ToIPv6SequentialRange()
}

var zeroIPv6Range = NewIPv6SeqRange(zeroIPv6, zeroIPv6)

type IPv6AddressSeqRange struct {
	ipAddressSeqRangeInternal
}

func (rng *IPv6AddressSeqRange) init() *IPv6AddressSeqRange {
	if rng.lower == nil {
		return zeroIPv6Range
	}
	return rng
}

func (rng *IPv6AddressSeqRange) GetCount() *big.Int {
	if rng == nil {
		return bigZero()
	}
	return rng.ipAddressSeqRangeInternal.getCount()
}

func (rng *IPv6AddressSeqRange) IsMultiple() bool {
	return rng != nil && rng.isMultiple()
}

func (rng *IPv6AddressSeqRange) String() string {
	if rng == nil {
		return nilString()
	}
	return rng.ToString((*IPv6Address).String, DefaultSeqRangeSeparator, (*IPv6Address).String)
}

func (rng IPv6AddressSeqRange) Format(state fmt.State, verb rune) {
	rng.init().format(state, verb)
}

func (rng *IPv6AddressSeqRange) ToString(lowerStringer func(*IPv6Address) string, separator string, upperStringer func(*IPv6Address) string) string {
	if rng == nil {
		return nilString()
	}
	return rng.init().toString(
		func(addr *IPAddress) string {
			return lowerStringer(addr.ToIPv6Address())
		},
		separator,
		func(addr *IPAddress) string {
			return upperStringer(addr.ToIPv6Address())
		},
	)
}

func (rng *IPv6AddressSeqRange) ToNormalizedString() string {
	return rng.ToString((*IPv6Address).ToNormalizedString, DefaultSeqRangeSeparator, (*IPv6Address).ToNormalizedString)
}

func (rng *IPv6AddressSeqRange) ToCanonicalString() string {
	return rng.ToString((*IPv6Address).ToCanonicalString, DefaultSeqRangeSeparator, (*IPv6Address).ToNormalizedString)
}

func (rng *IPv6AddressSeqRange) GetBitCount() BitCount {
	return rng.GetLower().GetBitCount()
}

func (rng *IPv6AddressSeqRange) GetByteCount() int {
	return rng.GetLower().GetByteCount()
}

func (rng *IPv6AddressSeqRange) GetLowerIPAddress() *IPAddress {
	return rng.init().lower
}

func (rng *IPv6AddressSeqRange) GetUpperIPAddress() *IPAddress {
	return rng.init().upper
}

func (rng *IPv6AddressSeqRange) GetLower() *IPv6Address {
	return rng.init().lower.ToIPv6Address()
}

func (rng *IPv6AddressSeqRange) GetUpper() *IPv6Address {
	return rng.init().upper.ToIPv6Address()
}

func (rng *IPv6AddressSeqRange) GetIP() net.IP {
	return rng.GetBytes()
}

func (rng *IPv6AddressSeqRange) CopyIP(bytes net.IP) net.IP {
	return rng.GetLower().CopyIP(bytes)
}

func (rng *IPv6AddressSeqRange) GetUpperIP() net.IP {
	return rng.GetUpperBytes()
}

func (rng *IPv6AddressSeqRange) CopyUpperIP(bytes net.IP) net.IP {
	return rng.GetUpper().CopyUpperIP(bytes)
}

func (rng *IPv6AddressSeqRange) GetBytes() []byte {
	return rng.GetLower().GetBytes()
}

func (rng *IPv6AddressSeqRange) CopyBytes(bytes []byte) []byte {
	return rng.GetLower().CopyBytes(bytes)
}

func (rng *IPv6AddressSeqRange) GetUpperBytes() []byte {
	return rng.GetUpper().GetUpperBytes()
}

func (rng *IPv6AddressSeqRange) CopyUpperBytes(bytes []byte) []byte {
	return rng.GetUpper().CopyUpperBytes(bytes)
}

func (rng *IPv6AddressSeqRange) GetValue() *big.Int {
	return rng.GetLower().GetValue()
}

func (rng *IPv6AddressSeqRange) GetUpperValue() *big.Int {
	return rng.GetUpper().GetValue()
}

func (rng *IPv6AddressSeqRange) Contains(other IPAddressType) bool {
	if rng == nil {
		return other == nil || other.ToAddress() == nil
	}
	return rng.init().contains(other)
}

func (rng *IPv6AddressSeqRange) ContainsRange(other IPAddressSeqRangeType) bool {
	if rng == nil {
		return other == nil || other.ToIPAddressSeqRange() == nil
	}
	return rng.init().containsRange(other)
}

func (rng *IPv6AddressSeqRange) Equal(other IPAddressSeqRangeType) bool {
	if rng == nil {
		return other == nil || other.ToIPAddressSeqRange() == nil
	}
	return rng.init().equals(other)
}

func (rng *IPv6AddressSeqRange) Compare(item AddressItem) int {
	if rng != nil {
		rng = rng.init()
	}
	return CountComparator.Compare(rng, item)
}

func (rng *IPv6AddressSeqRange) CompareSize(other IPAddressSeqRangeType) int {
	if rng == nil {
		if other != nil && other.ToIPAddressSeqRange() != nil {
			// we have size 0, other has size >= 1
			return -1
		}
		return 0
	}
	return rng.compareSize(other)
}

func (rng *IPv6AddressSeqRange) ContainsPrefixBlock(prefixLen BitCount) bool {
	return rng.init().ipAddressSeqRangeInternal.ContainsPrefixBlock(prefixLen)
}

func (rng *IPv6AddressSeqRange) ContainsSinglePrefixBlock(prefixLen BitCount) bool {
	return rng.init().ipAddressSeqRangeInternal.ContainsSinglePrefixBlock(prefixLen)
}

func (rng *IPv6AddressSeqRange) GetPrefixLenForSingleBlock() PrefixLen {
	return rng.init().ipAddressSeqRangeInternal.GetPrefixLenForSingleBlock()
}

func (rng *IPv6AddressSeqRange) GetMinPrefixLenForBlock() BitCount {
	return rng.init().ipAddressSeqRangeInternal.GetMinPrefixLenForBlock()
}

func (rng *IPv6AddressSeqRange) Iterator() IPv6AddressIterator {
	if rng == nil {
		return ipv6AddressIterator{nilAddrIterator()}
	}
	return ipv6AddressIterator{rng.init().iterator()}
}

func (rng *IPv6AddressSeqRange) PrefixBlockIterator(prefLength BitCount) IPv6AddressIterator {
	return &ipv6AddressIterator{rng.init().prefixBlockIterator(prefLength)}
}

func (rng *IPv6AddressSeqRange) PrefixIterator(prefLength BitCount) IPv6AddressSeqRangeIterator {
	return &ipv6RangeIterator{rng.init().prefixIterator(prefLength)}
}

func (rng *IPv6AddressSeqRange) ToIPAddressSeqRange() *IPAddressSeqRange {
	return (*IPAddressSeqRange)(unsafe.Pointer(rng))
}

func (rng *IPv6AddressSeqRange) Overlaps(other *IPv6AddressSeqRange) bool {
	return rng.init().overlaps(other.ToIPAddressSeqRange())
}

func (rng *IPv6AddressSeqRange) Intersect(other *IPv6AddressSeqRange) *IPAddressSeqRange {
	return rng.init().intersect(other.toIPSequentialRange())
}

func (rng *IPv6AddressSeqRange) CoverWithPrefixBlock() *IPv6Address {
	return rng.GetLower().CoverWithPrefixBlockTo(rng.GetUpper())
}

func (rng *IPv6AddressSeqRange) SpanWithPrefixBlocks() []*IPv6Address {
	return rng.GetLower().SpanWithPrefixBlocksTo(rng.GetUpper())
}

func (rng *IPv6AddressSeqRange) SpanWithSequentialBlocks() []*IPv6Address {
	return rng.GetLower().SpanWithSequentialBlocksTo(rng.GetUpper())
}

// Joins the given ranges into the fewest number of ranges.
// The returned array will be sorted by ascending lowest range value.
func (rng *IPv6AddressSeqRange) Join(ranges ...*IPAddressSeqRange) []*IPv6AddressSeqRange {
	origLen := len(ranges)
	ranges = append(make([]*IPAddressSeqRange, 0, origLen+1), ranges...)
	ranges[origLen] = rng.ToIPAddressSeqRange()
	return cloneToIPv6SeqRange(join(ranges))
}
