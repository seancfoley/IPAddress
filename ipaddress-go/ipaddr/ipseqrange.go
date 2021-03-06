package ipaddr

import (
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"unsafe"
)

type rangeCache struct {
	cacheLock sync.Mutex

	cachedCount *big.Int
	isMultiple  bool // set on construction
}

type ipAddressSeqRangeInternal struct {
	lower, upper *IPAddress
	cache        *rangeCache
}

func (rng *ipAddressSeqRangeInternal) IsMultiple() bool {
	return rng.cache != nil && rng.cache.isMultiple
}

func (rng *ipAddressSeqRangeInternal) GetCount() *big.Int {
	return rng.GetCachedCount(true)
}

func (rng *ipAddressSeqRangeInternal) GetCachedCount(copy bool) (res *big.Int) {
	cache := rng.cache
	count := cache.cachedCount
	if count == nil {
		if !rng.IsMultiple() {
			count = bigOne()
		} else if ipv4Range := rng.toIPv4SequentialRange(); ipv4Range != nil {
			upper := int64(ipv4Range.GetUpper().IntValue())
			lower := int64(ipv4Range.GetLower().IntValue())
			val := upper - lower + 1
			count = new(big.Int).SetInt64(val)
		} else {
			count = rng.upper.GetValue()
			res = rng.lower.GetValue()
			count.Sub(count, res).Add(count, bigOneConst())
			res.Set(count)
		}
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.cachedCount))
		atomic.StorePointer(dataLoc, unsafe.Pointer(count))
	}
	if res == nil {
		if copy {
			res = new(big.Int).Set(count)
		} else {
			res = count
		}
	}
	return
}

func (rng *ipAddressSeqRangeInternal) GetPrefixCount(prefixLen BitCount) *big.Int {
	if !rng.IsMultiple() { // also checks for zero-ranges
		return bigOne()
	}
	bitCount := rng.lower.GetBitCount()
	if prefixLen >= bitCount {
		return rng.GetCount()
	} else if prefixLen <= 0 {
		return bigOne()
	}
	shiftAdjustment := bitCount - prefixLen
	if ipv4Range := rng.toIPv4SequentialRange(); ipv4Range != nil {
		upper := ipv4Range.GetUpper()
		lower := ipv4Range.GetLower()
		upperAdjusted := upper.IntValue() >> shiftAdjustment
		lowerAdjusted := lower.IntValue() >> shiftAdjustment
		result := upperAdjusted - lowerAdjusted + 1
		return new(big.Int).SetInt64(result)
	}
	upper := rng.upper.GetValue()
	ushiftAdjustment := uint(shiftAdjustment)
	upper.Rsh(upper, ushiftAdjustment)
	lower := rng.lower.GetValue()
	lower.Rsh(lower, ushiftAdjustment)
	upper.Sub(upper, lower).Add(upper, bigOneConst())
	return upper
}

// IsMore returns whether this range has a large count than the other
func (rng *ipAddressSeqRangeInternal) IsMore(other *IPAddressSeqRange) int {
	if !rng.IsMultiple() {
		if other.IsMultiple() {
			return -1
		}
		return 0
	}
	return rng.GetCachedCount(false).CmpAbs(other.init().GetCachedCount(false))
}

func (rng *ipAddressSeqRangeInternal) contains(other IPAddressType) bool {
	otherAddr := other.ToIPAddress()
	return compareLowIPAddressValues(otherAddr.GetLower(), rng.lower) >= 0 &&
		compareLowIPAddressValues(otherAddr.GetUpper(), rng.upper) <= 0
}

func (rng *ipAddressSeqRangeInternal) equals(other IPAddressSeqRangeType) bool {
	otherRng := other.ToIPAddressSeqRange()
	return rng.lower.Equals(otherRng.GetLower()) && rng.upper.Equals(otherRng.GetUpper())
}

func (rng *ipAddressSeqRangeInternal) containsRange(other IPAddressSeqRangeType) bool {
	otherRange := other.ToIPAddressSeqRange()
	return compareLowIPAddressValues(otherRange.GetLower(), rng.lower) >= 0 &&
		compareLowIPAddressValues(otherRange.GetUpper(), rng.upper) <= 0
}

func (rng *ipAddressSeqRangeInternal) toIPv4SequentialRange() *IPv4AddressSeqRange {
	if rng.lower != nil && rng.lower.getAddrType().isIPv4() {
		return (*IPv4AddressSeqRange)(unsafe.Pointer(rng))
	}
	return nil
}

func (rng *ipAddressSeqRangeInternal) IsZero() bool {
	return rng.IncludesZero() && !rng.IsMultiple()
}

func (rng *ipAddressSeqRangeInternal) IncludesZero() bool {
	lower := rng.lower
	return lower == nil || lower.IsZero()
}

func (rng *ipAddressSeqRangeInternal) IsMax() bool {
	return rng.IncludesMax() && !rng.IsMultiple()
}

func (rng *ipAddressSeqRangeInternal) IncludesMax() bool {
	upper := rng.upper
	return upper == nil || upper.IsMax()
}

type IPAddressSeqRange struct {
	ipAddressSeqRangeInternal
}

var zeroRange = newSeqRange(zeroIPAddr, zeroIPAddr)

func (rng *IPAddressSeqRange) init() *IPAddressSeqRange {
	if rng.lower == nil {
		return zeroRange
	}
	return rng
}

func (rng *IPAddressSeqRange) GetLower() *IPAddress {
	return rng.init().lower
}

func (rng *IPAddressSeqRange) GetUpper() *IPAddress {
	return rng.init().upper
}

//TODO these two, then the remainder of methods in IPAddressSeqRange to do are the ones above these two in the Java IPAddressSeqRange code
//
// TODO these two CANNOT go into the internal class
// for the ipv4/6 these return false, but for the zero-bit ip range I think they are likely true
//	func (rng *IPAddressSeqRange) ContainsPrefixBlock(int prefixLen) bool {
//		return IPAddressSection.containsPrefixBlock(prefixLen, getLower(), getUpper());
//	}
//
//	func (rng *IPAddressSeqRange) ContainsSinglePrefixBlock(int prefixLen) bool {
//		return IPAddressSection.containsSinglePrefixBlock(prefixLen, getLower(), getUpper());
//	}

func (rng *IPAddressSeqRange) GetBitCount() BitCount {
	return rng.GetLower().GetBitCount()
}

func (rng *IPAddressSeqRange) GetByteCount() int {
	return rng.GetLower().GetByteCount()
}

func (rng *IPAddressSeqRange) GetIP() net.IP {
	return rng.GetBytes()
}

func (rng *IPAddressSeqRange) CopyIP(bytes net.IP) net.IP {
	return rng.CopyBytes(bytes)
}

func (rng *IPAddressSeqRange) GetUpperIP() net.IP {
	return rng.GetUpperBytes()
}

func (rng *IPAddressSeqRange) CopyUpperIP(bytes net.IP) net.IP {
	return rng.CopyUpperBytes(bytes)
}

func (rng *IPAddressSeqRange) GetBytes() []byte {
	return rng.GetLower().GetBytes()
}

func (rng *IPAddressSeqRange) CopyBytes(bytes []byte) []byte {
	return rng.GetLower().CopyBytes(bytes)
}

func (rng *IPAddressSeqRange) GetUpperBytes() []byte {
	return rng.GetUpper().GetUpperBytes()
}

func (rng *IPAddressSeqRange) CopyUpperBytes(bytes []byte) []byte {
	return rng.GetUpper().CopyUpperBytes(bytes)
}

func (rng *IPAddressSeqRange) Contains(other IPAddressType) bool {
	return rng.init().contains(other)
}

func (rng *IPAddressSeqRange) ContainsRange(other IPAddressSeqRangeType) bool {
	return rng.containsRange(other)
}

func (rng *IPAddressSeqRange) Equals(other IPAddressSeqRangeType) bool {
	return rng.init().equals(other)
}

func (rng *IPAddressSeqRange) GetValue() *big.Int {
	return rng.GetLower().GetValue()
}

func (rng *IPAddressSeqRange) GetUpperValue() *big.Int {
	return rng.GetUpper().GetValue()
}

func (rng *IPAddressSeqRange) ToIPAddressSeqRange() *IPAddressSeqRange {
	return rng
}

func (rng *IPAddressSeqRange) IsIPv4SequentialRange() bool { // returns false when lower is nil
	return rng != nil && rng.GetLower().IsIPv4()
}

func (rng *IPAddressSeqRange) IsIPv6SequentialRange() bool { // returns false when lower is nil
	return rng != nil && rng.GetLower().IsIPv6()
}

func (rng *IPAddressSeqRange) ToIPv4SequentialRange() *IPv4AddressSeqRange {
	if rng.IsIPv4SequentialRange() {
		return (*IPv4AddressSeqRange)(rng)
	}
	return nil
}

func (rng *IPAddressSeqRange) ToIPv6SequentialRange() *IPv6AddressSeqRange {
	if rng.IsIPv6SequentialRange() {
		return (*IPv6AddressSeqRange)(rng)
	}
	return nil
}

func compareLowValues(one, two *Address) int {
	return LowValueComparator.CompareAddresses(one, two)
}

func compareLowIPAddressValues(one, two *IPAddress) int {
	return LowValueComparator.CompareAddresses(one, two)
}

func newSeqRange(one, two *IPAddress) *IPAddressSeqRange {
	//TODO compare to ensure lower is the lowest one, also set isMultiple when you do the comparison
	//TODO looks like you need to add withoutPrefix() before doing this
	/*
		boolean f;
				if((f = first.contains(other)) || other.contains(first)) {
					T addr = f ? prefixLenRemover.apply(first) : prefixLenRemover.apply(other);
					lower = getLower.apply(addr);
					upper = getUpper.apply(addr);
				} else {
					T firstLower = getLower.apply(first);
					T otherLower = getLower.apply(other);
					T firstUpper = getUpper.apply(first);
					T otherUpper = getUpper.apply(other);
					T lower = compareLowValues(firstLower, otherLower) > 0 ? otherLower : firstLower;
					T upper = compareLowValues(firstUpper, otherUpper) < 0 ? otherUpper : firstUpper;
					this.lower = prefixLenRemover.apply(lower);
					this.upper = prefixLenRemover.apply(upper);
				}
	*/
	return &IPAddressSeqRange{
		ipAddressSeqRangeInternal{
			lower: one,
			upper: two,
			cache: &rangeCache{},
		},
	}
}
