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

	cachedCount *countSetting
	isMultiple  bool // set on construction
}

type ipAddressSeqRangeInternal struct {
	lower, upper *IPAddress
	cache        *rangeCache
}

func (rng *ipAddressSeqRangeInternal) IsMultiple() bool {
	if rng.lower == nil {
		return false
	}
	return rng.cache.isMultiple
}

func (rng *ipAddressSeqRangeInternal) setCount() (res *big.Int) {
	cache := rng.cache
	count := cache.cachedCount
	if count == nil {
		upper := rng.upper.GetValue()
		res = rng.lower.GetValue()
		upper.Sub(upper, res).Add(upper, bigOneConst())
		count = &countSetting{upper}
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.cachedCount))
		atomic.StorePointer(dataLoc, unsafe.Pointer(count))
		res.Set(upper)
	}
	//if cache.countSetting.isNotSetNoSync() {
	//	cache.cacheLock.Lock()
	//	if cache.countSetting.isNotSetNoSync() {
	//		upper := rng.upper.GetValue()
	//		res = rng.lower.GetValue()
	//		upper.Sub(upper, res).Add(upper, bigOneConst())
	//		cache.countSetting.count = upper
	//		res.Set(upper)
	//	}
	//	cache.cacheLock.Unlock()
	//}
	return
}

/*
func (grouping *addressDivisionGroupingBase) cacheCount(counter func() *big.Int) *big.Int {
	cache := grouping.cache // IsMultiple checks prior to this ensures cache no nil here
	count := cache.cachedCount
	if count == nil {
		count = &countSetting{counter()}
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.cachedCount))
		atomic.StorePointer(dataLoc, unsafe.Pointer(count))
	}
	//if cache.cachedCount.isNotSetNoSync() {
	//	cache.cacheLock.Lock()
	//	if cache.cachedCount.isNotSetNoSync() {
	//		cache.cachedCount.count = counter()
	//		cache.cachedCount.set()
	//	}
	//	cache.cacheLock.Unlock()
	//}
	return new(big.Int).Set(cache.cachedCount.count)
}
*/

func (rng *ipAddressSeqRangeInternal) GetCount() *big.Int {
	if !rng.IsMultiple() {
		return bigOne()
	}
	res := rng.setCount()
	if res == nil {
		// already set
		res = new(big.Int).Set(rng.cache.cachedCount.count)
	}
	return res
}

// IsMore returns whether this range has a large count than the other
func (rng *ipAddressSeqRangeInternal) IsMore(other *IPAddressSeqRange) int {
	if !rng.IsMultiple() {
		if other.IsMultiple() {
			return -1
		}
		return 0
	}
	thisCount := rng.setCount()
	if thisCount == nil {
		thisCount = rng.cache.cachedCount.count
	}
	other = other.init()
	otherCount := other.setCount()
	if otherCount == nil {
		otherCount = other.cache.cachedCount.count
	}
	return thisCount.CmpAbs(otherCount)
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

func (addr *IPAddressSeqRange) GetIP() net.IP {
	return addr.GetBytes()
}

func (addr *IPAddressSeqRange) CopyIP(bytes net.IP) net.IP {
	return addr.CopyBytes(bytes)
}

func (addr *IPAddressSeqRange) GetUpperIP() net.IP {
	return addr.GetUpperBytes()
}

func (addr *IPAddressSeqRange) CopyUpperIP(bytes net.IP) net.IP {
	return addr.CopyUpperBytes(bytes)
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

//TODO these 7 are ready to go once I add the same methods to groupings and addresses
func (rng *IPAddressSeqRange) GetValue() *big.Int {
	return rng.GetLower().GetValue()
}

func (rng *IPAddressSeqRange) GetUpperValue() *big.Int {
	return rng.GetUpper().GetValue()
}

//func (rng *IPAddressSeqRange) IsMultiple() bool {
//	return !rng.GetLower().Equals(rng.GetUpper())
//}
//
//func (rng *IPAddressSeqRange) IsZero() bool {
//	return rng.IncludesZero() && !rng.IsMultiple()
//}
//
//func (rng *IPAddressSeqRange) IncludesZero() bool {
//	return rng.GetLower().IsZero()
//}
//
//func (rng *IPAddressSeqRange) IsMax() bool {
//	return rng.IncludesMax() && !rng.IsMultiple()
//}
//
//func (rng *IPAddressSeqRange) IncludesMax() bool {
//	return rng.GetUpper().IsMax()
//}

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

func (rng *IPv4AddressSeqRange) GetBitCount() BitCount {
	return rng.GetLower().GetBitCount()
}

func (rng *IPv4AddressSeqRange) GetByteCount() int {
	return rng.GetLower().GetByteCount()
}

func (rng *IPv4AddressSeqRange) GetLower() *IPv4Address {
	return rng.init().lower.ToIPv4Address()
}

func (rng *IPv4AddressSeqRange) GetUpper() *IPv4Address {
	return rng.init().upper.ToIPv4Address()
}

func (addr *IPv4AddressSeqRange) GetIP() net.IP {
	return addr.GetBytes()
}

func (addr *IPv4AddressSeqRange) CopyIP(bytes net.IP) net.IP {
	return addr.CopyBytes(bytes)
}

func (addr *IPv4AddressSeqRange) GetUpperIP() net.IP {
	return addr.GetUpperBytes()
}

func (addr *IPv4AddressSeqRange) CopyUpperIP(bytes net.IP) net.IP {
	return addr.CopyUpperBytes(bytes)
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
	return rng.containsRange(other)
}

func (rng *IPv4AddressSeqRange) Equals(other IPAddressSeqRangeType) bool {
	return rng.init().equals(other)
}

func (rng *IPv4AddressSeqRange) ToIPAddressSeqRange() *IPAddressSeqRange {
	return (*IPAddressSeqRange)(unsafe.Pointer(rng))
}

func compareLowValues(one, two *Address) int {
	return LowValueComparator.CompareAddresses(one, two)
}

func compareLowIPAddressValues(one, two *IPAddress) int {
	return LowValueComparator.CompareAddresses(one, two)
}

func newSeqRange(one, two *IPAddress) *IPAddressSeqRange {
	//TODO compare to ensure lower is the lowest one, also set isMultiple when you do the comparison
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

func NewIPv6SeqRange(one, two *IPv6Address) *IPv6AddressSeqRange {
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

func (rng *IPv6AddressSeqRange) GetBitCount() BitCount {
	return rng.GetLower().GetBitCount()
}

func (rng *IPv6AddressSeqRange) GetByteCount() int {
	return rng.GetLower().GetByteCount()
}

func (rng *IPv6AddressSeqRange) GetLower() *IPv6Address {
	return rng.init().lower.ToIPv6Address()
}

func (rng *IPv6AddressSeqRange) GetUpper() *IPv6Address {
	return rng.init().upper.ToIPv6Address()
}

func (addr *IPv6AddressSeqRange) GetIP() net.IP {
	return addr.GetBytes()
}

func (addr *IPv6AddressSeqRange) CopyIP(bytes net.IP) net.IP {
	return addr.CopyBytes(bytes)
}

func (addr *IPv6AddressSeqRange) GetUpperIP() net.IP {
	return addr.GetUpperBytes()
}

func (addr *IPv6AddressSeqRange) CopyUpperIP(bytes net.IP) net.IP {
	return addr.CopyUpperBytes(bytes)
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
	return rng.init().contains(other)
}

func (rng *IPv6AddressSeqRange) ContainsRange(other IPAddressSeqRangeType) bool {
	return rng.containsRange(other)
}

func (rng *IPv6AddressSeqRange) Equals(other IPAddressSeqRangeType) bool {
	return rng.init().equals(other)
}

func (rng *IPv6AddressSeqRange) ToIPAddressSeqRange() *IPAddressSeqRange {
	return (*IPAddressSeqRange)(unsafe.Pointer(rng))
}
