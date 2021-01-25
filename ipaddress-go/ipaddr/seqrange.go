package ipaddr

import (
	"math/big"
	"sync"
	"unsafe"
)

// TODO what will be the zero IPAddressSeqRange sequential range?  An unversioned range, much like with addresses?
// ie it will have nil top and bottom
// a nil address has a grouping with no segments
// so a nil range will have no range boundaries, it will be empty
// But, an empty section (no segments) has a single value, a value of zero
// This dovetails nicely with GetValue, with various methods that check for blocks, etc
// BUT does it have an IP Version?  No...
// IPAddress zero value exists adn has zero as value, so this will too
// which means you need the same init() trick as for IPAddress{}

// TODO The other two (IPv4/6), what will be their zero ranges?  Do we default to 0.0.0.0 and :: again?
// Yep.

type rangeCache struct {
	cacheLock sync.Mutex

	countSetting countSetting
}

type ipAddressSeqRangeInternal struct {
	lower, upper *IPAddress
	cache        *rangeCache
}

type IPAddressSeqRange struct {
	ipAddressSeqRangeInternal
}

func (rng *IPAddressSeqRange) setCount() (res *big.Int) {
	cache := rng.cache
	if !cache.countSetting.isSetNoSync() {
		cache.cacheLock.Lock()
		if !cache.countSetting.isSetNoSync() {
			upper := rng.GetUpperValue()
			res = rng.GetValue()
			upper.Sub(upper, res).Add(upper, bigOneConst())
			cache.countSetting.count = upper
			res.Set(upper)
		}
		cache.cacheLock.Unlock()
	}
	return
}

func (rng *IPAddressSeqRange) GetCount() *big.Int {
	res := rng.setCount()
	if res == nil {
		// already set
		res = new(big.Int).Set(rng.cache.countSetting.count)
	}
	return res
}

// IsMore returns whether this range has a large count than the other
func (rng *IPAddressSeqRange) IsMore(other *IPAddressSeqRange) int {
	thisCount := rng.setCount()
	if thisCount == nil {
		thisCount = rng.cache.countSetting.count
	}
	otherCount := other.setCount()
	if otherCount == nil {
		otherCount = other.cache.countSetting.count
	}
	return thisCount.CmpAbs(otherCount)
}

func (rng *IPAddressSeqRange) GetLower() *IPAddress {
	return rng.lower
}

func (rng *IPAddressSeqRange) GetUpper() *IPAddress {
	return rng.upper
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

//TODO these 6 are ready to go once I add the same methods to groupings and addresses
func (rng *IPAddressSeqRange) GetValue() *big.Int {
	return rng.GetLower().GetValue()
}

func (rng *IPAddressSeqRange) GetUpperValue() *big.Int {
	return rng.GetUpper().GetValue()
}

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

func (rng *IPAddressSeqRange) ToIPv4SequentialRange() *IPv4AddressSeqRange {
	if rng == nil {
		return nil
	}
	if rng.lower.IsIPv4() { // returns false when lower is nil
		return (*IPv4AddressSeqRange)(unsafe.Pointer(rng))
	}
	return nil
}

func (rng *IPAddressSeqRange) ToIPv6SequentialRange() *IPv6AddressSeqRange {
	if rng == nil {
		return nil
	}
	if rng.lower.IsIPv6() { // returns false when lower is nil
		return (*IPv6AddressSeqRange)(unsafe.Pointer(rng))
	}
	return nil
}

func NewIPv4SeqRange(one, two *IPv4Address) *IPv4AddressSeqRange {
	return newSeqRange(one.ToIPAddress(), two.ToIPAddress()).ToIPv4SequentialRange()
}

type IPv4AddressSeqRange struct {
	ipAddressSeqRangeInternal
}

func (rng *IPv4AddressSeqRange) GetLower() *IPv4Address {
	return rng.lower.ToIPv4Address()
}

func (rng *IPv4AddressSeqRange) GetUpper() *IPv4Address {
	return rng.upper.ToIPv4Address()
}

func (rng *IPv4AddressSeqRange) ToIPAddressSeqRange() *IPAddressSeqRange {
	if rng != nil {
		return (*IPAddressSeqRange)(unsafe.Pointer(rng))
	}
	return nil
}

func newSeqRange(one, two *IPAddress) *IPAddressSeqRange {
	//TODO compare to ensure lower is the lowest one
	return &IPAddressSeqRange{
		ipAddressSeqRangeInternal{
			lower: one,
			upper: two,
		},
	}
}

func NewIPv6SeqRange(one, two *IPv6Address) *IPv6AddressSeqRange {
	return newSeqRange(one.ToIPAddress(), two.ToIPAddress()).ToIPv6SequentialRange()
}

type IPv6AddressSeqRange struct {
	ipAddressSeqRangeInternal
}

func (rng *IPv6AddressSeqRange) GetLower() *IPv6Address {
	return rng.lower.ToIPv6Address()
}

func (rng *IPv6AddressSeqRange) GetUpper() *IPv6Address {
	return rng.upper.ToIPv6Address()
}

func (rng *IPv6AddressSeqRange) ToIPAddressSeqRange() *IPAddressSeqRange {
	if rng != nil {
		return (*IPAddressSeqRange)(unsafe.Pointer(rng))
	}
	return nil
}
