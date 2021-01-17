package ipaddr

import (
	"fmt"
	"math/big"
	"sync"
	"unsafe"
)

type stringCache struct {
	string1, string2 string //TODO the various strings will go here
}

type groupingCache struct {
	lower, upper *AddressSection

	// needs to go.  Cannot always know what etwork is, because we have no abstract types and we need concrete types for polymorphism
	//network AddressNetwork // never nil // equivalent to overriding getNetwork(), ToIPvX(), IsIPvxConvertible(), etc, in Java, allows you to supply your own conversion
}

type addrType string

const (
	zeroType addrType = ""     // no segments
	ipv4Type addrType = "IPv4" // ipv4 segments
	ipv6Type addrType = "IPv6" // ipv6 segments
	macType  addrType = "MAC"  // mac segments
)

var emptyBytes []byte = []byte{}

func (a addrType) isNil() bool {
	return a == zeroType
}

func (a addrType) isIPv4() bool {
	return a == ipv4Type
}

func (a addrType) isIPv6() bool {
	return a == ipv6Type
}

//// whether the prefix of each segment align with each other and the section as a whole
//func (a addrType) alignsPrefix() bool {
//	return a.isIP()
//}

func (a addrType) isIP() bool {
	return a.isIPv4() || a.isIPv6()
}

func (a addrType) isMAC() bool {
	return a == macType
}

type maskLenSetting struct {
	atomicFlag
	networkMaskLen, hostMaskLen PrefixLen
}

//type CreationLock struct {
//	created    atomicFlag // to check if created
//	createLock sync.Mutex // acquire to create
//}
//
//func (lock *CreationLock) isItemCreated() bool {
//	return lock.created.isSet()
//}
//
//func (lock *CreationLock) create(creator func()) (ret bool) {
//	lock.createLock.Lock()
//	if !lock.isItemCreated() {
//		creator()
//		ret = true
//		lock.created.set()
//	}
//	lock.createLock.Unlock()
//	return
//}

type valueCache struct {
	//	All writing done after locking the cacheLock.
	//	Reading can be done by using the read lock of the cachelock,
	//	or instead using a specific atomic flag covering a specific set of cache fields.
	cacheLock sync.RWMutex

	cachedCount, cachedPrefixCount big.Int // use BitLen() or len(x.Bits()) to check if value is set, or maybe check for 0
	//cachedPrefixLen                prefixLenSetting

	cachedMaskLens maskLenSetting

	lowerBytes, upperBytes []byte
	//isMultiple             boolSetting
	stringCache  stringCache
	sectionCache groupingCache
}

type addressDivisionGroupingInternal struct {
	// the non-cache elements are assigned at creation and are immutable
	divisions    []*AddressDivision
	prefixLength PrefixLen // must align with the divisions if they store prefix lengths
	isMultiple   bool

	// When a top-level section is created, it is assigned an address type, IPv4, IPv6, or MAC,
	// and determines if an *AddressDivisionGrouping can be converted back to a section of the original type.
	//
	// Type-specific functions in IPAddressSection and lower levels, such as functions returning strings,
	// can rely on this field.
	addrType addrType

	// The index of the containing address where this section starts, only used by IPv6 where we trach the "IPv4-embedded" part of an address section
	addressSegmentIndex uint8

	//TODO rename so you can ensure we always check for nil, which happens with  zero-groupings
	// assigned on creation only; for zero-value groupings it is never assigned, but in that case it is not needed, there is nothing to cache
	cache *valueCache
}

func createSegmentArray(length int) []*AddressDivision {
	return make([]*AddressDivision, length)
}

// IsMultiple returns whether this address or grouping represents more than one address or grouping.
// Such addresses include CIDR/IP addresses (eg 1.2.3.4/11) or wildcard addresses (eg 1.2.*.4) or range addresses (eg 1.2.3-4.5)
func (grouping *addressDivisionGroupingInternal) IsMultiple() bool {
	return grouping.isMultiple
	//cache := grouping.cache
	//if cache == nil {
	//	return false
	//}
	//cache.RLock()
	//isMult := cache.isMultiple
	//cache.RUnlock()
	//if isMult.isSet {
	//	return isMult.value
	//}
	//cache.Lock()
	//isMult = cache.isMultiple
	//if !isMult.isSet {
	//	//go in reverse order, with prefixes, multiple values are more likely to show up in last segment
	//	for i := grouping.GetDivisionCount() - 1; i >= 0; i-- {
	//		if div := grouping.getDivision(i); div.isMultiple() {
	//			cache.isMultiple.value = true
	//			isMult.value = true
	//			break
	//		}
	//	}
	//	cache.isMultiple.isSet = true
	//}
	//cache.Unlock()
	//return isMult.value
}

func (grouping addressDivisionGroupingInternal) GetBitCount() (res BitCount) {
	for i := 0; i < grouping.GetDivisionCount(); i++ {
		res += grouping.getDivision(i).GetBitCount()
	}
	return
}

func (grouping addressDivisionGroupingInternal) GetByteCount() BitCount {
	return (grouping.GetBitCount() + 7) >> 3
}

func (grouping addressDivisionGroupingInternal) String() string {
	return fmt.Sprintf("%v", grouping.divisions)
}

//// getPrefixLengthCacheLocked calculates prefix length
//// If a division D has a prefix length p, and all following division have prefix length 0,
//// and there are no earlier division with the same property, then division D determines the over-all prefix length
//// of the grouping.
//// In the case of IPv4/6 groupings, this property is enforced, so if a division has a non-zero prefix length,
//// then all preceding division must have nil prefix length and all following must have zero prefix length.
//func (grouping *addressDivisionGroupingInternal) getPrefixLengthCacheLocked() PrefixLen {
//	cache := grouping.cache
//	prefLen := cache.cachedPrefixLen
//	if !prefLen.isSet {
//		count := grouping.GetDivisionCount()
//		bitsSoFar, prefixBits := BitCount(0), BitCount(0)
//		hasPrefix := false
//		for i := 0; i < count; i++ {
//			div := grouping.getDivision(i)
//			divPrefLen := div.getDivisionPrefixLength() //TODO for MAC this needs to be changed to getMinPrefixLengthForBlock (optimize it to check for full range or single value first )
//			if hasPrefix = divPrefLen != nil; hasPrefix {
//				divPrefBits := *divPrefLen
//				if !hasPrefix || divPrefBits != 0 {
//					prefixBits = bitsSoFar + divPrefBits
//				}
//				if grouping.addrType.alignsPrefix() {
//					break
//				}
//			}
//			bitsSoFar += div.GetBitCount()
//		}
//		if hasPrefix {
//			res := &prefixBits
//			prefLen.value = res
//			cache.cachedPrefixLen.value = res
//		}
//		cache.cachedPrefixLen.isSet = true
//	}
//	return prefLen.value
//}

// IsMultiple returns whether this address or grouping represents more than one address or grouping.
// Such addresses include CIDR/IP addresses (eg 1.2.3.4/11) or wildcard addresses (eg 1.2.*.4) or range addresses (eg 1.2.3-4.5)
func (grouping *addressDivisionGroupingInternal) GetPrefixLength() PrefixLen {
	return grouping.prefixLength
}

//// prefixesAlign returns whether the prefix of each division align with each other, which is a requirement for IPv4/6
//// If an earlier division has a prefix, then all following division must have prefix 0
//func (grouping *addressDivisionGroupingInternal) prefixesAlign() bool {
//	count := grouping.GetDivisionCount()
//	for i := 0; i < count; i++ {
//		div := grouping.getDivision(i)
//		divPrefLen := div.getDivisionPrefixLength() //TODO for MAC this needs to be changed to getMinPrefixLengthForBlock (optimize it to check for full range or single value first )
//		if divPrefLen != nil {
//			for j := i + 1; j < count; j++ {
//				div = grouping.getDivision(j)
//				divPrefLen = div.getDivisionPrefixLength()
//				if divPrefLen == nil || *divPrefLen != 0 {
//					return false
//				}
//			}
//		}
//	}
//	return true
//}

// CopyBytes gets the value for the lowest address in the range represented by this address division grouping.
//
// If the value fits in the given slice, the same slice is returned with the value.
// Otherwise, a new slice is allocated and returned with the value.
//
// You can use GetBitCount() to determine the required array length for the bytes.
func (grouping *addressDivisionGroupingInternal) CopyBytes(bytes []byte) []byte {
	if grouping.hasNoDivisions() {
		if bytes != nil {
			return bytes
		}
		return emptyBytes
	}
	cached, _ := grouping.getBytesInternal()
	return getBytesCopy(bytes, cached)
}

func (grouping *addressDivisionGroupingInternal) GetBytes() []byte {
	if grouping.hasNoDivisions() {
		return emptyBytes
	}
	cached, _ := grouping.getBytesInternal()
	return append(make([]byte, 0, len(cached)), cached...)
}

func (grouping *addressDivisionGroupingInternal) CopyUpperBytes(bytes []byte) []byte {
	if grouping.hasNoDivisions() {
		if bytes != nil {
			return bytes
		}
		return emptyBytes
	}
	_, cached := grouping.getBytesInternal()
	return getBytesCopy(bytes, cached)
}

func (grouping *addressDivisionGroupingInternal) GetUpperBytes() []byte {
	if grouping.hasNoDivisions() {
		return emptyBytes
	}
	_, cached := grouping.getBytesInternal()
	return append(make([]byte, 0, len(cached)), cached...)
}

func (grouping *addressDivisionGroupingInternal) getBytesInternal() (bytes, upperBytes []byte) {
	cache := grouping.cache
	if cache == nil {
		return emptyBytes, emptyBytes
	}
	divisionCount := grouping.GetDivisionCount()
	cache.cacheLock.RLock()
	bytes, upperBytes = cache.lowerBytes, cache.upperBytes
	cache.cacheLock.RUnlock()
	if bytes != nil {
		return
	}
	addrType := grouping.addrType
	cache.cacheLock.Lock()
	bytes, upperBytes = cache.lowerBytes, cache.upperBytes
	if bytes == nil {
		if addrType.isIPv4() {
			bytes, upperBytes = make([]byte, divisionCount), make([]byte, divisionCount)
			for i := 0; i < divisionCount; i++ {
				seg := grouping.getDivision(i).ToAddressSegment()
				bytes[i], upperBytes[i] = byte(seg.GetSegmentValue()), byte(seg.GetUpperSegmentValue())
			}
		} else if addrType.isIPv6() {
			byteCount := divisionCount << 1
			bytes, upperBytes = make([]byte, byteCount), make([]byte, byteCount)
			for i := 0; i < divisionCount; i++ {
				seg := grouping.getDivision(i).ToAddressSegment()
				byteIndex := i << 1
				val, upperVal := seg.GetSegmentValue(), seg.GetUpperSegmentValue()
				bytes[byteIndex], upperBytes[byteIndex] = byte(val>>8), byte(upperVal>>8)
				nextByteIndex := byteIndex + 1
				bytes[nextByteIndex], upperBytes[nextByteIndex] = byte(val), byte(upperVal)
			}
		} else {
			byteCount := grouping.GetByteCount()
			for k, byteIndex, bitIndex := divisionCount-1, byteCount-1, BitCount(8); k >= 0; k-- {
				div := grouping.getDivision(k)
				val, upperVal := div.GetDivisionValue(), div.GetUpperDivisionValue()
				divBits := div.GetBitCount()
				for divBits > 0 {
					rbi := 8 - bitIndex
					bytes[byteIndex] |= byte(val << rbi)
					upperBytes[byteIndex] |= byte(upperVal << rbi)
					val >>= bitIndex
					upperVal >>= bitIndex
					if divBits < bitIndex {
						bitIndex -= divBits
						break
					} else {
						divBits -= bitIndex
						bitIndex = 8
						byteIndex--
					}
				}
			}
		}
		cache.lowerBytes, cache.upperBytes = bytes, upperBytes
	}
	cache.cacheLock.Unlock()
	return
}

// Returns whether the series represents a range of values that are sequential.
// Generally, this means that any division covering a range of values must be followed by divisions that are full range, covering all values.
func (grouping *addressDivisionGroupingInternal) IsSequential() bool {
	count := grouping.GetDivisionCount()
	if count > 1 {
		for i := 0; i < count; i++ {
			if grouping.getDivision(i).isMultiple() {
				for i++; i < count; i++ {
					if !grouping.getDivision(i).IsFullRange() {
						return false
					}
				}
				return true
			}
		}
	}
	return true
}

// hasNoDivisions() returns whether this grouping is the zero grouping,
// which is what you get when contructing a grouping or section with no divisions
func (grouping *addressDivisionGroupingInternal) hasNoDivisions() bool {
	return len(grouping.divisions) == 0
}

func (grouping *addressDivisionGroupingInternal) GetDivisionCount() int { //TODO make non-public so not exposed in IPv4/6/MAC
	return len(grouping.divisions)
}

// TODO think about the panic a bit more, do we want an error?  do slices panic with bad indices?  Could return nil instead

// getDivision returns the division or panics if the index is negative or it is too large
func (grouping *addressDivisionGroupingInternal) getDivision(index int) *AddressDivision { //TODO make non-public so not exposed in IPv4/6/MAC
	return grouping.divisions[index]
}

type AddressDivisionGrouping struct {
	addressDivisionGroupingInternal
}

// ToAddressSection converts to an address section.
// If the conversion cannot happen due to division size or count, the result will be the zero value.
func (grouping *AddressDivisionGrouping) ToAddressSection() *AddressSection {
	if grouping == nil {
		return nil
	}
	var bitCount BitCount
	for i, div := range grouping.divisions { // all divisions must be equal size and have an exact number of bytes
		if i == 0 {
			bitCount = div.GetBitCount()
			if bitCount%8 != 0 {
				return nil
			}
		} else if bitCount != div.GetBitCount() {
			return nil
		}
	}
	return (*AddressSection)(unsafe.Pointer(grouping))
}

func (grouping *AddressDivisionGrouping) ToIPAddressSection() *IPAddressSection {
	section := grouping.ToAddressSection()
	if section == nil {
		return nil
	}
	return section.ToIPAddressSection()
}

func (grouping *AddressDivisionGrouping) ToIPv6AddressSection() *IPv6AddressSection {
	section := grouping.ToIPAddressSection()
	if section == nil {
		return nil
	}
	return section.ToIPv6AddressSection()
}

func (grouping *AddressDivisionGrouping) ToIPv4AddressSection() *IPv4AddressSection {
	section := grouping.ToIPAddressSection()
	if section == nil {
		return nil
	}
	return section.ToIPv4AddressSection()
}

func (grouping *AddressDivisionGrouping) ToMACAddressSection() *MACAddressSection {
	section := grouping.ToAddressSection()
	if section == nil {
		return nil
	}
	return section.ToMACAddressSection()
}

func (grouping *AddressDivisionGrouping) GetDivision(index int) *AddressDivision {
	return grouping.getDivision(index)
}

func getBytesCopy(bytes, cached []byte) []byte {
	if bytes == nil || len(bytes) < len(cached) {
		return append(make([]byte, 0, len(cached)), cached...)
	}
	copy(bytes, cached)
	return bytes
}
