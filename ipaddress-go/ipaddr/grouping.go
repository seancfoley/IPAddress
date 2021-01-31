package ipaddr

import (
	"fmt"
	"math/big"
	"unsafe"
)

var (
	emptyBytes = []byte{}
)

type addressDivisionGroupingInternal struct {
	addressDivisionGroupingBase

	// When a top-level section is created, it is assigned an address type, IPv4, IPv6, or MAC,
	// and determines if an *AddressDivisionGrouping can be converted back to a section of the original type.
	//
	// Type-specific functions in IPAddressSection and lower levels, such as functions returning strings,
	// can rely on this field.
	addrType addrType

	// The index of the containing address where this section starts, only used by IPv6 where we trach the "IPv4-embedded" part of an address section
	addressSegmentIndex uint8
}

func createSegmentArray(length int) []*AddressDivision {
	return make([]*AddressDivision, length)
}

// getDivision returns the division or panics if the index is negative or too large
func (grouping *addressDivisionGroupingInternal) getDivision(index int) *AddressDivision {
	return grouping.addressDivisionGroupingBase.getDivision(index).toAddressDivision()
}

// copySubDivisions copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (grouping *addressDivisionGroupingInternal) copySubDivisions(start, end int, divs []*AddressDivision) (count int) {
	divsArray := grouping.divisions
	if divsArray != nil {
		return divsArray.(standardDivArray).copySubDivisions(start, end, divs)
	}
	return
}

// copyDivisions copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (grouping *addressDivisionGroupingInternal) copyDivisions(divs []*AddressDivision) (count int) {
	divsArray := grouping.divisions
	if divsArray != nil {
		return divsArray.(standardDivArray).copyDivisions(divs)
	}
	return
}

func (grouping *addressDivisionGroupingInternal) isAddressSection() bool {
	var bitCount BitCount
	count := grouping.GetDivisionCount()
	// all divisions must be equal size and have an exact number of bytes
	for i := 0; i < count; i++ {
		div := grouping.getDivision(i)
		if i == 0 {
			bitCount = div.GetBitCount()
			if bitCount%8 != 0 || bitCount > SegIntSize {
				return false
			}
		} else if bitCount != div.GetBitCount() {
			return false
		}
	}
	return true
}

func (grouping *addressDivisionGroupingBase) isMore(other *AddressDivisionGrouping) int {
	if !grouping.IsMultiple() {
		if other.IsMultiple() {
			return -1
		}
		return 0
	}
	if !other.IsMultiple() {
		return 1
	}
	return grouping.GetCount().CmpAbs(other.GetCount())
}

func (grouping *addressDivisionGroupingInternal) GetCount() *big.Int {
	if !grouping.IsMultiple() {
		return bigOne()
	} else if section := grouping.toAddressSection(); section != nil {
		return section.GetCount()
	}
	return grouping.cacheCount(grouping.getBigCount)
}

func (grouping *addressDivisionGroupingInternal) toAddressDivisionGrouping() *AddressDivisionGrouping {
	return (*AddressDivisionGrouping)(unsafe.Pointer(grouping))
}

func (grouping *addressDivisionGroupingInternal) toAddressSection() *AddressSection {
	return grouping.toAddressDivisionGrouping().ToAddressSection()
}

func (section *addressDivisionGroupingInternal) matchesIPv6Address() bool {
	return section.addrType.isIPv6() // no need to check segment count because addresses cannot be constructed with incorrect segment count
}

func (section *addressDivisionGroupingInternal) matchesIPv4Address() bool {
	return section.addrType.isIPv4() // no need to check segment count because addresses cannot be constructed with incorrect segment count
}

func (section *addressDivisionGroupingInternal) matchesIPv6Section() bool {
	return section.addrType.isIPv6() || (section.addrType.isNil() && section.hasNoDivisions())
}

func (section *addressDivisionGroupingInternal) matchesIPv4Section() bool {
	return section.addrType.isIPv4() || (section.addrType.isNil() && section.hasNoDivisions())
}

func (section *addressDivisionGroupingInternal) matchesIPSection() bool {
	return section.addrType.isIP() || (section.addrType.isNil() && section.hasNoDivisions())
}

func (section *addressDivisionGroupingInternal) matchesIPAddress() bool {
	return section.matchesIPSection() // no need to check segment count because addresses cannot be constructed with incorrect segment count
}

func (section *addressDivisionGroupingInternal) matchesMACSection() bool {
	return section.addrType.isMAC() || (section.addrType.isNil() && section.hasNoDivisions())
}

func (section *addressSectionInternal) matchesMACAddress() bool {
	return section.addrType.isMAC()
	//segCount := section.GetSegmentCount()
	//return section.addrType.isMAC() &&
	//	(segCount == MediaAccessControlSegmentCount || segCount == ExtendedUniqueIdentifier64SegmentCount)
}

//func (grouping addressDivisionGroupingInternal) matchesIPv6Address() bool {
//	return grouping.addrType.isIPv6() && grouping.GetDivisionCount() == IPv6SegmentCount
//}
//
//func (grouping addressDivisionGroupingInternal) matchesIPv4Address() bool {
//	return grouping.addrType.isIPv4() && grouping.GetDivisionCount() == IPv4SegmentCount
//}

//func (grouping addressDivisionGroupingInternal) matchesMACAddress() bool {
//	segCount := grouping.GetDivisionCount()
//	return grouping.addrType.isMAC() &&
//		(segCount == MediaAccessControlSegmentCount || segCount == ExtendedUniqueIdentifier64SegmentCount)
//}

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
//		count := grouping.getDivisionCount()
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
//	count := grouping.getDivisionCount()
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

func (grouping *addressDivisionGroupingInternal) GetValue() *big.Int {
	if grouping.hasNoDivisions() {
		return bigZero()
	}
	return bigZero().SetBytes(grouping.getBytes())
}

func (grouping *addressDivisionGroupingInternal) GetUpperValue() *big.Int {
	if grouping.hasNoDivisions() {
		return bigZero()
	}
	return bigZero().SetBytes(grouping.getUpperBytes())
}

func (grouping *addressDivisionGroupingInternal) GetBytes() []byte {
	if grouping.hasNoDivisions() {
		return emptyBytes
	}
	cached := grouping.getBytes()
	return append(make([]byte, 0, len(cached)), cached...)
}

func (grouping *addressDivisionGroupingInternal) GetUpperBytes() []byte {
	if grouping.hasNoDivisions() {
		return emptyBytes
	}
	cached := grouping.getUpperBytes()
	return append(make([]byte, 0, len(cached)), cached...)
}

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
	cached := grouping.getBytes()
	return getBytesCopy(bytes, cached)
}

func (grouping *addressDivisionGroupingInternal) CopyUpperBytes(bytes []byte) []byte {
	if grouping.hasNoDivisions() {
		if bytes != nil {
			return bytes
		}
		return emptyBytes
	}
	cached := grouping.getUpperBytes()
	return getBytesCopy(bytes, cached)
}

func (grouping *addressDivisionGroupingInternal) getBytes() (bytes []byte) {
	bytes, _ = grouping.getBytesInternal()
	return
}

func (grouping *addressDivisionGroupingInternal) getUpperBytes() (bytes []byte) {
	_, bytes = grouping.getBytesInternal()
	return
}

func (grouping *addressDivisionGroupingInternal) getBytesInternal() (bytes, upperBytes []byte) {
	isMultiple := grouping.IsMultiple()
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
		if addrType.isIPv4() || addrType.isMAC() {
			bytes = make([]byte, divisionCount)
			if isMultiple {
				upperBytes = make([]byte, divisionCount)
			} else {
				upperBytes = bytes
			}
			for i := 0; i < divisionCount; i++ {
				seg := grouping.getDivision(i).ToAddressSegment()
				bytes[i] = byte(seg.GetSegmentValue())
				if isMultiple {
					upperBytes[i] = byte(seg.GetUpperSegmentValue())
				}
			}
		} else if addrType.isIPv6() {
			byteCount := divisionCount << 1
			bytes = make([]byte, byteCount)
			if isMultiple {
				upperBytes = make([]byte, byteCount)
			} else {
				upperBytes = bytes
			}
			for i := 0; i < divisionCount; i++ {
				seg := grouping.getDivision(i).ToAddressSegment()
				byteIndex := i << 1
				val := seg.GetSegmentValue()
				bytes[byteIndex] = byte(val >> 8)
				var upperVal SegInt
				if isMultiple {
					upperVal = seg.GetUpperSegmentValue()
					upperBytes[byteIndex] = byte(upperVal >> 8)
				}
				nextByteIndex := byteIndex + 1
				bytes[nextByteIndex] = byte(val)
				if isMultiple {
					upperBytes[nextByteIndex] = byte(upperVal)
				}
			}
		} else {
			byteCount := grouping.GetByteCount()
			bytes = make([]byte, byteCount)
			if isMultiple {
				upperBytes = make([]byte, byteCount)
			} else {
				upperBytes = bytes
			}
			for k, byteIndex, bitIndex := divisionCount-1, byteCount-1, BitCount(8); k >= 0; k-- {
				div := grouping.getDivision(k)
				val := div.GetDivisionValue()
				var upperVal DivInt
				if isMultiple {
					upperVal = div.GetUpperDivisionValue()
				}
				divBits := div.GetBitCount()
				for divBits > 0 {
					rbi := 8 - bitIndex
					bytes[byteIndex] |= byte(val << rbi)
					val >>= bitIndex
					if isMultiple {
						upperBytes[byteIndex] |= byte(upperVal << rbi)
						upperVal >>= bitIndex
					}
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
			if grouping.getDivision(i).IsMultiple() {
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

//
//func (grouping *addressDivisionGroupingInternal) GetDivision(index int) *AddressDivision {
//	return grouping.getDivision(index)
//}
//
//func (grouping *addressDivisionGroupingInternal) GetDivisionCount() int {
//	return grouping.getDivisionCount()
//}

type AddressDivisionGrouping struct {
	addressDivisionGroupingInternal
}

// copySubDivisions copies the existing divisions from the given start index until but not including the division at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (grouping *AddressDivisionGrouping) CopySubDivisions(start, end int, divs []*AddressDivision) (count int) {
	return grouping.copySubDivisions(start, end, divs)
}

// CopyDivisions copies the existing divisions from the given start index until but not including the division at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (grouping *AddressDivisionGrouping) CopyDivisions(divs []*AddressDivision) (count int) {
	return grouping.copyDivisions(divs)
}

func (grouping *AddressDivisionGrouping) IsAddressSection() bool {
	return grouping != nil && grouping.isAddressSection()
}

func (grouping *AddressDivisionGrouping) IsIPAddressSection() bool {
	return grouping.ToAddressSection().IsIPAddressSection()
}

func (grouping *AddressDivisionGrouping) IsIPv4AddressSection() bool {
	return grouping.ToAddressSection().IsIPv4AddressSection()
}

func (grouping *AddressDivisionGrouping) IsIPv6AddressSection() bool {
	return grouping.ToAddressSection().IsIPv6AddressSection()
}

func (grouping *AddressDivisionGrouping) IsMACAddressSection() bool {
	return grouping.ToAddressSection().IsMACAddressSection()
}

// ToAddressSection converts to an address section.
// If the conversion cannot happen due to division size or count, the result will be the zero value.
func (grouping *AddressDivisionGrouping) ToAddressSection() *AddressSection {
	if grouping == nil || !grouping.isAddressSection() {
		return nil
	}
	return (*AddressSection)(unsafe.Pointer(grouping))
}

func (grouping *AddressDivisionGrouping) ToIPAddressSection() *IPAddressSection {
	return grouping.ToAddressSection().ToIPAddressSection()
}

func (grouping *AddressDivisionGrouping) ToIPv6AddressSection() *IPv6AddressSection {
	return grouping.ToAddressSection().ToIPv6AddressSection()
}

func (grouping *AddressDivisionGrouping) ToIPv4AddressSection() *IPv4AddressSection {
	return grouping.ToAddressSection().ToIPv4AddressSection()
}

func (grouping *AddressDivisionGrouping) ToMACAddressSection() *MACAddressSection {
	return grouping.ToAddressSection().ToMACAddressSection()
}

func (grouping *AddressDivisionGrouping) ToAddressDivisionGrouping() *AddressDivisionGrouping {
	return grouping
}

func (grouping *AddressDivisionGrouping) GetDivision(index int) *AddressDivision {
	return grouping.getDivision(index)
}

//func (grouping *AddressDivisionGrouping) GetGenericDivision(index int) AddressGenericDivision {
//	return grouping.getDivision(index)
//}
//
//func (grouping *AddressDivisionGrouping) GetDivisionCount() int {
//	xxx
//	return grouping.getDivisionCount()
//}

func (grouping *AddressDivisionGrouping) IsMore(other *AddressDivisionGrouping) int {
	return grouping.isMore(other)
}

type addrType string

const (
	zeroType addrType = ""     // no segments
	ipv4Type addrType = "IPv4" // ipv4 segments
	ipv6Type addrType = "IPv6" // ipv6 segments
	macType  addrType = "MAC"  // mac segments
)

func (a addrType) isNil() bool {
	return a == zeroType
}

func (a addrType) isIPv4() bool {
	return a == ipv4Type
}

func (a addrType) isIPv6() bool {
	return a == ipv6Type
}

func (a addrType) isIP() bool {
	return a.isIPv4() || a.isIPv6()
}

func (a addrType) isMAC() bool {
	return a == macType
}

func getBytesCopy(bytes, cached []byte) []byte {
	if bytes == nil || len(bytes) < len(cached) {
		return append(make([]byte, 0, len(cached)), cached...)
	}
	copy(bytes, cached)
	return bytes
}
