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

	// The index of the containing address where this section starts, only used by IPv6 where we trach the "IPv4-embedded" part of an address section
	addressSegmentIndex int8
}

func createSegmentArray(length int) []*AddressDivision {
	return make([]*AddressDivision, length)
}

// getDivision returns the division or panics if the index is negative or too large
func (grouping *addressDivisionGroupingInternal) getDivision(index int) *AddressDivision {
	divsArray := grouping.divisions
	if divsArray != nil {
		return divsArray.(standardDivArray).divisions[index]
	}
	panic("invalid index") // must be consistent with above code which panics with invalid index
}

// getDivision returns the divisions slice, only to be used internally
func (grouping *addressDivisionGroupingInternal) getDivisionsInternal() []*AddressDivision {
	divsArray := grouping.divisions
	if divsArray != nil {
		return divsArray.(standardDivArray).divisions
	}
	return nil
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
	if grouping == nil {
		return false
	}
	if grouping.matchesAddrSection() {
		return true
	}
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

func (grouping *addressDivisionGroupingInternal) IsMore(other AddressDivisionSeries) int { // the GetCount() is optimized which is why we do not defer to the method in addressDivisionGroupingBase
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
	return grouping.addressDivisionGroupingBase.GetCount()
}

func (grouping *addressDivisionGroupingInternal) GetPrefixCount() *big.Int {
	if section := grouping.toAddressSection(); section != nil {
		return section.GetPrefixCount()
	}
	return grouping.addressDivisionGroupingBase.GetPrefixCount()
}

func (grouping *addressDivisionGroupingInternal) GetPrefixCountLen(prefixLen BitCount) *big.Int {
	if section := grouping.toAddressSection(); section != nil {
		return section.GetPrefixCountLen(prefixLen)
	}
	return grouping.addressDivisionGroupingBase.GetPrefixCountLen(prefixLen)
}

func (grouping *addressDivisionGroupingInternal) toAddressDivisionGrouping() *AddressDivisionGrouping {
	return (*AddressDivisionGrouping)(unsafe.Pointer(grouping))
}

func (grouping *addressDivisionGroupingInternal) toAddressSection() *AddressSection {
	return grouping.toAddressDivisionGrouping().ToAddressSection()
}

func (grouping *addressDivisionGroupingInternal) matchesIPv6Address() bool {
	return grouping.getAddrType().isIPv6() // no need to check segment count because addresses cannot be constructed with incorrect segment count
}

func (grouping *addressDivisionGroupingInternal) matchesIPv4Address() bool {
	return grouping.getAddrType().isIPv4() // no need to check segment count because addresses cannot be constructed with incorrect segment count
}

func (grouping *addressDivisionGroupingInternal) matchesIPAddress() bool {
	return grouping.matchesIPSection() // no need to check segment count because addresses cannot be constructed with incorrect segment count (note the zero IPAddress has zero segments)
}

func (grouping *addressSectionInternal) matchesMACAddress() bool {
	return grouping.getAddrType().isMAC()
}

func (grouping *addressDivisionGroupingInternal) matchesAddrSection() bool {
	return !grouping.getAddrType().isNil() || grouping.hasNoDivisions()
}

func (grouping *addressDivisionGroupingInternal) matchesIPv6Section() bool {
	addrType := grouping.getAddrType()
	return addrType.isIPv6() || (addrType.isNil() && grouping.hasNoDivisions())
}

func (grouping *addressDivisionGroupingInternal) matchesIPv4Section() bool {
	addrType := grouping.getAddrType()
	return addrType.isIPv4() || (addrType.isNil() && grouping.hasNoDivisions())
}

func (grouping *addressDivisionGroupingInternal) matchesIPSection() bool {
	addrType := grouping.getAddrType()
	return addrType.isIP() || (addrType.isNil() && grouping.hasNoDivisions())
}

func (grouping *addressDivisionGroupingInternal) matchesMACSection() bool {
	addrType := grouping.getAddrType()
	return addrType.isMAC() || (addrType.isNil() && grouping.hasNoDivisions())
}

func (grouping *addressDivisionGroupingInternal) init() *addressDivisionGroupingInternal {
	if grouping.divisions == nil {
		return &zeroSection.addressDivisionGroupingInternal
	}
	return grouping
}

func (grouping addressDivisionGroupingInternal) String() string {
	if sect := grouping.toAddressSection(); sect != nil {
		return sect.ToNormalizedString()
	}
	return fmt.Sprintf("%v", grouping.init().divisions)
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
//			bitsSoFar += div.getBitCount()
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

func (grouping *addressDivisionGroupingInternal) GetPrefixLength() PrefixLen {
	return grouping.prefixLength
}

func (grouping *addressDivisionGroupingInternal) IsPrefixed() bool {
	return grouping.prefixLength != nil
}

//TODO eventually when supporting large divisions,
//might move containsPrefixBlock(prefixLen BitCount), containsSinglePrefixBlock(prefixLen BitCount),
// GetMinPrefixLengthForBlock, and GetPrefixLengthForSingleBlock into groupingBase code
// IsPrefixBlock, IsSinglePrefixBlock
// which looks straightforward since none deal with DivInt, instead they all call into divisionValues interface

func (grouping *addressDivisionGroupingInternal) ContainsPrefixBlock(prefixLen BitCount) bool {
	if section := grouping.toAddressSection(); section != nil {
		return section.ContainsPrefixBlock(prefixLen)
	}
	prefixLen = checkSubnet(grouping, prefixLen)
	divisionCount := grouping.GetDivisionCount()
	var prevBitCount BitCount
	for i := 0; i < divisionCount; i++ {
		division := grouping.getDivision(i)
		bitCount := division.GetBitCount()
		totalBitCount := bitCount + prevBitCount
		if prefixLen < totalBitCount {
			divPrefixLen := prefixLen - prevBitCount
			if !division.containsPrefixBlock(divPrefixLen) {
				return false
			}
			for i++; i < divisionCount; i++ {
				division = grouping.getDivision(i)
				if !division.IsFullRange() {
					return false
				}
			}
			return true
		}
		prevBitCount = totalBitCount
	}
	return true
}

func (grouping *addressDivisionGroupingInternal) ContainsSinglePrefixBlock(prefixLen BitCount) bool {
	prefixLen = checkSubnet(grouping, prefixLen)
	divisionCount := grouping.GetDivisionCount()
	var prevBitCount BitCount
	for i := 0; i < divisionCount; i++ {
		division := grouping.getDivision(i)
		bitCount := division.getBitCount()
		totalBitCount := bitCount + prevBitCount
		if prefixLen >= totalBitCount {
			if division.isMultiple() {
				return false
			}
		} else {
			divPrefixLen := prefixLen - prevBitCount
			if !division.ContainsSinglePrefixBlock(divPrefixLen) {
				return false
			}
			for i++; i < divisionCount; i++ {
				division = grouping.getDivision(i)
				if !division.IsFullRange() {
					return false
				}
			}
			return true
		}
		prevBitCount = totalBitCount
	}
	return true
}

func (grouping *addressDivisionGroupingInternal) IsSinglePrefixBlock() bool { //Note for any given prefix length you can compare with getPrefixLengthForSingleBlock
	prefLen := grouping.GetPrefixLength() //TODO cache this value
	return prefLen != nil && grouping.ContainsSinglePrefixBlock(*prefLen)
}

func (grouping *addressDivisionGroupingInternal) IsPrefixBlock() bool { //Note for any given prefix length you can compare with getMinPrefixLengthForBlock
	prefLen := grouping.GetPrefixLength() //TODO cache this value
	return prefLen != nil && grouping.ContainsPrefixBlock(*prefLen)
}

func (grouping *addressDivisionGroupingInternal) GetMinPrefixLengthForBlock() BitCount {
	// TODO  maybe we should cache this value, like we do in Java,
	// although not clear why cached in Java (maybe because it is hard to calculate)
	count := grouping.GetDivisionCount()
	totalPrefix := grouping.GetBitCount()
	for i := count - 1; i >= 0; i-- {
		div := grouping.getDivision(i)
		segBitCount := div.getBitCount()
		segPrefix := div.GetMinPrefixLengthForBlock()
		if segPrefix == segBitCount {
			break
		} else {
			totalPrefix -= segBitCount
			if segPrefix != 0 {
				totalPrefix += segPrefix
				break
			}
		}
	}
	return totalPrefix
}

func (grouping *addressDivisionGroupingInternal) GetPrefixLengthForSingleBlock() PrefixLen {
	count := grouping.GetDivisionCount()
	var totalPrefix BitCount
	for i := 0; i < count; i++ {
		div := grouping.getDivision(i)
		divPrefix := div.GetPrefixLengthForSingleBlock()
		if divPrefix == nil {
			return nil
		}
		divPrefLen := *divPrefix
		totalPrefix += divPrefLen
		if divPrefLen < div.GetBitCount() {
			//remaining segments must be full range or we return nil
			for i++; i < count; i++ {
				laterDiv := grouping.getDivision(i)
				if !laterDiv.IsFullRange() {
					return nil
				}
			}
		}
	}
	return cache(totalPrefix)
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

func (grouping *addressDivisionGroupingInternal) CompareTo(item AddressItem) int {
	return CountComparator.Compare(grouping, item)
}

func (grouping *addressDivisionGroupingInternal) GetBytes() []byte {
	if grouping.hasNoDivisions() {
		return emptyBytes
	}
	cached := grouping.getBytes()
	return cloneBytes(cached)
}

func (grouping *addressDivisionGroupingInternal) GetUpperBytes() []byte {
	if grouping.hasNoDivisions() {
		return emptyBytes
	}
	cached := grouping.getUpperBytes()
	return cloneBytes(cached)
}

// CopyBytes gets the value for the lowest address in the range represented by this address division grouping.
//
// If the value fits in the given slice, the same slice is returned with the value.
// Otherwise, a new slice is allocated and returned with the value.
//
// You can use getBitCount() to determine the required array length for the bytes.
func (grouping *addressDivisionGroupingInternal) CopyBytes(bytes []byte) []byte {
	if grouping.hasNoDivisions() {
		if bytes != nil {
			return bytes
		}
		return emptyBytes
	}
	return getBytesCopy(bytes, grouping.getBytes())
}

func (grouping *addressDivisionGroupingInternal) CopyUpperBytes(bytes []byte) []byte {
	if grouping.hasNoDivisions() {
		if bytes != nil {
			return bytes
		}
		return emptyBytes
	}
	return getBytesCopy(bytes, grouping.getUpperBytes())
}

func (grouping *addressDivisionGroupingInternal) getBytes() (bytes []byte) {
	bytes, _ = grouping.getCachedBytes(grouping.calcBytes)
	return
}

func (grouping *addressDivisionGroupingInternal) getUpperBytes() (bytes []byte) {
	_, bytes = grouping.getCachedBytes(grouping.calcBytes)
	return
}

func (grouping *addressDivisionGroupingInternal) calcBytes() (bytes, upperBytes []byte) {
	addrType := grouping.getAddrType()
	divisionCount := grouping.GetDivisionCount()
	isMultiple := grouping.IsMultiple()
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

func (grouping *addressDivisionGroupingInternal) Equals(other GenericGroupingType) bool {
	// For an identity comparison need to access the *addressDivisionGroupingBase or something
	//otherSection := other.to
	//if section.toAddressSection() == otherSection {
	//	return true
	//}
	matchesStructure, count := grouping.matchesStructure(other)
	if !matchesStructure || count != other.GetDivisionCount() {
		return false
	} else {
		for i := 0; i < count; i++ {
			one := grouping.getDivision(i)
			two := other.GetGenericDivision(i)
			if !one.Equals(two) { //this checks the division types and also the bit counts
				return false
			}
		}
	}
	return true
}

type AddressDivisionGrouping struct {
	addressDivisionGroupingInternal
}

//func (grouping *AddressDivisionGrouping) ContainsPrefixBlock(prefixLen BitCount) bool {
//	return grouping.containsPrefixBlock(prefixLen)
//}

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
