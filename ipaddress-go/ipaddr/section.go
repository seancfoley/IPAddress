package ipaddr

import (
	"unsafe"
)

//////////////////////////////////////////////////////////////////
//
//
//
type addressSectionInternal struct {
	addressDivisionGroupingInternal
}

func (section *addressSectionInternal) toAddressSection() *AddressSection {
	return (*AddressSection)(unsafe.Pointer(section))
}

func (section *addressSectionInternal) GetBitsPerSegment() BitCount {
	if section.GetDivisionCount() == 0 {
		return 0
	}
	return section.GetDivision(0).GetBitCount()
}

func (section *addressSectionInternal) GetBytesPerSegment() int {
	if section.GetDivisionCount() == 0 {
		return 0
	}
	return section.GetDivision(0).GetByteCount()
}

func (section *addressSectionInternal) GetSegment(index int) *AddressSegment {
	return section.GetDivision(index).ToAddressSegment()
}

//func (section *addressSectionInternal) GetSegmentX(index int) AddressSegmentX {
//	return section.GetDivision(index).ToAddressSegmentX()
//}

func (section *addressSectionInternal) GetSegmentCount() int {
	return section.GetDivisionCount()
}

func (section *addressSectionInternal) GetBitCount() BitCount {
	divLen := len(section.divisions)
	if divLen == 0 {
		return 0
	}
	return section.GetDivision(0).GetBitCount() * BitCount(section.GetSegmentCount())
}

func (section *addressSectionInternal) GetByteCount() int {
	return int((section.GetBitCount() + 7) >> 3)
}

//func (section *addressSectionInternal) ToPrefixBlock() *AddressSection {
//	xxx
//	//TODO ToPrefixBlock
//	return nil
//}

//func (section *addressSectionInternal) toPrefixBlockLen(prefLen BitCount) *AddressSection {
//	xxxxx
//	bitCount := section.GetBitCount()
//	if prefLen < 0 {
//		prefLen = 0
//	} else {
//		if prefLen > bitCount {
//			prefLen = bitCount
//		}
//	}
//	segCount := section.GetSegmentCount()
//	if segCount == 0 {
//		return section.toAddressSection()
//	}
//	segmentByteCount := section.GetBytesPerSegment()
//	segmentBitCount := section.GetBitsPerSegment()
//	prefixedSegmentIndex := getHostSegmentIndex(prefLen, segmentByteCount, segmentBitCount)
//	if prefixedSegmentIndex >= segCount {
//		if prefLen == bitCount {
//			last := section.GetSegment(segCount - 1).ToIPAddressSegment()
//			segPrefLength := last.GetSegmentPrefixLength()
//			if segPrefLength != nil && *segPrefLength == segmentBitCount {
//				return section.toAddressSection()
//			}
//		} else { // prefLen > bitCount
//			return section.toAddressSection()
//		}
//	} else {
//		segPrefLength := *getPrefixedSegmentPrefixLength(segmentBitCount, prefLen, prefixedSegmentIndex)
//		seg := section.GetSegment(prefixedSegmentIndex).ToIPAddressSegment()
//		segPref := seg.GetSegmentPrefixLength()
//		if segPref != nil && *segPref == segPrefLength && seg.ContainsPrefixBlock(segPrefLength) {
//			i := prefixedSegmentIndex + 1
//			for ; i < segCount; i++ {
//				seg = section.GetSegment(i).ToIPAddressSegment()
//				if !seg.IsFullRange() {
//					break
//				}
//			}
//			if i == segCount {
//				return section.toAddressSection()
//			}
//		}
//	}
//	newSegs := createSegmentArray(segCount)
//	if prefLen > 0 {
//		prefixedSegmentIndex = getNetworkSegmentIndex(prefLen, segmentByteCount, segmentBitCount)
//		copy(newSegs, section.divisions[:prefixedSegmentIndex])
//	} else {
//		prefixedSegmentIndex = 0
//	}
//	for i := prefixedSegmentIndex; i < segCount; i++ {
//		segPrefLength := getPrefixedSegmentPrefixLength(segmentBitCount, prefLen, i)
//		oldSeg := section.divisions[i]
//		newSegs[i] = oldSeg.ToIPAddressSegment().ToPrefixedNetworkSegment(segPrefLength).ToAddressDivision()
//	}
//	return createIPSection(newSegs, &prefLen, section.addrType, section.addressSegmentIndex, section.isMultiple || prefLen < bitCount)
//}

//func (section *addressSectionInternal) matchesSection(segmentCount int, segmentBitCount BitCount) bool {
//	divLen := len(section.divisions)
//	return divLen <= segmentCount && (divLen == 0 || section.GetDivision(0).GetBitCount() == segmentBitCount)
//}
//
//func (section *addressSectionInternal) matchesAddress(segmentCount int, segmentBitCount BitCount) bool {
//	return len(section.divisions) == segmentCount && section.GetDivision(0).GetBitCount() == segmentBitCount
//}

//func (section *addressSectionInternal) matchesIPv6Section() bool {
//	//xxxx all the cache access must check for nil first, all cache access must go through methods xxx
//	cache := section.cache
//	return cache == nil || cache.addrType.isIPv6()
//	//|| (cache.addrType.isNil() &&
//	//		section.matchesSection(IPv6SegmentCount, IPv6BitsPerSegment) && section.prefixesAlign())
//}
//
//func (section *addressSectionInternal) matchesIPv4Section() bool {
//	cache := section.cache
//	return cache == nil || cache.addrType.isIPv4() ||
//		(cache.addrType.isNil() &&
//			section.matchesSection(IPv4SegmentCount, IPv4BitsPerSegment) && section.prefixesAlign())
//}
//
//func (section *addressSectionInternal) matchesIPSection() bool {
//	cache := section.cache
//	return cache == nil || cache.addrType.isIP() ||
//		(cache.addrType.isNil() &&
//			(section.matchesSection(IPv4SegmentCount, IPv4BitsPerSegment) || section.matchesSection(IPv6SegmentCount, IPv6BitsPerSegment)) &&
//			section.prefixesAlign())
//}

func (section *addressSectionInternal) matchesIPv6Section() bool {
	//xxxx all the cache access must check for nil first, all cache access must go through methods xxx
	//cache := section.cache
	return section.addrType.isIPv6() || section.addrType.isNil()
	//|| (cache.addrType.isNil() &&
	//		section.matchesSection(IPv6SegmentCount, IPv6BitsPerSegment) && section.prefixesAlign())
}

func (section *addressSectionInternal) matchesIPv4Section() bool {
	return section.addrType.isIPv4() || section.addrType.isNil()
}

func (section *addressSectionInternal) matchesIPSection() bool {
	return section.addrType.isIP() || section.addrType.isNil()
}

func (section *addressSectionInternal) matchesMACSection() bool {
	return section.addrType.isMAC() || section.addrType.isNil()
}

func (section *addressSectionInternal) matchesIPv6Address() bool {
	return section.addrType.isIPv6() && section.GetSegmentCount() == IPv6SegmentCount
}

func (section *addressSectionInternal) matchesIPv4Address() bool {
	return section.addrType.isIPv4() && section.GetSegmentCount() == IPv4SegmentCount
}

func (section *addressSectionInternal) matchesMACAddress() bool {
	segCount := section.GetSegmentCount()
	return section.addrType.isMAC() &&
		(segCount == MediaAccessControlSegmentCount || segCount == ExtendedUniqueIdentifier64SegmentCount)
}

//func (section *addressSectionInternal) getAddrType() addrType {
//	cache := section.cache
//	if cache != nil {
//		xxx
//		//TODO locking
//		if cache.addrType.isIPv4() {
//			return ipv4AddrType
//		} else if cache.addrType.isIPv6() {
//			return ipv6AddrType
//		}
//		divLen := section.GetDivisionCount()
//		if divLen > 0 {
//			bc := section.GetDivision(0).GetBitCount()
//			if bc == IPv4BitsPerSegment {
//				return ipv4AddrType
//			} else if bc == IPv6BitsPerSegment {
//				return ipv6AddrType
//			}
//		}
//	}
//	return noAddrType
//}

func (section *addressSectionInternal) ToAddressDivisionGrouping() *AddressDivisionGrouping {
	return (*AddressDivisionGrouping)(unsafe.Pointer(section))
}

func createSection(segments []*AddressDivision, prefixLength PrefixLen, addrType addrType, startIndex uint8, isMultiple bool) *AddressSection {
	return &AddressSection{
		addressSectionInternal{
			addressDivisionGroupingInternal{
				divisions:           segments,
				prefixLength:        prefixLength,
				addrType:            addrType,
				addressSegmentIndex: startIndex,
				isMultiple:          isMultiple,
				cache:               &valueCache{},
			},
		},
	}
}

//
//
//
//
type AddressSection struct {
	addressSectionInternal
}

//func (section *AddressSection) String() string {
//	return section.addressSectionInternal.String()
//}

func (section *AddressSection) getLowestOrHighestSection(lowest bool) (result *AddressSection) {
	if !section.IsMultiple() {
		return section
	}
	cache := section.cache
	sectionCache := &cache.sectionCache
	cache.RLock()
	if lowest {
		result = sectionCache.lower
	} else {
		result = sectionCache.upper
	}
	cache.RUnlock()
	if result != nil {
		return
	}
	cache.Lock()
	if lowest {
		result = sectionCache.lower
		if result == nil {
			result = section.createLowestOrHighestSectionCacheLocked(lowest)
			sectionCache.lower = result
		}
	} else {
		result = sectionCache.upper
		if result == nil {
			result = section.createLowestOrHighestSectionCacheLocked(lowest)
			sectionCache.upper = result
		}
	}
	cache.Unlock()
	return
}

func (section *AddressSection) createLowestOrHighestSectionCacheLocked(lowest bool) *AddressSection {
	segmentCount := section.GetSegmentCount()
	segs := createSegmentArray(segmentCount)
	if lowest {
		for i := 0; i < segmentCount; i++ {
			segs[i] = section.GetSegment(i).GetLower().ToAddressDivision()
		}
	} else {
		for i := 0; i < segmentCount; i++ {
			segs[i] = section.GetSegment(i).GetUpper().ToAddressDivision()
		}
	}
	return createSection(segs, section.prefixLength, section.addrType, section.addressSegmentIndex, false)
}

func (section *AddressSection) GetLower() *AddressSection {
	return section.getLowestOrHighestSection(true)
}

func (section *AddressSection) GetUpper() *AddressSection {
	return section.getLowestOrHighestSection(false)
}

func (section *AddressSection) ToPrefixBlock() *AddressSection {
	prefixLength := section.GetPrefixLength()
	if prefixLength == nil {
		return section
	}
	return section.toPrefixBlockLen(*prefixLength)
}

func (section *AddressSection) toPrefixBlockLen(prefLen BitCount) *AddressSection {
	bitCount := section.GetBitCount()
	if prefLen < 0 {
		prefLen = 0
	} else {
		if prefLen > bitCount {
			prefLen = bitCount
		}
	}
	segCount := section.GetSegmentCount()
	if segCount == 0 {
		return section
	}
	segmentByteCount := section.GetBytesPerSegment()
	segmentBitCount := section.GetBitsPerSegment()
	existingPrefixLength := section.GetPrefixLength()
	prefixMatches := existingPrefixLength != nil && *existingPrefixLength == prefLen
	if prefixMatches {
		prefixedSegmentIndex := getHostSegmentIndex(prefLen, segmentByteCount, segmentBitCount)
		if prefixedSegmentIndex >= segCount {
			return section
		}
		segPrefLength := *getPrefixedSegmentPrefixLength(segmentBitCount, prefLen, prefixedSegmentIndex)
		seg := section.GetSegment(prefixedSegmentIndex)
		if seg.containsPrefixBlock(segPrefLength) {
			i := prefixedSegmentIndex + 1
			for ; i < segCount; i++ {
				seg = section.GetSegment(i)
				if !seg.IsFullRange() {
					break
				}
			}
			if i == segCount {
				return section
			}
		}
	}
	prefixedSegmentIndex := 0
	newSegs := createSegmentArray(segCount)
	if prefLen > 0 {
		prefixedSegmentIndex = getNetworkSegmentIndex(prefLen, segmentByteCount, segmentBitCount)
		copy(newSegs, section.divisions[:prefixedSegmentIndex])
	}
	for i := prefixedSegmentIndex; i < segCount; i++ {
		segPrefLength := getPrefixedSegmentPrefixLength(segmentBitCount, prefLen, i)
		oldSeg := section.divisions[i]
		newSegs[i] = oldSeg.toPrefixedNetworkDivision(segPrefLength)
	}
	//TODO caching of prefLen?  we should map it to a global array - check what we have in the validation code
	return createSection(newSegs, &prefLen, section.addrType, section.addressSegmentIndex, section.isMultiple || prefLen < bitCount)
}

//func (section *AddressSection) toPrefixBlockLen(prefLen BitCount) *AddressSection {
//	bitCount := section.GetBitCount()
//	if prefLen < 0 {
//		prefLen = 0
//	} else {
//		if prefLen > bitCount {
//			prefLen = bitCount
//		}
//	}
//	segCount := section.GetSegmentCount()
//	if segCount == 0 {
//		return section
//	}
//
//	segmentByteCount := section.GetBytesPerSegment()
//	segmentBitCount := section.GetBitsPerSegment()
//	prefixedSegmentIndex := getHostSegmentIndex(prefLen, segmentByteCount, segmentBitCount)
//	if prefixedSegmentIndex >= segCount {
//		if prefLen == bitCount {
//			last := section.GetSegment(segCount - 1)
//			existingPrefLength := last.getSegmentPrefixLength()
//			if existingPrefLength != nil && *existingPrefLength == segmentBitCount {
//				return section
//			}
//		} else { // prefLen > bitCount
//			return section
//		}
//	} else {
//		segPrefLength := *getPrefixedSegmentPrefixLength(segmentBitCount, prefLen, prefixedSegmentIndex)
//
//		seg := section.GetSegment(prefixedSegmentIndex)
//		existingPrefLength := seg.GetSegmentPrefixLength()
//
//		//mostly it is this containsPrefixBlock we care about - we could also compare the prefix in one fell swoop, not per segment
//
//		if existingPrefLength != nil && *existingPrefLength == segPrefLength && seg.containsPrefixBlock(segPrefLength) {
//			i := prefixedSegmentIndex + 1
//			for ; i < segCount; i++ {
//				seg = section.GetSegment(i)
//				if !seg.IsFullRange() {
//					break
//				}
//			}
//			if i == segCount {
//				return section
//			}
//		}
//	}
//	newSegs := createSegmentArray(segCount)
//	if prefLen > 0 {
//		prefixedSegmentIndex = getNetworkSegmentIndex(prefLen, segmentByteCount, segmentBitCount)
//		copy(newSegs, section.divisions[:prefixedSegmentIndex])
//	} else {
//		prefixedSegmentIndex = 0
//	}
//	for i := prefixedSegmentIndex; i < segCount; i++ {
//		segPrefLength := getPrefixedSegmentPrefixLength(segmentBitCount, prefLen, i)
//		oldSeg := section.divisions[i]
//		newSegs[i] = oldSeg.toPrefixedNetworkDivision(segPrefLength)
//	}
//	//TODO caching of prefLen?  we should map it to a global array - check what we have in the validation code
//	return createSection(newSegs, &prefLen, section.addrType, section.addressSegmentIndex, section.isMultiple || prefLen < bitCount)
//}

func (section *AddressSection) ToIPAddressSection() *IPAddressSection {
	if section == nil || !section.matchesIPSection() {
		return nil
	}
	//cache := section.cache
	//xxx
	//cache.addrType = section.getAddrType()
	return (*IPAddressSection)(unsafe.Pointer(section))
}

func (section *AddressSection) ToIPv6AddressSection() *IPv6AddressSection {
	if section == nil || !section.matchesIPv6Section() {
		return nil
	}
	//cache := section.cache
	//if cache != nil {
	//	xxx
	//	cache.addrType = ipv6AddrType
	//}
	return (*IPv6AddressSection)(unsafe.Pointer(section))
}

func (section *AddressSection) ToIPv4AddressSection() *IPv4AddressSection {
	if section == nil || !section.matchesIPv4Section() {
		return nil
	}
	//cache := section.cache
	//if cache != nil {
	//	xxx
	//	cache.addrType = ipv4AddrType
	//}
	return (*IPv4AddressSection)(unsafe.Pointer(section))
}

func (section *AddressSection) ToMACAddressSection() *MACAddressSection {
	if section == nil || !section.matchesMACSection() {
		return nil
	}
	//cache := section.cache
	//if cache != nil {
	//	xxx
	//	cache.addrType = macAddrType
	//}
	return (*MACAddressSection)(unsafe.Pointer(section))
}
