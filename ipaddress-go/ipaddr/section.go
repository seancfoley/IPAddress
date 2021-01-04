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

func (section *addressSectionInternal) ToPrefixBlock() *AddressSection {
	//TODO ToPrefixBlock
	return nil
}

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
	cache.RLock()
	if lowest {
		result = cache.sectionCache.lower
	} else {
		result = cache.sectionCache.upper
	}
	cache.RUnlock()
	if result != nil {
		return
	}
	cache.Lock()
	if lowest {
		result = cache.sectionCache.lower
	} else {
		result = cache.sectionCache.upper
	}
	if result == nil {
		//var segProducer func(int) *addressDivisionInternal
		//if lowest {
		//	segProducer = func(i int) *addressDivisionInternal { return section.GetSegment(i).GetLower() }
		//} else {
		//	segProducer = func(i int) *addressDivisionInternal { return section.GetSegment(i).GetUpper() }
		//}

		//TODO TODO TODO here here here shows how I got here, I need to get back to ipv6 address creation in parsedipaddress
		//xxxx I should probably get rid of the network , you cannot assume you know which version or type, and thus it cannot be assigned or used xxxx
		//xxxx I wanted that for doing ipv4/6 conversion - need a better way (creating your own types is not so useful anyway)
		//	maybe just supply a converter?
		//And we were thinking about conversion becquse of the ToIpv6 method
		//But also we had a method with IPAddress in signature for SpanWithRange
		//xxxx I also need to think about the prefix alignment issue after all this resolved
		//Back to the issue of conversion -
		//	Maybe we allow all kinds
		//Or maybe none at all
		//Maybe the behind the scenes conversion needs to go
		//Maybe you keep network but not to use the creators!
		//	Yes!
		//	Certainly do not use the creators
		//I think it should not be the network object
		//But still, you store a converter for a single conversion?  naw
		//it makes no sense

		result = section.createLowestOrHighestSectionCacheLocked(
			//section.cache.sectionCache.network.GetAddressCreator().(IPAddressCreator),
			//segProducer,
			lowest)
	}
	cache.Unlock()

	return
}

func (section *AddressSection) createLowestOrHighestSectionCacheLocked(
	//creator IPAddressCreator,
	//segProducer func(int) *addressDivisionInternal,
	lowest bool) (result *AddressSection) {

	segmentCount := section.GetSegmentCount()
	segs := createSegmentArray(segmentCount)
	for i := 0; i < segmentCount; i++ {
		if lowest {
			segs[i] = section.GetSegment(i).GetLower().ToAddressDivision()
		} else {
			segs[i] = section.GetSegment(i).GetUpper().ToAddressDivision()
		}
	}
	result = &AddressSection{addressSectionInternal{addressDivisionGroupingInternal{
		divisions:    segs,
		prefixLength: section.prefixLength,
		cache:        &valueCache{},
		addrType:     section.addrType,
	}}}
	return
}

func (section *AddressSection) GetLower() *AddressSection {
	return section.getLowestOrHighestSection(true)
}

func (section *AddressSection) GetUpper() *AddressSection {
	return section.getLowestOrHighestSection(false)
}

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
