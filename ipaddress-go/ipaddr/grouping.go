package ipaddr

import (
	"fmt"
	"math/big"
	"sync"
	"unsafe"
)

type prefixLenSetting struct {
	value PrefixLen
	isSet bool
}

type stringCache struct {
	string1, string2 string
}

type groupingCache struct {
	lower, upper *AddressSection

	// needs to go.  Cannot always know what etwork is, because we have no abstract types and we need concrete types for polymorphism
	//network AddressNetwork // never nil // equivalent to overriding getNetwork(), ToIPvX(), IsIPvxConvertible(), etc, in Java, allows you to supply your own conversion
}

type addrType string

const noAddrType addrType = ""
const ipv4AddrType addrType = "IPv4"
const ipv6AddrType addrType = "IPv6"
const macAddrType addrType = "MAC"

func (a addrType) isIndeterminate() bool {
	return a == noAddrType
}

func (a addrType) isIPv4() bool {
	return a == ipv4AddrType
}

func (a addrType) isIPv6() bool {
	return a == ipv6AddrType
}

// whether the prefix of each segment align with each other and the section as a whole
func (a addrType) alignsPrefix() bool {
	return a.isIP()
}

func (a addrType) isIP() bool {
	return a.isIPv4() || a.isIPv6()
}

func (a addrType) isMAC() bool {
	return a == macAddrType
}

type valueCache struct {
	sync.RWMutex

	cachedCount, cachedPrefixCount big.Int // use BitLen() or len(x.Bits()) to check if value is set, or maybe check for 0
	cachedPrefixLen                prefixLenSetting
	lowerBytes, upperBytes         []byte
	isMultiple                     boolSetting
	stringCache                    stringCache
	sectionCache                   groupingCache

	// When a top-level section is created, it is assigned an address type, IPv4, IPv6, or MAC.
	// This is true whether created directly, or created from a low-level grouping or section.
	// Groupings or sections only acquire an asigned type when converted to a top-level type.
	// Once a type is assigned, it never changes.
	//
	// All derived sections are given the same type as the original derived from.
	// The one exception is when an IPAddressSection is created directly and is the zero-segment section,
	// in which cases derived sections must be IPv4 or IPv6.
	// In general, a grouping derived from any zero-division grouping can become any type.
	//
	// All derived sections must maintain a structure matching that type, so that means
	// the number of segments, the bit-count of each, and the segment prefix alignments must
	// remain consistent with the type.  If you append or insert segments, the type must be respected.
	//
	// When doing an upwards conversion to a grouping or section, if the type is assigned (ie not indeterminate),
	// then it can be used as a quicker check for whether the upwards conversion is allowed.
	// Otherwise, the contents of the section must be checked (bit count, segment count, prefix aligment).
	//
	// The type assignment allows us to cache strings and any other type-specific data in the grouping.
	// We can be sure the contents will not become a mismatch to a different type later, since the type cannot be changed.
	// It also allows for quicker upwards conversions.  It also allows for certain operations to be "virtual"
	// in the sense that they are consistent with the original created object.
	//
	// There is no data cached when the type is not yet assigned that could be inconsistent with the assigned type.
	// So that means, like in Java, division groupings do not cache strings, nor do address sections, nor do ip address sections,
	// if they have no assigned type yet.  However, once a type is assigned, then functions at any level may cache type-specific data.
	//
	// However, even if the type is assigned we must be careful.
	// The same function called on a grouping with an assigned type cannot produce a different result
	// than a function called on the same grouping with no assigned type, to avoid confusion, and to avoid "side-effects".
	//
	// So that means type-specific string functions and other functions returning type-specific data will only exist at the top levels,
	// OR those functions must first attempt to assign a type first.  In general, this really only applies to IPAddressSection,
	// because we do not know the possible list of all addresses, so avoiding ambiguity is impossible for AddressSection and below,
	// but we do know all possible IP address types and can figure out which one we are.
	//
	addrType addrType
}

//TODO I think you want to have pointer receivers, because suppose you assign valueCache at some point,
//then it will be lost most likely
//Now, that does ont prevent the user from copying these on his own, but hey, what can ya do?
//BUT that also means AddressSection cannot have a copy either!  And you really wanted them all to be the same object with on deferering amongst the hierarchy
// HERE HERE HERE --> WHICH means that you should make AddressDivisionGrouping contain a pointer to its contents
// this means all functions must then have a check for it being nil, but that is probably the best option
// AND then it doesn't matter if copied or not!
// WHICH then means you do not need pointer receivers
// summarizing... pointer receivers or pointers to addresses is not the issue
// it is whether you want people copying the contents of an address, and if you have cached values, like valueCache, you do not
// So then you make the thing copyable
// And once you do that, pointer receivers provide no benefit
//
// You could also just have the cache populated right away, pointing somewhere
// In any case,
// you want these things copyable
// in which case, pointer receivers are not required
// It is really only the cache that needs to be considered, the others do not change
// The solution is to allocate it right away
// Either that, or you need a double pointer
// Or perhaps you point to the whole thing
// OK, I like how this looks - need to consider the trade-off between assigning cache right away or not
// ALSO conside zero values!  Cannot assign it right away! But zero value needs no caching!
// OK, it is perfect as is.  Just make sure you create a cache obj and assign it on creation of grouping

type addressDivisionGroupingInternal struct {
	divisions           []*AddressDivision
	prefixLength        PrefixLen // must align with the divisions if they store prefix lengths
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
	cache := grouping.cache
	if cache == nil {
		return false
	}
	cache.RLock()
	isMult := cache.isMultiple
	cache.RUnlock()
	if isMult.isSet {
		return isMult.value
	}
	cache.Lock()
	isMult = cache.isMultiple
	if !isMult.isSet {
		//go in reverse order, with prefixes, multiple values are more likely to show up in last segment
		for i := grouping.GetDivisionCount() - 1; i >= 0; i-- {
			if div := grouping.GetDivision(i); div.isMultiple() {
				cache.isMultiple.value = true
				isMult.value = true
				break
			}
		}
		cache.isMultiple.isSet = true
	}
	cache.Unlock()
	return isMult.value
}

//xxxxx
//consider 1:2:* mac
//it gets pref length 16
//we iterate, first element
//1:2:0:0:0:0 has pref length 16
//then shorten to 4 segs or less
//then, if we wanted to make this ipv4
//we woudl have a problem, because with mac segs, not possible to assign prefix 0
//to any of the 0 segs, so we cannot
//
//There is also the question of cached strings for the section
//
//So what can be done? a switchover?  Not so sure I like that,
//because we change prefix length but values and bits must stay the same?
//Too confusing.
//	This is generally true.
//	If it has a prefix length, the segment prefix lengths must align.
//	If no prefix length, then no problem.
//
//	Now, what about general divisions?  general groupings?
//	Can we create them with prefix length, and if so, what do they look like?
//	Well, I think I will end up with a new divisionsValues impl for general divisions.
//
//	What about appending, prepending, replacing, etc? Well, I think the ipvx versions will require ipvx inputs.
//	The more general ones will not.  And in the end, we will end up with the same checks to go back to ipvx.
//
//	But what about cached strings? Well, we are fine for divs and segs!
//	Because cachedWildcardSring is the same for all divisions.
//	Only ip segs use cachedString.
//	But what about groupings?  The separator is different for one.  But those strings are restricted to sections.
//
//	OK, I think you need another rule:  Once a section has become a specific type, it cannot be any other.
//	We need a flag for that.
//
//	TODO conversion: So we have two things:
//		1. prefixes must align for ipvx
//		2. we assign a type/version just once, and it can never change after
//	 - We can combine the two, so that if the type/version not there, then we check aligment,
//		otherwise we check just type/version.
//	- ANy segment altering func must check type/version, and if it is ipvx, it must satisfy alignment too.
//	This also handles strings, they can only be created when we know the ip version!
//	Which means, no caching for any string funcs below the highest!  None!
//	- In reality, this is not really restrictive, because of the other checks, bit count, segment count, etc

// getPrefixLengthCacheLocked calculates prefix length
// If a division D has a prefix length p, and all following division have prefix length 0,
// and there are no earlier division with the same property, then division D determines the over-all prefix length
// of the grouping.
// In the case of IPv4/6 groupings, this property is enforced, so if a division has a non-zero prefix length,
// then all preceding division must have nil prefix length and all following must have zero prefix length.
func (grouping *addressDivisionGroupingInternal) getPrefixLengthCacheLocked() PrefixLen {
	cache := grouping.cache
	prefLen := cache.cachedPrefixLen
	if !prefLen.isSet {
		count := grouping.GetDivisionCount()
		bitsSoFar, prefixBits := BitCount(0), BitCount(0)
		hasPrefix := false
		for i := 0; i < count; i++ {
			div := grouping.GetDivision(i)
			divPrefLen := div.getDivisionPrefixLength() //TODO for MAC this needs to be changed to getMinPrefixLengthForBlock (optimize it to check for full range or single value first )
			if hasPrefix = divPrefLen != nil; hasPrefix {
				divPrefBits := *divPrefLen
				if !hasPrefix || divPrefBits != 0 {
					prefixBits = bitsSoFar + divPrefBits
				}
				if grouping.cache.addrType.alignsPrefix() {
					break
				}
			}
			bitsSoFar += div.GetBitCount()
		}
		if hasPrefix {
			res := &prefixBits
			prefLen.value = res
			cache.cachedPrefixLen.value = res
		}
		cache.cachedPrefixLen.isSet = true
	}
	return prefLen.value
}

// IsMultiple returns whether this address or grouping represents more than one address or grouping.
// Such addresses include CIDR/IP addresses (eg 1.2.3.4/11) or wildcard addresses (eg 1.2.*.4) or range addresses (eg 1.2.3-4.5)
func (grouping *addressDivisionGroupingInternal) GetPrefixLength() PrefixLen {
	cache := grouping.cache
	if cache == nil {
		// zero-valued grouping (no divisions)
		return nil
	}
	cache.RLock()
	prefLen := cache.cachedPrefixLen
	cache.RUnlock()
	if prefLen.isSet {
		return prefLen.value
	}
	cache.Lock()
	result := grouping.getPrefixLengthCacheLocked()
	cache.Unlock()
	return result
}

// prefixesAlign returns whether the prefix of each division align with each other, which is a requirement for IPv4/6
// If an earlier division has a prefix, then all following division must have prefix 0
func (grouping *addressDivisionGroupingInternal) prefixesAlign() bool {
	count := grouping.GetDivisionCount()
	for i := 0; i < count; i++ {
		div := grouping.GetDivision(i)
		divPrefLen := div.getDivisionPrefixLength() //TODO for MAC this needs to be changed to getMinPrefixLengthForBlock (optimize it to check for full range or single value first )
		if divPrefLen != nil {
			for j := i + 1; j < count; j++ {
				div = grouping.GetDivision(j)
				divPrefLen = div.getDivisionPrefixLength()
				if divPrefLen == nil || *divPrefLen != 0 {
					return false
				}
			}
		}
	}
	return true
}

//xxxx think about isAligned - does it jive with the fact you can switch back and forth from ipv4 to mac?
//xxxx only if the rule is enforced
//xxxx and you cannot really enforce it, or can you?  yes you can
//xxxx for ipv4/6 we enforce , for mac we never change a prefix unless it is set explicitly
//xxxx but you CANNOT enforce the rule that an ipv4 segment returns true for isAligned and mac returns false
//xxxx so it needs to go
//xxxx so where does it come from in the code above?
//xxxx it needs to be set somewhere, sort of
//xxxx or do I just keep going to the end of the segments?  Maybe I do
//xxxx and Maybe I add another check when converting to ip sections
//remember that we only infer mac prefix length on creation
//I think perhaps you allow segments to provide any old prefix length and on mac they do not always jive with the whole section
//In fact, taht is also true with others, only when you convert to ipsection is that rule enforced
//What about cached strings?  does not apply since we have no fancy strings with groupings, the cached strings are not used I think otherwise
//
//All in all, I think maybe you remove isAligned (so you check all segs), and you only check alignment when converting to IPAddressSection
//Yeah, in fact, prefix len will be set already in most cases when constructing
//But you cannot really use prefix len as an indicator that they are aligned
//But you are already checking bit lengths when converting upwards, and this does not even apply to Address, or maybe it does
//
//What about cached strings when going mac to ipv4?
//I am strarting to think you cannot allow mac to ipv4 or ipv4 to mac
//It only applies to sections anyway!
//Maybe you can apply a "hint", ie IPVersion or type or something
//Yeah
//This only applies to cached stuff, maybe only strings, do you really need to worry about this?
//KISS
//I think you are leaning towards no alignment in method above, remove alignment everywhere
//And you check for it when converting to IPAddressSection or IPAddress, and perhaps you have a cached flag indicating it!  Yeah.
//As for using mac for ipv4 or vice versa, it applies only to sections, and really only to strings
//BUt there are scenarios, what if I contructed IPv4 from 4 mac segments?  Probably fine.  But I do need the prefix check.
//What if I used it as a mac section first, so I cached a bunch of strings?
//You may need to have a type/version flag that is set during conversion (if not already set)
//Or you could put that flag in the string cache
//What about lower/upper, which are sections already and have their own strings?
//Maybe you need to prvent ipv4 to mac to ipv4
//OH, there is also network!  that might be the clincher.  I've thought about clearing out the cache, making some of it version dependent, etc
//Maybe you can check the network version? That is an indicator for everything else.  In fact, you could set the network if it is nil.
//	That is a good idea.  Maybe it could even supercede the other checks?  If there is a netowrk?

func (grouping *addressDivisionGroupingInternal) getBytes() []byte {
	if grouping.hasNoDivisions() {
		//TODO been thinking about returning nil?  Kinda makes sense, not specifying divisions not the same as specifying 0 divisions
		//arr := [0]byte{}
		//return arr[:]
		return nil
	}
	//TODO
	//return addr.section.getBytes()
	return nil
}

// Returns whether the series represents a range of values that are sequential.
// Generally, this means that any division covering a range of values must be followed by divisions that are full range, covering all values.
func (grouping *addressDivisionGroupingInternal) IsSequential() bool {
	count := grouping.GetDivisionCount()
	if count > 1 {
		for i := 0; i < count; i++ {
			if grouping.GetDivision(i).isMultiple() {
				for i++; i < count; i++ {
					if !grouping.GetDivision(i).IsFullRange() {
						return false
					}
				}
				return true
			}
		}
	}
	return true

}

//// hasNilDivisions() returns whether this grouping is the zero grouping,
//// which is what you get when contructing a grouping or section with no divisions
//func (grouping *addressDivisionGroupingInternal) hasNilDivisions() bool {
//	return grouping.divisions == nil
//}

// hasNilDivisions() returns whether this grouping is the zero grouping,
// which is what you get when contructing a grouping or section with no divisions
func (grouping *addressDivisionGroupingInternal) hasNoDivisions() bool {
	return len(grouping.divisions) == 0
}

func (grouping *addressDivisionGroupingInternal) GetDivisionCount() int { //TODO make non-public so not exposed in IPv4/6/MAC
	return len(grouping.divisions)
}

// TODO think about the panic a bit more, do we want an error?  do slices panic with bad indices?

// GetDivision returns the division or panics if the index is negative or it is too large
func (grouping *addressDivisionGroupingInternal) GetDivision(index int) *AddressDivision { //TODO make non-public so not exposed in IPv4/6/MAC
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

func (section *addressSectionInternal) ToPrefixBlock() *AddressSection {
	//TODO ToPrefixBlock
	return nil
}

func (section *addressSectionInternal) matchesSection(segmentCount int, segmentBitCount BitCount) bool {
	divLen := len(section.divisions)
	return divLen <= segmentCount && (divLen == 0 || section.GetDivision(0).GetBitCount() == segmentBitCount)
}

func (section *addressSectionInternal) matchesAddress(segmentCount int, segmentBitCount BitCount) bool {
	return len(section.divisions) == segmentCount && section.GetDivision(0).GetBitCount() == segmentBitCount
}

func (section *addressSectionInternal) matchesIPv6Section() bool {
	//xxxx all the cache access must check for nil first, all cache access must go through methods xxx
	cache := section.cache
	return cache == nil || cache.addrType.isIPv6() ||
		(cache.addrType.isIndeterminate() &&
			section.matchesSection(IPv6SegmentCount, IPv6BitsPerSegment) && section.prefixesAlign())
}

func (section *addressSectionInternal) matchesIPv4Section() bool {
	cache := section.cache
	return cache == nil || cache.addrType.isIPv4() ||
		(cache.addrType.isIndeterminate() &&
			section.matchesSection(IPv4SegmentCount, IPv4BitsPerSegment) && section.prefixesAlign())
}

func (section *addressSectionInternal) matchesIPSection() bool {
	cache := section.cache
	return cache == nil || cache.addrType.isIP() ||
		(cache.addrType.isIndeterminate() &&
			(section.matchesSection(IPv4SegmentCount, IPv4BitsPerSegment) || section.matchesSection(IPv6SegmentCount, IPv6BitsPerSegment)) &&
			section.prefixesAlign())
}

func (section *addressSectionInternal) getAddrType() addrType {
	cache := section.cache
	if cache != nil {
		if cache.addrType.isIPv4() {
			return ipv4AddrType
		} else if cache.addrType.isIPv6() {
			return ipv6AddrType
		}
		divLen := section.GetDivisionCount()
		if divLen > 0 {
			bc := section.GetDivision(0).GetBitCount()
			if bc == IPv4BitsPerSegment {
				return ipv4AddrType
			} else if bc == IPv6BitsPerSegment {
				return ipv6AddrType
			}
		}
	}
	return noAddrType
}

func (section *addressSectionInternal) matchesMACSection() bool {
	// note that any MAC section is also an ExtendedUniqueIdentifier64, so no need to check section.matchesSection(MediaAccessControlSegmentCount, MACBitsPerSegment)
	cache := section.cache
	return cache == nil || cache.addrType.isMAC() || section.matchesSection(ExtendedUniqueIdentifier64SegmentCount, MACBitsPerSegment)
}

func (section *addressSectionInternal) matchesIPv6Address() bool {
	cache := section.cache
	return cache != nil && (section.matchesAddress(IPv6SegmentCount, IPv6BitsPerSegment) && section.prefixesAlign())
}

func (section *addressSectionInternal) matchesIPv4Address() bool {
	cache := section.cache
	return cache != nil && (section.matchesAddress(IPv4SegmentCount, IPv4BitsPerSegment) && section.prefixesAlign())
}

func (section *addressSectionInternal) matchesMACAddress() bool {
	return section.matchesAddress(MediaAccessControlSegmentCount, MACBitsPerSegment) ||
		section.matchesAddress(ExtendedUniqueIdentifier64SegmentCount, MACBitsPerSegment)
}

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
		prefixLength: section.getPrefixLengthCacheLocked(),
		cache:        &valueCache{addrType: section.cache.addrType},
	}}}
	return
}

func (section *AddressSection) GetLower() *AddressSection {
	return section.getLowestOrHighestSection(true)
}

func (section *AddressSection) GetUpper() *AddressSection {
	return section.getLowestOrHighestSection(true)
}

func (section *AddressSection) ToIPAddressSection() *IPAddressSection {
	if section == nil || !section.matchesIPSection() {
		return nil
	}
	cache := section.cache
	cache.addrType = section.getAddrType()
	return (*IPAddressSection)(unsafe.Pointer(section))
}

func (section *AddressSection) ToIPv6AddressSection() *IPv6AddressSection {
	if section == nil || !section.matchesIPv6Section() {
		return nil
	}
	cache := section.cache
	if cache != nil {
		cache.addrType = ipv6AddrType
	}
	return (*IPv6AddressSection)(unsafe.Pointer(section))
}

func (section *AddressSection) ToIPv4AddressSection() *IPv4AddressSection {
	if section == nil || !section.matchesIPv4Section() {
		return nil
	}
	cache := section.cache
	if cache != nil {
		cache.addrType = ipv4AddrType
	}
	return (*IPv4AddressSection)(unsafe.Pointer(section))
}

func (section *AddressSection) ToMACAddressSection() *MACAddressSection {
	if section == nil || !section.matchesMACSection() {
		return nil
	}
	cache := section.cache
	if cache != nil {
		cache.addrType = macAddrType
	}
	return (*MACAddressSection)(unsafe.Pointer(section))
}

//
//
//
//
type ipAddressSectionInternal struct {
	addressSectionInternal
}

func (section *ipAddressSectionInternal) GetSegment(index int) *IPAddressSegment {
	return section.GetDivision(index).ToIPAddressSegment()
}

func (section *ipAddressSectionInternal) GetIPVersion() IPVersion {
	if section.matchesIPv4Section() {
		return IPv4
	}
	return IPv6
}

func (section *ipAddressSectionInternal) GetNetworkPrefixLength() PrefixLen {
	return section.prefixLength
}

func (section *ipAddressSectionInternal) GetBlockMaskPrefixLength(network bool) PrefixLen {
	// TODO GetBlockMaskPrefixLength is needed for address creation amongst other things
	return nil
}

func (section *ipAddressSectionInternal) ToAddressSection() *AddressSection {
	return (*AddressSection)(unsafe.Pointer(section))
}

func (section *ipAddressSectionInternal) initPrefix(bitsPerSegment BitCount) error {
	var previousSegmentPrefix PrefixLen
	segCount := section.GetSegmentCount()
	for i := 0; i < segCount; i++ {
		div := section.GetDivision(i)
		if div == nil {
			//TODO throw new NullPointerException(getMessage("ipaddress.error.null.segment"));
			return &addressException{"ipaddress.error.null.segment"}
		} else if section.GetDivision(i).GetBitCount() != bitsPerSegment {
			return &addressException{"ipaddress.error.mismatched.bit.size"}
		}
		segment := section.GetSegment(i)

		//Across an address prefixes are:
		//IPv6: (null):...:(null):(1 to 16):(0):...:(0)
		//or IPv4: ...(null).(1 to 8).(0)...
		segPrefix := segment.GetSegmentPrefixLength()
		if previousSegmentPrefix == nil {
			if segPrefix != nil {
				section.prefixLength = getNetworkPrefixLength(bitsPerSegment, *segPrefix, i)
				//break
			}
		} else if segPrefix == nil || *segPrefix != 0 {
			//return &inconsistentPrefixException(segments[i-1], segment, segPrefix)
			return &inconsistentPrefixException{str: fmt.Sprintf("%v %v %v", section.GetSegment(i-1), segment, segPrefix), key: "ipaddress.error.inconsistent.prefixes"}
		}
		previousSegmentPrefix = segPrefix
	}
	//if(previousSegmentPrefix == nil) { no need for this now since prefix length always set
	//	cachedPrefixLength = NO_PREFIX_LENGTH;
	//}
	return nil
}

//
//
//
// An IPAddress section has segments, which are divisions of equal length and size
type IPAddressSection struct {
	ipAddressSectionInternal
}

func (section *IPAddressSection) IsIPv4() bool {
	return section.matchesIPv4Section()
}

func (section *IPAddressSection) IsIPv6() bool {
	return section.matchesIPv6Section()
}

func (section *IPAddressSection) GetLower() *IPAddressSection {
	return section.ToAddressSection().GetLower().ToIPAddressSection()
}

func (section *IPAddressSection) GetUpper() *IPAddressSection {
	return section.ToAddressSection().GetUpper().ToIPAddressSection()
}

func (section *IPAddressSection) ToPrefixBlock() *IPAddressSection {
	//TODO ToPrefixBlock
	return nil
}

func (section *IPAddressSection) ToIPv6AddressSection() *IPv6AddressSection {
	if section == nil {
		return nil
	} else if section.matchesIPv6Section() {
		cache := section.cache
		cache.addrType = ipv6AddrType
		return (*IPv6AddressSection)(unsafe.Pointer(section))
	}
	return nil
}

func (section *IPAddressSection) ToIPv4AddressSection() *IPv4AddressSection {
	if section == nil {
		return nil
	} else if section.matchesIPv4Section() {
		cache := section.cache
		cache.addrType = ipv4AddrType
		return (*IPv4AddressSection)(unsafe.Pointer(section))
	}
	return nil
}

func BitsPerSegment(version IPVersion) BitCount {
	if version == IPv4 {
		return IPv4BitsPerSegment
	}
	return IPv6BitsPerSegment
}

func assignPrefix(prefixLength PrefixLen, segments []*AddressDivision, res *IPAddressSection, singleOnly bool, boundaryBits, maxBits BitCount) (err AddressValueException) {
	//if prefixLength != nil {
	prefLen := *prefixLength
	if prefLen < 0 {
		return &prefixLenException{prefixLen: prefLen, key: "ipaddress.error.prefixSize"}
		//throw new PrefixLenException(networkPrefixLength);
	} else if prefLen > boundaryBits {
		if prefLen > maxBits {
			return &prefixLenException{prefixLen: prefLen, key: "ipaddress.error.prefixSize"}
			//throw new PrefixLenException(networkPrefixLength);
		}
		prefLen = boundaryBits
		prefixLength = &boundaryBits
	}
	if len(segments) > 0 {
		segsPrefLen := res.prefixLength
		if segsPrefLen != nil {
			sp := *segsPrefLen
			if sp < prefLen { //if the segments have a shorter prefix length, then use that
				prefLen = sp
				prefixLength = segsPrefLen
			}
		}
		var segProducer func(*AddressDivision, PrefixLen) *AddressDivision
		if !singleOnly && isPrefixSubnetSegs(segments, prefLen, false) {
			segProducer = (*AddressDivision).toPrefixedNetworkDivision
		} else {
			segProducer = (*AddressDivision).toPrefixedDivision
		}
		setPrefixedSegments(
			prefLen,
			res.divisions,
			res.GetBitsPerSegment(),
			res.GetBytesPerSegment(),
			segProducer)
	}
	res.prefixLength = prefixLength
	//} // else prefixLength has already been set to the proper value
	return
}

// Starting from the first host bit according to the prefix, if the section is a sequence of zeros in both low and high values,
// followed by a sequence where low values are zero and high values are 1, then the section is a subnet prefix.
//
// Note that this includes sections where hosts are all zeros, or sections where hosts are full range of values,
// so the sequence of zeros can be empty and the sequence of where low values are zero and high values are 1 can be empty as well.
// However, if they are both empty, then this returns false, there must be at least one bit in the sequence.
func isPrefixSubnetSegs(sectionSegments []*AddressDivision, networkPrefixLength BitCount, fullRangeOnly bool) bool {
	segmentCount := len(sectionSegments)
	if segmentCount == 0 {
		return false
	}
	seg := sectionSegments[0]
	//SegmentValueProvider func(segmentIndex int) SegInt
	return isPrefixSubnet(
		func(segmentIndex int) SegInt {
			return sectionSegments[segmentIndex].ToAddressSegment().GetSegmentValue()
		},
		func(segmentIndex int) SegInt {
			return sectionSegments[segmentIndex].ToAddressSegment().GetUpperSegmentValue()
		},
		//segmentIndex -> sectionSegments[segmentIndex].getSegmentValue(),
		//segmentIndex -> sectionSegments[segmentIndex].getUpperSegmentValue(),
		segmentCount,
		seg.GetByteCount(),
		seg.GetBitCount(),
		seg.ToAddressSegment().GetMaxSegmentValue(),
		//SegInt(seg.GetMaxValue()),
		networkPrefixLength,
		fullRangeOnly)
}

func setPrefixedSegments(
	sectionPrefixBits BitCount,
	segments []*AddressDivision,
	segmentBitCount BitCount,
	segmentByteCount int,
	segProducer func(*AddressDivision, PrefixLen) *AddressDivision) {
	var i int
	if sectionPrefixBits != 0 {
		i = getNetworkSegmentIndex(sectionPrefixBits, segmentByteCount, segmentBitCount)
	}
	for ; i < len(segments); i++ {
		pref := getPrefixedSegmentPrefixLength(segmentBitCount, sectionPrefixBits, i)
		if pref != nil {
			segments[i] = segProducer(segments[i], pref)
		}
	}
}

func normalizePrefixBoundary(
	sectionPrefixBits BitCount,
	segments []*AddressDivision,
	segmentBitCount BitCount,
	segmentByteCount int,
	segmentCreator func(val, upperVal SegInt, prefLen PrefixLen) *AddressDivision) {
	//we've already verified segment prefixes.  We simply need to check the case where the prefix is at a segment boundary,
	//whether the network side has the correct prefix
	networkSegmentIndex := getNetworkSegmentIndex(sectionPrefixBits, segmentByteCount, segmentBitCount)
	if networkSegmentIndex >= 0 {
		segment := segments[networkSegmentIndex].ToIPAddressSegment()
		if !segment.IsPrefixed() {
			segments[networkSegmentIndex] = segmentCreator(segment.GetSegmentValue(), segment.GetUpperSegmentValue(), cacheBitcount(segmentBitCount))
		}
	}
}

func newIPv6AddressSection(segments []*AddressDivision, startIndex int /*, cloneSegments bool*/, normalizeSegments bool) (res *IPv6AddressSection, err AddressValueException) {
	if startIndex < 0 {
		err = &addressPositionException{val: startIndex, key: "ipaddress.error.invalid.position"}
		return
	}
	segsLen := len(segments)
	if startIndex+segsLen > IPv6SegmentCount {
		err = &addressValueException{val: startIndex + segsLen, key: "ipaddress.error.exceeds.size"}
		return
	}
	//if cloneSegments { //TODO this is likely not necessary because for public you will need to convert from []*IPv6AddressSegment to []*AddressDivision before calling this func
	//	segments = append(make([]*AddressDivision, 0, segsLen), segments...)
	//}
	res = &IPv6AddressSection{
		ipAddressSectionInternal{
			addressSectionInternal{
				addressDivisionGroupingInternal{
					divisions:           segments,
					cache:               &valueCache{addrType: ipv6AddrType},
					addressSegmentIndex: uint8(startIndex),
				},
			},
		},
	}
	err = res.initPrefix(IPv6BitsPerSegment)
	if err != nil {
		return
	}
	prefLen := res.prefixLength
	if normalizeSegments && prefLen != nil {
		normalizePrefixBoundary(*prefLen, segments, IPv6BitsPerSegment, IPv6BytesPerSegment, func(val, upperVal SegInt, prefLen PrefixLen) *AddressDivision {
			return NewIPv6RangePrefixSegment(IPv6SegInt(val), IPv6SegInt(upperVal), prefLen).ToAddressDivision()
		})
	}
	return
}

//protected IPv6AddressSection(IPv6AddressSegment[] segments, int startIndex, boolean cloneSegments, Integer networkPrefixLength, boolean singleOnly) throws AddressValueException {

func newIPv6AddressSectionSingle(segments []*AddressDivision, startIndex int /*cloneSegments bool,*/, prefixLength PrefixLen, singleOnly bool) (res *IPv6AddressSection, err AddressValueException) {
	res, err = newIPv6AddressSection(segments, startIndex /*cloneSegments,*/, prefixLength == nil)
	if err != nil {
		err = assignPrefix(prefixLength, segments, res.ToIPAddressSection(), singleOnly, BitCount(len(segments)<<4), IPv6BitCount)
	}
	return
}

// IPv6AddressSection represents a section of an IPv6 address comprising 0 to 8 IPv6 address segments.
// The zero values is a section with zero segments.
type IPv6AddressSection struct {
	ipAddressSectionInternal
}

func (section *IPv6AddressSection) GetSegment(index int) *IPv6AddressSegment {
	return section.GetDivision(index).ToIPv6AddressSegment()
}

func (section *IPv6AddressSection) GetLower() *IPv6AddressSection {
	return section.ToAddressSection().GetLower().ToIPv6AddressSection()
}

func (section *IPv6AddressSection) GetUpper() *IPv6AddressSection {
	return section.ToAddressSection().GetUpper().ToIPv6AddressSection()
}

func (section *IPv6AddressSection) ToPrefixBlock() *IPv6AddressSection {
	//TODO ToPrefixBlock
	return nil
}

func (section *IPv6AddressSection) ToIPAddressSection() *IPAddressSection {
	return (*IPAddressSection)(unsafe.Pointer(section))
}

func (section *IPv6AddressSection) GetIPVersion() IPVersion {
	return IPv6
}

func newIPv4AddressSection(segments []*AddressDivision /*cloneSegments bool,*/, normalizeSegments bool) (res *IPv4AddressSection, err AddressValueException) {
	//if startIndex < 0 {
	//	err = &addressPositionException{val: startIndex, key: "ipaddress.error.invalid.position"}
	//	return
	//}
	segsLen := len(segments)
	if segsLen > IPv4SegmentCount {
		err = &addressValueException{val: segsLen, key: "ipaddress.error.exceeds.size"}
		return
	}
	//if cloneSegments { //TODO this is likely not necessary because for public you will need to convert from []*IPv4AddressSegment to []*AddressDivision before calling this func
	//	segments = append(make([]*AddressDivision, 0, segsLen), segments...)
	//}
	res = &IPv4AddressSection{
		ipAddressSectionInternal{
			addressSectionInternal{
				addressDivisionGroupingInternal{
					divisions: segments,
					cache:     &valueCache{addrType: ipv4AddrType},
					//addressSegmentIndex: uint8(startIndex),
				},
			},
		},
	}
	err = res.initPrefix(IPv4BitsPerSegment)
	if err != nil {
		return
	}
	prefLen := res.prefixLength
	if normalizeSegments && prefLen != nil {
		normalizePrefixBoundary(*prefLen, segments, IPv4BitsPerSegment, IPv4BytesPerSegment, func(val, upperVal SegInt, prefLen PrefixLen) *AddressDivision {
			return NewIPv4RangePrefixSegment(IPv4SegInt(val), IPv4SegInt(upperVal), prefLen).ToAddressDivision()
		})
	}
	return
}

func newIPv4AddressSectionSingle(segments []*AddressDivision /* cloneSegments bool,*/, prefixLength PrefixLen, singleOnly bool) (res *IPv4AddressSection, err AddressValueException) {
	res, err = newIPv4AddressSection(segments /*cloneSegments,*/, prefixLength == nil)
	if err == nil && prefixLength != nil {
		err = assignPrefix(prefixLength, segments, res.ToIPAddressSection(), singleOnly, BitCount(len(segments)<<3), IPv4BitCount)
	}
	return
}

// IPv4AddressSection represents a section of an IPv4 address comprising 0 to 4 IPv4 address segments.
// The zero values is a section with zero segments.
type IPv4AddressSection struct {
	ipAddressSectionInternal
}

func (section *IPv4AddressSection) GetSegment(index int) *IPv4AddressSegment {
	return section.GetDivision(index).ToIPv4AddressSegment()
}

func (section *IPv4AddressSection) GetLower() *IPv4AddressSection {
	return section.ToAddressSection().GetLower().ToIPv4AddressSection()
}

func (section *IPv4AddressSection) GetUpper() *IPv4AddressSection {
	return section.ToAddressSection().GetUpper().ToIPv4AddressSection()
}

func (section *IPv4AddressSection) ToPrefixBlock() *IPv4AddressSection {
	//TODO ToPrefixBlock
	return nil
}

func (section *IPv4AddressSection) ToIPAddressSection() *IPAddressSection {
	return (*IPAddressSection)(unsafe.Pointer(section))
}

func (section *IPv4AddressSection) GetIPVersion() IPVersion {
	return IPv4
}

//
//
//
//
//
//
//
type macAddressSectionInternal struct {
	addressSectionInternal
}

func (section *macAddressSectionInternal) GetSegment(index int) *MACAddressSegment {
	return section.GetDivision(index).ToMACAddressSegment()
}

//func (section *ipAddressSectionInternal) GetIPVersion() IPVersion (TODO need the MAC equivalent (ie EUI 64 or MAC 48, butcannot remember if there is a MAC equivalent)
//	if section.IsIPv4() {
//		return IPv4
//	}
//	return IPv6
//}

type MACAddressSection struct {
	macAddressSectionInternal
}

func (section *MACAddressSection) ToAddressSection() *AddressSection {
	return (*AddressSection)(unsafe.Pointer(section))
}

func (section *MACAddressSection) GetLower() *MACAddressSection {
	return section.ToAddressSection().GetLower().ToMACAddressSection()
}

func (section *MACAddressSection) GetUpper() *MACAddressSection {
	return section.ToAddressSection().GetUpper().ToMACAddressSection()
}

func (section *MACAddressSection) ToPrefixBlock() *MACAddressSection {
	//TODO ToPrefixBlock
	return nil
}
