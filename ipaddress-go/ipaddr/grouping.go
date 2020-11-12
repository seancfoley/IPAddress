package ipaddr

import (
	"math/big"
	"sync/atomic"
	"unsafe"
)

// A flag is set just once by just one goroutine
type atomicFlag struct {
	val uint32
}

func (a *atomicFlag) isSet() bool {
	return atomic.LoadUint32(&a.val) > 0
}

func (a *atomicFlag) set() {
	atomic.StoreUint32(&a.val, 1)
}

func (a *atomicFlag) unset() {
	atomic.StoreUint32(&a.val, 0)
}

type BitCount int

type PrefixLen *BitCount

type Port *int
type Service string

// Allows for 3 different boolean values: not set, set to true, set to false (Similar to Boolean in Java which is null, true, false)
type boolSetting struct {
	value, isSet bool
}

type valueCache struct {
	cachedCount, cachedPrefixCount big.Int // use BitLen() or len(x.Bits()) to check if value is set, or maybe check for 0
	lowerBytes, upperBytes         []byte  // TODO cache net.IP  in address, much like we cache InetAddress in Java
	isMultiple                     boolSetting
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

type AddressDivisionGrouping struct {
	divisions    []*AddressDivision
	prefixLength PrefixLen   // must align with the divisions if they store prefix lengths
	cache        *valueCache // assigned on creation, except for zero-value groupings, in which it is not needed
}

func (grouping *AddressDivisionGrouping) getBytes() []byte {
	if grouping.hasNilDivisions() {
		//TODO been thinking about returning nil?  Kinda makes sense, not specifying divisions not the same as specifying 0 divisions
		//arr := [0]byte{}
		//return arr[:]
		return nil
	}
	//TODO
	//return addr.section.getBytes()
	return nil
}

// hasNilDivisions() returns whether this grouping is the zero grouping,
// which is what you get when contructing a grouping or section with no divisions
func (grouping *AddressDivisionGrouping) hasNilDivisions() bool {
	return grouping.divisions == nil
}

func (grouping *AddressDivisionGrouping) GetDivisionCount() int {
	return len(grouping.divisions)
}

// GetDivision returns the division or panics if the index is negative, matches or exceeds the number of divisions
func (grouping *AddressDivisionGrouping) GetDivision(index int) *AddressDivision {
	return grouping.divisions[index]
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
	//return AddressSection{grouping}
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

//////////////////////////////////////////////////////////////////
//
//
//
type AddressSection struct {
	AddressDivisionGrouping
}

func (section *AddressSection) GetSegmentCount() int {
	return section.GetDivisionCount()
}

func (section *AddressSection) matchesSection(segmentCount int, segmentBitCount BitCount) bool {
	divLen := len(section.divisions)
	return divLen <= segmentCount && (divLen == 0 || section.GetDivision(0).GetBitCount() == segmentBitCount)
}

func (section *AddressSection) matchesAddress(segmentCount int, segmentBitCount BitCount) bool {
	return len(section.divisions) == segmentCount && section.GetDivision(0).GetBitCount() == segmentBitCount
}

func (section *AddressSection) matchesIPv6Section() bool {
	return section.matchesSection(IPv6SegmentCount, IPv6BitsPerSegment)
}

func (section *AddressSection) matchesIPv4Section() bool {
	return section.matchesSection(IPv4SegmentCount, IPv4BitsPerSegment)
}

func (section *AddressSection) matchesIPv6Address() bool {
	return section.matchesAddress(IPv6SegmentCount, IPv6BitsPerSegment)
}

func (section *AddressSection) matchesIPv4Address() bool {
	return section.matchesAddress(IPv4SegmentCount, IPv4BitsPerSegment)
}

func (section *AddressSection) ToAddressDivisionGrouping() AddressDivisionGrouping {
	return section.AddressDivisionGrouping
}

func (section *AddressSection) ToAddressSection() *AddressSection {
	return section
}

func (section *AddressSection) ToIPAddressSection() *IPAddressSection {
	if section == nil {
		return nil
	}
	divCount := section.GetDivisionCount()
	if divCount > 0 {
		bc := section.GetDivision(0).GetBitCount()
		if divCount <= IPv4SegmentCount {
			if bc != IPv4BitsPerSegment && bc != IPv6BitsPerSegment {
				return nil
			}
		} else if divCount <= IPv6SegmentCount {
			if bc != IPv6BitsPerSegment {
				return nil
			}
		} else {
			return nil
		}
	}
	return (*IPAddressSection)(unsafe.Pointer(section))
}

func (section *AddressSection) ToIPv6AddressSection() *IPv6AddressSection {
	if section == nil {
		return nil
	} else if divCount := section.GetDivisionCount(); divCount != IPv6SegmentCount {
		return nil
	} else if section.GetDivision(0).GetBitCount() != IPv6BitsPerSegment {
		return nil
	}
	return (*IPv6AddressSection)(unsafe.Pointer(section))
}

func (section *AddressSection) ToIPv4AddressSection() *IPv4AddressSection {
	if section == nil {
		return nil
	} else if divCount := section.GetDivisionCount(); divCount != IPv4SegmentCount {
		return nil
	} else if section.GetDivision(0).GetBitCount() != IPv4BitsPerSegment {
		return nil
	}
	return (*IPv4AddressSection)(unsafe.Pointer(section))
}

//
//
//
// An IPAddress section has segments, which are divisions of equal length and size
type IPAddressSection struct {
	AddressSection //TODO you need the same indirection as swith address addressInternal
}

func (section *IPAddressSection) ToIPAddressSection() *IPAddressSection {
	return section
}

func (section *IPAddressSection) GetSegment(index int) *IPAddressSegment {
	return section.GetDivision(index).ToIPAddressSegment()
}

func (section *IPAddressSection) IsIPv4() bool {
	return section.matchesIPv4Address()
}

func (section *IPAddressSection) IsIPv6() bool {
	return section.matchesIPv6Address()
}

func (section *IPAddressSection) GetIPVersion() IPVersion {
	if section.IsIPv4() {
		return IPv4
	}
	return IPv6
}

func (section *IPAddressSection) GetNetworkPrefixLength() PrefixLen {
	return section.prefixLength
}

func (section *IPAddressSection) ToIPv6AddressSection() *IPv6AddressSection {
	if section == nil {
		return nil
	}
	if section.matchesIPv6Section() {
		return (*IPv6AddressSection)(unsafe.Pointer(section))
		//return IPv6AddressSection{section}
	}
	return nil
	//return IPv6AddressSection{}
}

func (section *IPAddressSection) ToIPv4AddressSection() *IPv4AddressSection {
	if section == nil {
		return nil
	}
	if section.matchesIPv4Section() {
		return (*IPv4AddressSection)(unsafe.Pointer(section))
		//return IPv4AddressSection{section}
	}
	return nil
	//return IPv4AddressSection{}
}

// IPv6AddressSection represents a section of an IPv6 address comprising 0 to 8 IPv6 address segments.
// The zero values is a section with zero segments.
type IPv6AddressSection struct {
	IPAddressSection //TODO you need the same indirection as swith address ipAddressInternal
}

func (section *IPv6AddressSection) ToIPv6AddressSection() *IPv6AddressSection {
	return section
}

func (section *IPv6AddressSection) IsIPv4() bool {
	return false
}

func (section *IPv6AddressSection) IsIPv6() bool {
	return true
}

func (section *IPv6AddressSection) GetIPVersion() IPVersion {
	return IPv6
}

// IPv4AddressSection represents a section of an IPv4 address comprising 0 to 4 IPv4 address segments.
// The zero values is a section with zero segments.
type IPv4AddressSection struct {
	IPAddressSection
}

func (section *IPv4AddressSection) ToIPv4AddressSection() *IPv4AddressSection {
	return section
}

func (section *IPv4AddressSection) IsIPv4() bool {
	return true
}

func (section *IPv4AddressSection) IsIPv6() bool {
	return false
}

func (section *IPv4AddressSection) GetIPVersion() IPVersion {
	return IPv4
}
