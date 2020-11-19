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

type BitCount uint16

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

type addressDivisionGroupingInternal struct {
	divisions    []*AddressDivision
	prefixLength PrefixLen   // must align with the divisions if they store prefix lengths
	cache        *valueCache // assigned on creation, except for zero-value groupings, in which it is not needed
}

func (grouping *addressDivisionGroupingInternal) getBytes() []byte {
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
func (grouping *addressDivisionGroupingInternal) hasNilDivisions() bool {
	return grouping.divisions == nil
}

func (grouping *addressDivisionGroupingInternal) GetDivisionCount() int {
	return len(grouping.divisions)
}

// TODO think about the panic a bit more, do we want an error?  do slices panic with bad indices?

// GetDivision returns the division or panics if the index is negative or it is too large
func (grouping *addressDivisionGroupingInternal) GetDivision(index int) *AddressDivision {
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

func (section *addressSectionInternal) GetSegment(index int) *AddressSegment {
	return section.GetDivision(index).ToAddressSegment()
}

func (section *addressSectionInternal) GetSegmentCount() int {
	return section.GetDivisionCount()
}

func (section *addressSectionInternal) matchesSection(segmentCount int, segmentBitCount BitCount) bool {
	divLen := len(section.divisions)
	return divLen <= segmentCount && (divLen == 0 || section.GetDivision(0).GetBitCount() == segmentBitCount)
}

func (section *addressSectionInternal) matchesAddress(segmentCount int, segmentBitCount BitCount) bool {
	return len(section.divisions) == segmentCount && section.GetDivision(0).GetBitCount() == segmentBitCount
}

func (section *addressSectionInternal) matchesIPv6Section() bool {
	return section.matchesSection(IPv6SegmentCount, IPv6BitsPerSegment)
}

func (section *addressSectionInternal) matchesIPv4Section() bool {
	return section.matchesSection(IPv4SegmentCount, IPv4BitsPerSegment)
}

func (section *addressSectionInternal) matchesIPSection() bool {
	return section.matchesIPv6Section() || section.matchesIPv4Section()
}

func (section *addressSectionInternal) matchesMACSection() bool {
	return section.matchesSection(ExtendedUniqueIdentifier64SegmentCount, MACBitsPerSegment)
}

func (section *addressSectionInternal) matchesIPv6Address() bool {
	return section.matchesAddress(IPv6SegmentCount, IPv6BitsPerSegment)
}

func (section *addressSectionInternal) matchesIPv4Address() bool {
	return section.matchesAddress(IPv4SegmentCount, IPv4BitsPerSegment)
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

func (section *AddressSection) ToIPAddressSection() *IPAddressSection {
	if section == nil || !section.matchesIPSection() {
		return nil
	}
	return (*IPAddressSection)(unsafe.Pointer(section))
}

func (section *AddressSection) ToIPv6AddressSection() *IPv6AddressSection {
	if section == nil || !section.matchesIPv6Section() {
		return nil
	}
	return (*IPv6AddressSection)(unsafe.Pointer(section))
}

func (section *AddressSection) ToIPv4AddressSection() *IPv4AddressSection {
	if section == nil || !section.matchesIPv4Section() {
		return nil
	}
	return (*IPv4AddressSection)(unsafe.Pointer(section))
}

func (section *AddressSection) ToMACAddressSection() *MACAddressSection {
	if section == nil || !section.matchesMACSection() {
		return nil
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

func (section *ipAddressSectionInternal) IsIPv4() bool {
	return section.matchesIPv4Section()
}

func (section *ipAddressSectionInternal) IsIPv6() bool {
	return section.matchesIPv6Section()
}

func (section *ipAddressSectionInternal) GetIPVersion() IPVersion {
	if section.IsIPv4() {
		return IPv4
	}
	return IPv6
}

func (section *ipAddressSectionInternal) GetNetworkPrefixLength() PrefixLen {
	return section.prefixLength
}

func (section *ipAddressSectionInternal) GetBlockMaskPrefixLength(network bool) PrefixLen {
	return nil
	//return addr.GetSection().GetBlockMaskPrefixLength() TODO
}

func (section *ipAddressSectionInternal) ToAddressSection() *AddressSection {
	return (*AddressSection)(unsafe.Pointer(section))
}

//
//
//
// An IPAddress section has segments, which are divisions of equal length and size
type IPAddressSection struct {
	ipAddressSectionInternal
}

func (section *IPAddressSection) ToIPv6AddressSection() *IPv6AddressSection {
	if section == nil {
		return nil
	} else if section.matchesIPv6Section() {
		return (*IPv6AddressSection)(unsafe.Pointer(section))
	}
	return nil
}

func (section *IPAddressSection) ToIPv4AddressSection() *IPv4AddressSection {
	if section == nil {
		return nil
	}
	if section.matchesIPv4Section() {
		return (*IPv4AddressSection)(unsafe.Pointer(section))
	}
	return nil
}

// IPv6AddressSection represents a section of an IPv6 address comprising 0 to 8 IPv6 address segments.
// The zero values is a section with zero segments.
type IPv6AddressSection struct {
	ipAddressSectionInternal
}

func (section *IPv6AddressSection) GetSegment(index int) *IPv6AddressSegment {
	return section.GetDivision(index).ToIPv6AddressSegment()
}

func (section *IPv6AddressSection) ToIPAddressSection() *IPAddressSection {
	return (*IPAddressSection)(unsafe.Pointer(section))
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
	ipAddressSectionInternal
}

func (section *IPv4AddressSection) GetSegment(index int) *IPv4AddressSegment {
	return section.GetDivision(index).ToIPv4AddressSegment()
}

func (section *IPv4AddressSection) ToIPAddressSection() *IPAddressSection {
	return (*IPAddressSection)(unsafe.Pointer(section))
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

//func (section *ipAddressSectionInternal) GetIPVersion() IPVersion (TODO need the MAC equivalent, butcannot remember if there is a MAC equivalent)
//	if section.IsIPv4() {
//		return IPv4
//	}
//	return IPv6
//}

type MACAddressSection struct {
	macAddressSectionInternal
}
