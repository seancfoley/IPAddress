package ipaddr

import "math/big"

type PrefixLen *int

type boolSetting struct {
	value, isSet bool
}

type valueCache struct {
	cachedCount, cachedPrefixCount big.Int // use BitLen() or len(x.Bits()) to check if value is set, or maybe check for 0
	lowerBytes, upperBytes         []byte  // TODO use net.IP for the same in address
	isMultiple                     boolSetting
}

type AddressDivisionGrouping struct {
	divisions    []AddressDivision
	prefixLength PrefixLen // must align with the divisions if they store prefix lengths
	cache        *valueCache
}

func (grouping AddressDivisionGrouping) GetDivisionCount() int {
	return len(grouping.divisions)
}

// GetDivision returns the division or panics if the index is negative, matches or exceeds the number of divisions
func (grouping AddressDivisionGrouping) GetDivision(index int) AddressDivision {
	return grouping.divisions[index]
}

// hasNoDivisions() returns whether this grouping is the zero grouping,
// which is what you get when contructing a grouping or section with no divisions
func (grouping AddressDivisionGrouping) hasNoDivisions() bool {
	return grouping.divisions == nil
}

// ToAddressSection converts to an address section.
// If the conversion cannot happen due to division size or count, the result will be the zero value.
func (grouping AddressDivisionGrouping) ToAddressSection() AddressSection {
	bitCount := 0
	for i, div := range grouping.divisions { // all divisions must be equal size and have an exact number of bytes
		if i == 0 {
			bitCount = div.GetBitCount()
			if bitCount%8 != 0 {
				return AddressSection{}
			}
		} else if bitCount != div.GetBitCount() {
			return AddressSection{}
		}
	}
	return AddressSection{grouping}
}

func (grouping AddressDivisionGrouping) IsIPv4() bool {
	return grouping.ToIPAddressSection().IsIPv4()
}

func (grouping AddressDivisionGrouping) ToIPAddressSection() IPAddressSection {
	return grouping.ToAddressSection().ToIPAddressSection()
}

func (grouping AddressDivisionGrouping) ToIPv6AddressSection() IPv6AddressSection {
	return grouping.ToIPAddressSection().ToIPv6AddressSection()
}

func (grouping AddressDivisionGrouping) ToIPv4AddressSection() IPv4AddressSection {
	return grouping.ToIPAddressSection().ToIPv4AddressSection()
}

//////////////////////////////////////////////////////////////////
//
//
//
type AddressSection struct {
	AddressDivisionGrouping
}

func (section AddressSection) GetSegmentCount() int {
	return section.GetDivisionCount()
}

func (section AddressSection) matchesSection(segmentCount, segmentBitCount int) bool {
	divLen := len(section.divisions)
	return divLen <= segmentCount && (divLen == 0 || section.GetDivision(0).GetBitCount() == segmentBitCount)
}

func (section AddressSection) matchesAddress(segmentCount, segmentBitCount int) bool {
	return len(section.divisions) == segmentCount && section.GetDivision(0).GetBitCount() == segmentBitCount
}

func (section AddressSection) matchesIPv6Section() bool {
	return section.matchesSection(IPv6SegmentCount, IPv6BitsPerSegment)
}

func (section AddressSection) matchesIPv4Section() bool {
	return section.matchesSection(IPv4SegmentCount, IPv4BitsPerSegment)
}

func (section AddressSection) matchesIPv6Address() bool {
	return section.matchesAddress(IPv6SegmentCount, IPv6BitsPerSegment)
}

func (section AddressSection) matchesIPv4Address() bool {
	return section.matchesAddress(IPv4SegmentCount, IPv4BitsPerSegment)
}

func (section AddressSection) ToAddressDivisionGrouping() AddressDivisionGrouping {
	return section.AddressDivisionGrouping
}

func (section AddressSection) ToAddressSection() AddressSection {
	return section
}

func (section AddressSection) ToIPAddressSection() IPAddressSection {
	divCount := section.GetDivisionCount()
	if divCount == IPv4SegmentCount {
		if section.GetDivision(0).GetBitCount() != IPv4BitsPerSegment {
			return IPAddressSection{}
		}
	} else if divCount == IPv6SegmentCount {
		if section.GetDivision(0).GetBitCount() != IPv6BitsPerSegment {
			return IPAddressSection{}
		}
	} else {
		return IPAddressSection{}
	}
	return IPAddressSection{section}
}

func (section AddressSection) ToIPv6AddressSection() IPv6AddressSection {
	return section.ToIPAddressSection().ToIPv6AddressSection()
}

func (section AddressSection) ToIPv4AddressSection() IPv4AddressSection {
	return section.ToIPAddressSection().ToIPv4AddressSection()
}

//
//
//
// An IPAddress section has segments, which are divisions of equal length and size
type IPAddressSection struct {
	AddressSection //TODO you need the same indirection as swith address addressInternal
}

func (section IPAddressSection) ToIPAddressSection() IPAddressSection {
	return section
}

func (section IPAddressSection) GetSegment(index int) IPAddressSegment {
	return section.GetDivision(index).ToIPAddressSegment()
}

func (section IPAddressSection) ToIPv6AddressSection() IPv6AddressSection {
	if section.matchesIPv6Section() {
		return IPv6AddressSection{section}
	}
	return IPv6AddressSection{}
}

func (section IPAddressSection) ToIPv4AddressSection() IPv4AddressSection {
	if section.matchesIPv4Section() {
		return IPv4AddressSection{section}
	}
	return IPv4AddressSection{}
}

// IPv6AddressSection represents a section of an IPv6 address comprising 0 to 8 IPv6 address segments.
// The zero values is a section with zero segments.
type IPv6AddressSection struct {
	IPAddressSection //TODO you need the same indirection as swith address ipAddressInternal
}

func (section IPv6AddressSection) ToIPv6AddressSection() IPv6AddressSection {
	return section
}

// IPv4AddressSection represents a section of an IPv4 address comprising 0 to 4 IPv4 address segments.
// The zero values is a section with zero segments.
type IPv4AddressSection struct {
	IPAddressSection
}

func (section IPv4AddressSection) ToIPv4AddressSection() IPv4AddressSection {
	return section
}
