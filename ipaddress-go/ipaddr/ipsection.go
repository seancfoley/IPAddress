package ipaddr

import (
//"reflect"
)

type ipAddressSectionInternal struct {
	ipaddressDivisionGroupingInternal //TODO rename with capital A
	//this will have a few fields most likely
	//TODO add a few methods: getSegmentCount(), etc
}

func (grouping *ipAddressSectionInternal) toIPSection() *IPAddressSection {
	grouping.assignDefaultValues()
	switch grouping.divisionType {
	case ipaddressSegmentType, ipv4addressSegmentType, ipv6addressSegmentType:
		return &IPAddressSection{*grouping}
	default:
		return nil
	}
}

// ToIPDivisionGrouping() converts this division grouping to an IPAddressDivisionGrouping
func (grouping *ipAddressSectionInternal) ToIPDivisionGrouping() *IPAddressDivisionGrouping {
	return grouping.toIPDivisionGrouping()
}

func (grouping *ipAddressSectionInternal) GetSegmentCount() int {
	return len(grouping.divisions)
}

type IPAddressSection struct {
	ipAddressSectionInternal
}

// ToIPSection() converts this division grouping to an IPAddressSection
//func (grouping *AddressDivisionGrouping) ToIPSection() *IPAddressSection {
//	return grouping.IPAddressDivisionGrouping()
//}

//func (grouping *IPAddressSection) ToIPSection() *IPAddressSection {
//	return grouping
//}

// ToIPv4() converts this division grouping to an IPv4 section if it originated as an IPv4 section, otherwise it returns nil
func (grouping *IPAddressSection) ToIPv4() *IPv4AddressSection {
	grouping.assignDefaultValues()
	if grouping.divisionType == ipv4addressSegmentType {
		return &IPv4AddressSection{ipv4AddressSectionInternal{grouping.ipAddressSectionInternal}}
	}
	return nil
}

// ToIPv6() converts this division grouping to an IPv6 section if it originated as an IPv6 section, otherwise it returns nil
func (grouping *IPAddressSection) ToIPv6() *IPv6AddressSection {
	grouping.assignDefaultValues()
	if grouping.divisionType == ipv6addressSegmentType {
		return &IPv6AddressSection{ipv6AddressSectionInternal{grouping.ipAddressSectionInternal}}
	}
	return nil
}

func (grouping *IPAddressSection) GetSegment(index int) (seg *IPAddressSegment) {
	if grouping.checkIndex(index) {
		seg = grouping.divisions[index].ToIPSegment()
	}
	return
}
