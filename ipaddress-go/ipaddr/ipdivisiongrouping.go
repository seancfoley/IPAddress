package ipaddr

import (
//"reflect"
)

//func (grouping *AddressDivisionGrouping) ToDivisionGrouping() *AddressDivisionGrouping {
//	return grouping
//}

type ipaddressDivisionGroupingInternal struct { //TODO rename with capital A
	addressDivisionGroupingInternal //TODO rename with capital A
	//TODO add a few methods: getZeroRangeSegments, getZeroSegments, getZeroSegments(bool), includesZeroHost
}

func (grouping *ipaddressDivisionGroupingInternal) ToDivisionGrouping() *AddressDivisionGrouping {
	return &AddressDivisionGrouping{grouping.addressDivisionGroupingInternal}
}

type IPAddressDivisionGrouping struct {
	ipaddressDivisionGroupingInternal
}

// ToIPDivisionGrouping() converts this division grouping to an IPAddressDivisionGrouping
//func (grouping *AddressDivisionGrouping) ToIPDivisionGrouping() *IPAddressDivisionGrouping {
//	return grouping.toIPDivisionGrouping()
//}

// ToIPSection() converts this division grouping to an IPAddressSection
func (grouping *IPAddressDivisionGrouping) ToIPSection() *IPAddressSection {
	return grouping.toIPSection()
}

//func (grouping *IPAddressDivisionGrouping) ToIPDivisionGrouping() *IPAddressDivisionGrouping {
//	return grouping
//}

// ToIPv4() converts this division grouping to an IPv4 section if it originated as an IPv4 section, otherwise it returns nil
func (grouping *IPAddressDivisionGrouping) ToIPv4() *IPv4AddressSection {
	return grouping.toIPv4()
}

// ToIPv6() converts this division grouping to an IPv6 section if it originated as an IPv6 section, otherwise it returns nil
func (grouping *IPAddressDivisionGrouping) ToIPv6() *IPv6AddressSection {
	return grouping.toIPv6()
}

func (grouping *IPAddressDivisionGrouping) GetIPDivision(index int) (seg *IPAddressDivision) {
	if grouping.checkIndex(index) {
		seg = grouping.divisions[index].ToIPDivision()
	}
	return
}
func (grouping *IPAddressDivisionGrouping) GetDivisionCount() int {
	return len(grouping.divisions)
}
