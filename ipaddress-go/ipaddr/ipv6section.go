package ipaddr

import (
//"reflect"
)

type ipv6AddressSectionInternal struct {
	ipAddressSectionInternal
}

func (grouping *ipv6AddressSectionInternal) ToIPSection() *IPAddressSection {
	return grouping.toIPSection()
}

func (grouping *ipv6AddressSectionInternal) GetIPv6Segment(index int) (seg *IPv6AddressSegment) {
	if grouping.checkIndex(index) {
		seg = grouping.divisions[index].toIPv6()
	}
	return
}

type IPv6AddressSection struct {
	ipv6AddressSectionInternal
}
