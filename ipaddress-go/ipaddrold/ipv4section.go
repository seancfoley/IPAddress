package ipaddrold

type ipv4AddressSectionInternal struct {
	ipAddressSectionInternal
}

func (grouping *ipv4AddressSectionInternal) ToIPSection() *IPAddressSection {
	return grouping.toIPSection()
}

func (grouping *ipv4AddressSectionInternal) GetIPv4Segment(index int) (seg *IPv4AddressSegment) {
	if grouping.checkIndex(index) {
		seg = grouping.divisions[index].toIPv4()
	}
	return
}

type IPv4AddressSection struct {
	ipv4AddressSectionInternal
}
