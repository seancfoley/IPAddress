package ipaddr

// IPAddrIterator iterates through IP addresses, subnets and ranges
type AddressIterator interface {
	iteratorBase
	Next() *Address
}

type singleAddrIterator struct {
	original *Address
}

func (it *singleAddrIterator) HasNext() bool {
	return it.original != nil
}

func (it *singleAddrIterator) Next() (res *Address) {
	if it.HasNext() {
		res = it.original
		it.original = nil
	}
	return
}

type multiAddrIterator struct {
	SectionIterator
	zone Zone
}

func (it multiAddrIterator) Next() (res *Address) {
	if it.HasNext() {
		sect := it.SectionIterator.Next()
		res = createAddress(sect, it.zone)
	}
	return
}

func addrIterator(
	single bool,
	original *Address,
	valsAreMultiple bool,
	iterator SegmentsIterator) AddressIterator {
	if single {
		return &singleAddrIterator{original: original}
	}
	var zone Zone
	if original != nil {
		zone = original.zone
	}
	return multiAddrIterator{
		SectionIterator: &multiSectionIterator{
			original:        original.section,
			iterator:        iterator,
			valsAreMultiple: valsAreMultiple,
		},
		zone: zone,
	}
}

func prefixAddrIterator(
	single bool,
	original *Address,
	iterator SegmentsIterator) AddressIterator {
	if single {
		return &singleAddrIterator{original: original}
	}
	var zone Zone
	if original != nil {
		zone = original.zone
	}
	return multiAddrIterator{
		SectionIterator: &prefixSectionIterator{
			original: original.section,
			iterator: iterator,
		},
		zone: zone,
	}
}

// this one is used by the sequential ranges
func rangeAddrIterator(
	single bool,
	original *Address,
	valsAreMultiple bool,
	iterator SegmentsIterator) AddressIterator {
	return addrIterator(single, original, valsAreMultiple, iterator)
}

// IPv4AddrIterator iterates through IP addresses, subnets and ranges
type IPAddressIterator interface {
	iteratorBase
	Next() *IPAddress
}

type ipAddrIterator struct {
	AddressIterator
}

func (iter ipAddrIterator) Next() *IPAddress {
	return iter.AddressIterator.Next().ToIPAddress()
}

// IPv4AddressIterator iterates through IPv4 addresses, subnets and ranges
type IPv4AddrIterator interface { //TODO rename to IPv4AddressIterator
	iteratorBase
	Next() *IPv4Address
}

type ipv4AddressIterator struct {
	AddressIterator
}

func (iter ipv4AddressIterator) Next() *IPv4Address {
	return iter.AddressIterator.Next().ToIPv4Address()
}

// IPv6AddressIterator iterates through IPv4 addresses, subnets and ranges
type IPv6AddressIterator interface {
	iteratorBase
	Next() *IPv6Address
}

type ipv6AddressIterator struct {
	AddressIterator
}

func (iter ipv6AddressIterator) Next() *IPv6Address {
	return iter.AddressIterator.Next().ToIPv6Address()
}

// MACAddressIterator iterates through MAC addresses, subnets and ranges
type MACAddressIterator interface {
	iteratorBase
	Next() *MACAddress
}

type macAddressIterator struct {
	AddressIterator
}

func (iter macAddressIterator) Next() *MACAddress {
	return iter.AddressIterator.Next().ToMACAddress()
}
