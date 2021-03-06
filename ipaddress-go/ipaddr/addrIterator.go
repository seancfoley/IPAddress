package ipaddr

type AddressIterator interface {
	HasNext() bool
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
	*multiSectionIterator
	zone Zone
}

func (it multiAddrIterator) Next() (res *Address) {
	if it.HasNext() {
		segs := it.iterator.Next()
		res = createIteratedAddress(it.creator, segs, it.prefixLength, it.zone)
	}
	return
}

func addrIterator(
	useOriginal bool,
	original *Address,
	creator ParsedAddressCreator,
	iterator SegmentsIterator,
	prefixLength PrefixLen) AddressIterator {
	if useOriginal {
		return &singleAddrIterator{original: original}
	}
	return multiAddrIterator{
		multiSectionIterator: &multiSectionIterator{
			creator:      creator,
			iterator:     iterator,
			prefixLength: prefixLength,
		},
		zone: original.zone,
	}
}

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

type IPv4AddrIterator interface {
	iteratorBase
	Next() *IPv4Address
}

type ipv4AddressIterator struct {
	AddressIterator
}

func (iter ipv4AddressIterator) Next() *IPv4Address {
	return iter.AddressIterator.Next().ToIPv4Address()
}

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

func createIteratedAddress(creator ParsedAddressCreator, next []*AddressDivision, prefixLength PrefixLen, zone Zone) *Address {
	return creator.createAddressInternal(createIteratedSection(creator, next, prefixLength), zone)
}
