package ipaddr

// AddrIterator iterates through IP addresses, subnets and ranges
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

// IPv4AddressIterator iterates through IP addresses, subnets and ranges
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

type ipAddrSliceIterator struct {
	addrs []*IPAddress
}

func (iter ipAddrSliceIterator) HasNext() bool {
	return len(iter.addrs) > 0
}

func (iter ipAddrSliceIterator) Next() (res *IPAddress) {
	if iter.HasNext() {
		res = iter.addrs[0]
		iter.addrs = iter.addrs[1:]
	}
	return
}

// IPv4AddressIterator iterates through IPv4 addresses, subnets and ranges
type IPv4AddressIterator interface {
	iteratorBase
	Next() *IPv4Address
}

type ipv4AddressIterator struct {
	AddressIterator
}

func (iter ipv4AddressIterator) Next() *IPv4Address {
	return iter.AddressIterator.Next().ToIPv4Address()
}

type ipv4IPAddressIterator struct {
	IPAddressIterator
}

func (iter ipv4IPAddressIterator) Next() *IPv4Address {
	return iter.IPAddressIterator.Next().ToIPv4Address()
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

type ipv6IPAddressIterator struct {
	IPAddressIterator
}

func (iter ipv6IPAddressIterator) Next() *IPv6Address {
	return iter.IPAddressIterator.Next().ToIPv6Address()
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

type ExtendedSegmentSeriesIterator interface {
	iteratorBase
	Next() ExtendedSegmentSeries
}

type ExtendedIPSegmentSeriesIterator interface {
	iteratorBase
	Next() ExtendedIPSegmentSeries
}

type addressSeriesIterator struct {
	AddressIterator
}

func (iter addressSeriesIterator) Next() ExtendedSegmentSeries {
	return WrappedAddress{iter.AddressIterator.Next()}
}

type ipaddressSeriesIterator struct {
	IPAddressIterator
}

func (iter ipaddressSeriesIterator) Next() ExtendedIPSegmentSeries {
	return WrappedIPAddress{iter.IPAddressIterator.Next()}
}

type sectionSeriesIterator struct {
	SectionIterator
}

func (iter sectionSeriesIterator) Next() ExtendedSegmentSeries {
	return WrappedAddressSection{iter.SectionIterator.Next()}
}

type ipsectionSeriesIterator struct {
	IPSectionIterator
}

func (iter ipsectionSeriesIterator) Next() ExtendedIPSegmentSeries {
	return WrappedIPAddressSection{iter.IPSectionIterator.Next()}
}
