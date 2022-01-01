//
// Copyright 2020-2021 Sean C Foley
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package ipaddr

// AddrIterator iterates through IP addresses, subnets and ranges
type AddressIterator interface {
	HasNext
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

func nilAddrIterator() AddressIterator {
	return &singleAddrIterator{}
}

func addrIterator(
	single bool,
	original *Address,
	prefixLen PrefixLen,
	valsAreMultiple bool,
	iterator SegmentsIterator) AddressIterator {
	if single {
		return &singleAddrIterator{original: original}
	}
	//var zone Zone= original.zone
	//if original != nil {
	//	zone = original.zone
	//}
	return multiAddrIterator{
		SectionIterator: &multiSectionIterator{
			original:        original.section,
			iterator:        iterator,
			valsAreMultiple: valsAreMultiple,
			prefixLen:       prefixLen,
		},
		zone: original.zone,
	}
}

func prefixAddrIterator(
	single bool,
	original *Address,
	prefixLen PrefixLen,
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
			original:  original.section,
			iterator:  iterator,
			prefixLen: prefixLen,
		},
		zone: zone,
	}
}

// this one is used by the sequential ranges
func rangeAddrIterator(
	single bool,
	original *Address,
	prefixLen PrefixLen,
	valsAreMultiple bool,
	iterator SegmentsIterator) AddressIterator {
	return addrIterator(single, original, prefixLen, valsAreMultiple, iterator)
}

// IPv4AddressIterator iterates through IP addresses, subnets and ranges
type IPAddressIterator interface {
	HasNext
	Next() *IPAddress
}

type ipAddrIterator struct {
	AddressIterator
}

func (iter ipAddrIterator) Next() *IPAddress {
	return iter.AddressIterator.Next().ToIP()
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
	HasNext
	Next() *IPv4Address
}

type ipv4AddressIterator struct {
	AddressIterator
}

func (iter ipv4AddressIterator) Next() *IPv4Address {
	return iter.AddressIterator.Next().ToIPv4()
}

type ipv4IPAddressIterator struct {
	IPAddressIterator
}

func (iter ipv4IPAddressIterator) Next() *IPv4Address {
	return iter.IPAddressIterator.Next().ToIPv4()
}

// IPv6AddressIterator iterates through IPv4 addresses, subnets and ranges
type IPv6AddressIterator interface {
	HasNext
	Next() *IPv6Address
}

type ipv6AddressIterator struct {
	AddressIterator
}

func (iter ipv6AddressIterator) Next() *IPv6Address {
	return iter.AddressIterator.Next().ToIPv6()
}

type ipv6IPAddressIterator struct {
	IPAddressIterator
}

func (iter ipv6IPAddressIterator) Next() *IPv6Address {
	return iter.IPAddressIterator.Next().ToIPv6()
}

// MACAddressIterator iterates through MACSize addresses, subnets and ranges
type MACAddressIterator interface {
	HasNext
	Next() *MACAddress
}

type macAddressIterator struct {
	AddressIterator
}

func (iter macAddressIterator) Next() *MACAddress {
	return iter.AddressIterator.Next().ToMAC()
}

type ExtendedSegmentSeriesIterator interface {
	HasNext
	Next() ExtendedSegmentSeries
}

type ExtendedIPSegmentSeriesIterator interface {
	HasNext
	Next() ExtendedIPSegmentSeries
}

type addressSeriesIterator struct {
	AddressIterator
}

func (iter addressSeriesIterator) Next() ExtendedSegmentSeries {
	return WrapAddress(iter.AddressIterator.Next())
}

type ipaddressSeriesIterator struct {
	IPAddressIterator
}

func (iter ipaddressSeriesIterator) Next() ExtendedIPSegmentSeries {
	return iter.IPAddressIterator.Next().Wrap()
}

type sectionSeriesIterator struct {
	SectionIterator
}

func (iter sectionSeriesIterator) Next() ExtendedSegmentSeries {
	return WrapSection(iter.SectionIterator.Next())
}

type ipsectionSeriesIterator struct {
	IPSectionIterator
}

func (iter ipsectionSeriesIterator) Next() ExtendedIPSegmentSeries {
	return WrapIPSection(iter.IPSectionIterator.Next())
}

type UnwrappedIPAddressIterator struct {
	IPAddressIterator
}

func (iter UnwrappedIPAddressIterator) Next() *Address {
	return iter.IPAddressIterator.Next().ToAddressBase()
}
