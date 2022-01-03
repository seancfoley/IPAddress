//
// Copyright 2020-2022 Sean C Foley
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

import (
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrerr"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrstr"
)

// ExtendedIPSegmentSeries wraps either an IPAddress or IPAddressSection.
// ExtendedIPSegmentSeries can be used to write code that works with both IP Addresses and IP Address Sections,
// going further than IPAddressSegmentSeries to offer additional methods, methods with the series types in their signature.
type ExtendedIPSegmentSeries interface {
	IPAddressSegmentSeries

	ToCustomString(stringOptions addrstr.IPStringOptions) string

	// Unwrap returns the wrapped *IPAddress or *IPAddressSection as an interface, IPAddressSegmentSeries
	Unwrap() IPAddressSegmentSeries

	Equal(ExtendedIPSegmentSeries) bool
	Contains(ExtendedIPSegmentSeries) bool
	CompareSize(ExtendedIPSegmentSeries) int

	// GetSection returns the full address section
	GetSection() *IPAddressSection

	// GetTrailingSection returns an ending subsection of the full address section
	GetTrailingSection(index int) *IPAddressSection

	// GetSubSection returns a subsection of the full address section
	GetSubSection(index, endIndex int) *IPAddressSection

	GetNetworkSection() *IPAddressSection
	GetHostSection() *IPAddressSection
	GetNetworkSectionLen(BitCount) *IPAddressSection
	GetHostSectionLen(BitCount) *IPAddressSection

	GetNetworkMask() ExtendedIPSegmentSeries
	GetHostMask() ExtendedIPSegmentSeries

	GetSegment(index int) *IPAddressSegment
	GetSegments() []*IPAddressSegment
	CopySegments(segs []*IPAddressSegment) (count int)
	CopySubSegments(start, end int, segs []*IPAddressSegment) (count int)

	IsIPv4() bool
	IsIPv6() bool

	ToIPv4() IPv4AddressSegmentSeries
	ToIPv6() IPv6AddressSegmentSeries

	// ToBlock creates a sequential block by changing the segment at the given index to have the given lower and upper value,
	// and changing the following segments to be full-range
	ToBlock(segmentIndex int, lower, upper SegInt) ExtendedIPSegmentSeries

	ToPrefixBlockLen(BitCount) ExtendedIPSegmentSeries
	ToPrefixBlock() ExtendedIPSegmentSeries

	ToZeroHostLen(BitCount) (ExtendedIPSegmentSeries, addrerr.IncompatibleAddressError)
	ToZeroHost() (ExtendedIPSegmentSeries, addrerr.IncompatibleAddressError)
	ToMaxHostLen(BitCount) (ExtendedIPSegmentSeries, addrerr.IncompatibleAddressError)
	ToMaxHost() (ExtendedIPSegmentSeries, addrerr.IncompatibleAddressError)
	ToZeroNetwork() ExtendedIPSegmentSeries

	Increment(int64) ExtendedIPSegmentSeries
	IncrementBoundary(int64) ExtendedIPSegmentSeries

	GetLower() ExtendedIPSegmentSeries
	GetUpper() ExtendedIPSegmentSeries

	AssignPrefixForSingleBlock() ExtendedIPSegmentSeries
	AssignMinPrefixForBlock() ExtendedIPSegmentSeries

	SequentialBlockIterator() ExtendedIPSegmentSeriesIterator
	BlockIterator(segmentCount int) ExtendedIPSegmentSeriesIterator
	Iterator() ExtendedIPSegmentSeriesIterator
	PrefixIterator() ExtendedIPSegmentSeriesIterator
	PrefixBlockIterator() ExtendedIPSegmentSeriesIterator

	SpanWithPrefixBlocks() []ExtendedIPSegmentSeries
	SpanWithSequentialBlocks() []ExtendedIPSegmentSeries

	CoverWithPrefixBlock() ExtendedIPSegmentSeries

	AdjustPrefixLen(BitCount) ExtendedIPSegmentSeries
	AdjustPrefixLenZeroed(BitCount) (ExtendedIPSegmentSeries, addrerr.IncompatibleAddressError)
	SetPrefixLen(BitCount) ExtendedIPSegmentSeries
	SetPrefixLenZeroed(BitCount) (ExtendedIPSegmentSeries, addrerr.IncompatibleAddressError)
	WithoutPrefixLen() ExtendedIPSegmentSeries

	ReverseBytes() (ExtendedIPSegmentSeries, addrerr.IncompatibleAddressError)
	ReverseBits(perByte bool) (ExtendedIPSegmentSeries, addrerr.IncompatibleAddressError)
	ReverseSegments() ExtendedIPSegmentSeries
}

type WrappedIPAddress struct {
	*IPAddress
}

func (addr WrappedIPAddress) Unwrap() IPAddressSegmentSeries {
	res := addr.IPAddress
	if res == nil {
		return nil
	}
	return res
}

func (addr WrappedIPAddress) ToIPv4() IPv4AddressSegmentSeries {
	return addr.IPAddress.ToIPv4()
}

func (addr WrappedIPAddress) ToIPv6() IPv6AddressSegmentSeries {
	return addr.IPAddress.ToIPv6()
}

func (addr WrappedIPAddress) GetNetworkMask() ExtendedIPSegmentSeries {
	return WrapIPAddress(addr.IPAddress.GetNetworkMask())
}

func (addr WrappedIPAddress) GetHostMask() ExtendedIPSegmentSeries {
	return WrapIPAddress(addr.IPAddress.GetHostMask())
}

func (addr WrappedIPAddress) SequentialBlockIterator() ExtendedIPSegmentSeriesIterator {
	return ipaddressSeriesIterator{addr.IPAddress.SequentialBlockIterator()}
}

func (addr WrappedIPAddress) BlockIterator(segmentCount int) ExtendedIPSegmentSeriesIterator {
	return ipaddressSeriesIterator{addr.IPAddress.BlockIterator(segmentCount)}
}

func (addr WrappedIPAddress) Iterator() ExtendedIPSegmentSeriesIterator {
	return ipaddressSeriesIterator{addr.IPAddress.Iterator()}
}

func (addr WrappedIPAddress) PrefixIterator() ExtendedIPSegmentSeriesIterator {
	return ipaddressSeriesIterator{addr.IPAddress.PrefixIterator()}
}

func (addr WrappedIPAddress) PrefixBlockIterator() ExtendedIPSegmentSeriesIterator {
	return ipaddressSeriesIterator{addr.IPAddress.PrefixBlockIterator()}
}

// creates a sequential block by changing the segment at the given index to have the given lower and upper value,
// and changing the following segments to be full-range
func (addr WrappedIPAddress) ToBlock(segmentIndex int, lower, upper SegInt) ExtendedIPSegmentSeries {
	return WrapIPAddress(addr.IPAddress.ToBlock(segmentIndex, lower, upper))
}

func (addr WrappedIPAddress) ToPrefixBlockLen(bitCount BitCount) ExtendedIPSegmentSeries {
	return WrapIPAddress(addr.IPAddress.ToPrefixBlockLen(bitCount))
}

func (addr WrappedIPAddress) ToPrefixBlock() ExtendedIPSegmentSeries {
	return WrapIPAddress(addr.IPAddress.ToPrefixBlock())
}

func (addr WrappedIPAddress) ToZeroHostLen(bitCount BitCount) (ExtendedIPSegmentSeries, addrerr.IncompatibleAddressError) {
	return wrapIPAddrWithErr(addr.IPAddress.ToZeroHostLen(bitCount)) //in IPAddress/Section
}

func (addr WrappedIPAddress) ToZeroHost() (ExtendedIPSegmentSeries, addrerr.IncompatibleAddressError) {
	return wrapIPAddrWithErr(addr.IPAddress.ToZeroHost()) // in IPAddress/Section/Segment
}

func (addr WrappedIPAddress) ToMaxHostLen(bitCount BitCount) (ExtendedIPSegmentSeries, addrerr.IncompatibleAddressError) {
	return wrapIPAddrWithErr(addr.IPAddress.ToMaxHostLen(bitCount))
}

func (addr WrappedIPAddress) ToMaxHost() (ExtendedIPSegmentSeries, addrerr.IncompatibleAddressError) {
	return wrapIPAddrWithErr(addr.IPAddress.ToMaxHost())
}

func (addr WrappedIPAddress) ToZeroNetwork() ExtendedIPSegmentSeries {
	return WrapIPAddress(addr.IPAddress.ToZeroNetwork()) //IPAddress/Section.  ToZeroHost() is in IPAddress/Section/Segment
}

func (addr WrappedIPAddress) Increment(i int64) ExtendedIPSegmentSeries {
	return convIPAddrToIntf(addr.IPAddress.Increment(i))
}

func (addr WrappedIPAddress) IncrementBoundary(i int64) ExtendedIPSegmentSeries {
	return convIPAddrToIntf(addr.IPAddress.IncrementBoundary(i))
}

func (addr WrappedIPAddress) GetLower() ExtendedIPSegmentSeries {
	return WrapIPAddress(addr.IPAddress.GetLower())
}

func (addr WrappedIPAddress) GetUpper() ExtendedIPSegmentSeries {
	return WrapIPAddress(addr.IPAddress.GetUpper())
}

func (addr WrappedIPAddress) GetSection() *IPAddressSection {
	return addr.IPAddress.GetSection()
}

func (addr WrappedIPAddress) AssignPrefixForSingleBlock() ExtendedIPSegmentSeries {
	return convIPAddrToIntf(addr.IPAddress.AssignPrefixForSingleBlock())
}

func (addr WrappedIPAddress) AssignMinPrefixForBlock() ExtendedIPSegmentSeries {
	return WrapIPAddress(addr.IPAddress.AssignMinPrefixForBlock())
}

func (addr WrappedIPAddress) WithoutPrefixLen() ExtendedIPSegmentSeries {
	return WrapIPAddress(addr.IPAddress.WithoutPrefixLen())
}

func (addr WrappedIPAddress) SpanWithPrefixBlocks() []ExtendedIPSegmentSeries {
	return addr.IPAddress.spanWithPrefixBlocks()
}

func (addr WrappedIPAddress) SpanWithSequentialBlocks() []ExtendedIPSegmentSeries {
	return addr.IPAddress.spanWithSequentialBlocks()
}

func (addr WrappedIPAddress) CoverWithPrefixBlock() ExtendedIPSegmentSeries {
	return addr.IPAddress.coverSeriesWithPrefixBlock()
}

func (addr WrappedIPAddress) Contains(other ExtendedIPSegmentSeries) bool {
	a, ok := other.Unwrap().(AddressType)
	return ok && addr.IPAddress.Contains(a)
}

func (addr WrappedIPAddress) CompareSize(other ExtendedIPSegmentSeries) int {
	if a, ok := other.Unwrap().(AddressType); ok {
		return addr.IPAddress.CompareSize(a)
	}
	return addr.GetCount().Cmp(other.GetCount())
}

func (addr WrappedIPAddress) Equal(other ExtendedIPSegmentSeries) bool {
	a, ok := other.Unwrap().(AddressType)
	return ok && addr.IPAddress.Equal(a)
}

func (addr WrappedIPAddress) SetPrefixLen(prefixLen BitCount) ExtendedIPSegmentSeries {
	return WrapIPAddress(addr.IPAddress.SetPrefixLen(prefixLen))
}

func (addr WrappedIPAddress) SetPrefixLenZeroed(prefixLen BitCount) (ExtendedIPSegmentSeries, addrerr.IncompatibleAddressError) {
	return wrapIPAddrWithErr(addr.IPAddress.SetPrefixLenZeroed(prefixLen))
}

func (addr WrappedIPAddress) AdjustPrefixLen(prefixLen BitCount) ExtendedIPSegmentSeries {
	return WrapIPAddress(addr.IPAddress.AdjustPrefixLen(prefixLen))
}

func (addr WrappedIPAddress) AdjustPrefixLenZeroed(prefixLen BitCount) (ExtendedIPSegmentSeries, addrerr.IncompatibleAddressError) {
	return wrapIPAddrWithErr(addr.IPAddress.AdjustPrefixLenZeroed(prefixLen))
}

func (addr WrappedIPAddress) ReverseBytes() (ExtendedIPSegmentSeries, addrerr.IncompatibleAddressError) {
	return wrapIPAddrWithErr(addr.IPAddress.ReverseBytes())
}

func (addr WrappedIPAddress) ReverseBits(perByte bool) (ExtendedIPSegmentSeries, addrerr.IncompatibleAddressError) {
	return wrapIPAddrWithErr(addr.IPAddress.ReverseBits(perByte))
}

func (addr WrappedIPAddress) ReverseSegments() ExtendedIPSegmentSeries {
	return WrapIPAddress(addr.IPAddress.ReverseSegments())
}

type WrappedIPAddressSection struct {
	*IPAddressSection
}

func (section WrappedIPAddressSection) Unwrap() IPAddressSegmentSeries {
	res := section.IPAddressSection
	if res == nil {
		return nil
	}
	return res
}

func (section WrappedIPAddressSection) ToIPv4() IPv4AddressSegmentSeries {
	return section.IPAddressSection.ToIPv4()
}

func (section WrappedIPAddressSection) ToIPv6() IPv6AddressSegmentSeries {
	return section.IPAddressSection.ToIPv6()
}

func (section WrappedIPAddressSection) GetNetworkMask() ExtendedIPSegmentSeries {
	return WrapIPSection(section.IPAddressSection.GetNetworkMask())
}

func (section WrappedIPAddressSection) GetHostMask() ExtendedIPSegmentSeries {
	return WrapIPSection(section.IPAddressSection.GetHostMask())
}

func (section WrappedIPAddressSection) SequentialBlockIterator() ExtendedIPSegmentSeriesIterator {
	return ipsectionSeriesIterator{section.IPAddressSection.SequentialBlockIterator()}
}

func (section WrappedIPAddressSection) BlockIterator(segmentCount int) ExtendedIPSegmentSeriesIterator {
	return ipsectionSeriesIterator{section.IPAddressSection.BlockIterator(segmentCount)}
}

func (section WrappedIPAddressSection) Iterator() ExtendedIPSegmentSeriesIterator {
	return ipsectionSeriesIterator{section.IPAddressSection.Iterator()}
}

func (section WrappedIPAddressSection) PrefixIterator() ExtendedIPSegmentSeriesIterator {
	return ipsectionSeriesIterator{section.IPAddressSection.PrefixIterator()}
}

func (section WrappedIPAddressSection) PrefixBlockIterator() ExtendedIPSegmentSeriesIterator {
	return ipsectionSeriesIterator{section.IPAddressSection.PrefixBlockIterator()}
}

// creates a sequential block by changing the segment at the given index to have the given lower and upper value,
// and changing the following segments to be full-range
func (section WrappedIPAddressSection) ToBlock(segmentIndex int, lower, upper SegInt) ExtendedIPSegmentSeries {
	return WrapIPSection(section.IPAddressSection.ToBlock(segmentIndex, lower, upper))
}

func (section WrappedIPAddressSection) ToPrefixBlockLen(bitCount BitCount) ExtendedIPSegmentSeries {
	return WrapIPSection(section.IPAddressSection.ToPrefixBlockLen(bitCount))
}

func (section WrappedIPAddressSection) ToPrefixBlock() ExtendedIPSegmentSeries {
	return WrapIPSection(section.IPAddressSection.ToPrefixBlock())
}

func (section WrappedIPAddressSection) ToZeroHostLen(bitCount BitCount) (ExtendedIPSegmentSeries, addrerr.IncompatibleAddressError) {
	return wrapIPSectWithErr(section.IPAddressSection.ToZeroHostLen(bitCount))
}

func (section WrappedIPAddressSection) ToZeroHost() (ExtendedIPSegmentSeries, addrerr.IncompatibleAddressError) {
	return wrapIPSectWithErr(section.IPAddressSection.ToZeroHost())
}

func (section WrappedIPAddressSection) ToMaxHostLen(bitCount BitCount) (ExtendedIPSegmentSeries, addrerr.IncompatibleAddressError) {
	return wrapIPSectWithErr(section.IPAddressSection.ToMaxHostLen(bitCount))
}

func (section WrappedIPAddressSection) ToMaxHost() (ExtendedIPSegmentSeries, addrerr.IncompatibleAddressError) {
	return wrapIPSectWithErr(section.IPAddressSection.ToMaxHost())
}

func (section WrappedIPAddressSection) ToZeroNetwork() ExtendedIPSegmentSeries {
	return WrapIPSection(section.IPAddressSection.ToZeroNetwork())
}

func (section WrappedIPAddressSection) Increment(i int64) ExtendedIPSegmentSeries {
	return convIPSectToIntf(section.IPAddressSection.Increment(i))
}

func (section WrappedIPAddressSection) IncrementBoundary(i int64) ExtendedIPSegmentSeries {
	return convIPSectToIntf(section.IPAddressSection.IncrementBoundary(i))
}

func (section WrappedIPAddressSection) GetLower() ExtendedIPSegmentSeries {
	return WrapIPSection(section.IPAddressSection.GetLower())
}

func (section WrappedIPAddressSection) GetUpper() ExtendedIPSegmentSeries {
	return WrapIPSection(section.IPAddressSection.GetUpper())
}

func (section WrappedIPAddressSection) GetSection() *IPAddressSection {
	return section.IPAddressSection
}

func (section WrappedIPAddressSection) AssignPrefixForSingleBlock() ExtendedIPSegmentSeries {
	return convIPSectToIntf(section.IPAddressSection.AssignPrefixForSingleBlock())
}

func (section WrappedIPAddressSection) AssignMinPrefixForBlock() ExtendedIPSegmentSeries {
	return WrapIPSection(section.IPAddressSection.AssignMinPrefixForBlock())
}

func (section WrappedIPAddressSection) WithoutPrefixLen() ExtendedIPSegmentSeries {
	return WrapIPSection(section.IPAddressSection.WithoutPrefixLen())
}

func (section WrappedIPAddressSection) SpanWithPrefixBlocks() []ExtendedIPSegmentSeries {
	return section.IPAddressSection.spanWithPrefixBlocks()
}

func (section WrappedIPAddressSection) SpanWithSequentialBlocks() []ExtendedIPSegmentSeries {
	return section.IPAddressSection.spanWithSequentialBlocks()
}

func (section WrappedIPAddressSection) CoverWithPrefixBlock() ExtendedIPSegmentSeries {
	return section.IPAddressSection.coverSeriesWithPrefixBlock()
}

func (section WrappedIPAddressSection) Contains(other ExtendedIPSegmentSeries) bool {
	s, ok := other.Unwrap().(AddressSectionType)
	return ok && section.IPAddressSection.Contains(s)
}

func (section WrappedIPAddressSection) Equal(other ExtendedIPSegmentSeries) bool {
	s, ok := other.Unwrap().(AddressSectionType)
	return ok && section.IPAddressSection.Equal(s)
}

func (section WrappedIPAddressSection) CompareSize(other ExtendedIPSegmentSeries) int {
	if s, ok := other.Unwrap().(AddressSectionType); ok {
		return section.IPAddressSection.CompareSize(s)
	}
	return section.GetCount().Cmp(other.GetCount())
}

func (section WrappedIPAddressSection) SetPrefixLen(prefixLen BitCount) ExtendedIPSegmentSeries {
	return WrapIPSection(section.IPAddressSection.SetPrefixLen(prefixLen))
}

func (section WrappedIPAddressSection) SetPrefixLenZeroed(prefixLen BitCount) (ExtendedIPSegmentSeries, addrerr.IncompatibleAddressError) {
	return wrapIPSectWithErr(section.IPAddressSection.SetPrefixLenZeroed(prefixLen))
}

func (section WrappedIPAddressSection) AdjustPrefixLen(prefixLen BitCount) ExtendedIPSegmentSeries {
	return WrapIPSection(section.IPAddressSection.AdjustPrefixLen(prefixLen))
}

func (section WrappedIPAddressSection) AdjustPrefixLenZeroed(prefixLen BitCount) (ExtendedIPSegmentSeries, addrerr.IncompatibleAddressError) {
	return wrapIPSectWithErr(section.IPAddressSection.AdjustPrefixLenZeroed(prefixLen))
}

func (section WrappedIPAddressSection) ReverseBytes() (ExtendedIPSegmentSeries, addrerr.IncompatibleAddressError) {
	return wrapIPSectWithErr(section.IPAddressSection.ReverseBytes())
}

func (section WrappedIPAddressSection) ReverseBits(perByte bool) (ExtendedIPSegmentSeries, addrerr.IncompatibleAddressError) {
	return wrapIPSectWithErr(section.IPAddressSection.ReverseBits(perByte))
}

func (section WrappedIPAddressSection) ReverseSegments() ExtendedIPSegmentSeries {
	return WrapIPSection(section.IPAddressSection.ReverseSegments())
}

var _ ExtendedIPSegmentSeries = WrappedIPAddress{}
var _ ExtendedIPSegmentSeries = WrappedIPAddressSection{}

// In go, a nil value is not coverted to a nil interface, it is converted to a non-nil interface instance with underlying value nil
func convIPAddrToIntf(addr *IPAddress) ExtendedIPSegmentSeries {
	if addr == nil {
		return nil
	}
	return WrapIPAddress(addr)
}

func convIPSectToIntf(sect *IPAddressSection) ExtendedIPSegmentSeries {
	if sect == nil {
		return nil
	}
	return WrapIPSection(sect)
}

func wrapIPSectWithErr(section *IPAddressSection, err addrerr.IncompatibleAddressError) (ExtendedIPSegmentSeries, addrerr.IncompatibleAddressError) {
	if err == nil {
		return WrapIPSection(section), nil
	}
	return nil, err
}

func wrapIPAddrWithErr(addr *IPAddress, err addrerr.IncompatibleAddressError) (ExtendedIPSegmentSeries, addrerr.IncompatibleAddressError) {
	if err == nil {
		return WrapIPAddress(addr), nil
	}
	return nil, err
}

func WrapIPAddress(addr *IPAddress) WrappedIPAddress {
	return WrappedIPAddress{addr}
}

func WrapIPSection(section *IPAddressSection) WrappedIPAddressSection {
	return WrappedIPAddressSection{section}
}
