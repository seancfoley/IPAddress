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

import (
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrerr"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrstr"
)

// ExtendedSegmentSeries wraps either an Address or AddressSection.
// ExtendedSegmentSeries can be used to write code that works with both Addresses and Address Sections,
// going further than AddressSegmentSeries to offer additional methods with the series types in their signature.
type ExtendedSegmentSeries interface {
	AddressSegmentSeries

	ToCustomString(stringOptions addrstr.StringOptions) string

	// Unwrap returns the wrapped *Address or *AddressSection as an interface, AddressSegmentSeries
	Unwrap() AddressSegmentSeries

	Equal(ExtendedSegmentSeries) bool
	Contains(ExtendedSegmentSeries) bool
	CompareSize(ExtendedSegmentSeries) int

	// GetSection returns the full address section
	GetSection() *AddressSection

	// GetTrailingSection returns an ending subsection of the full address section
	GetTrailingSection(index int) *AddressSection

	// GetSubSection returns a subsection of the full address section
	GetSubSection(index, endIndex int) *AddressSection

	GetSegment(index int) *AddressSegment
	GetSegments() []*AddressSegment
	CopySegments(segs []*AddressSegment) (count int)
	CopySubSegments(start, end int, segs []*AddressSegment) (count int)

	IsIP() bool
	IsIPv4() bool
	IsIPv6() bool
	IsMAC() bool

	ToIP() IPAddressSegmentSeries
	ToIPv4() IPv4AddressSegmentSeries
	ToIPv6() IPv6AddressSegmentSeries
	ToMAC() MACAddressSegmentSeries

	// ToBlock creates a sequential block by changing the segment at the given index to have the given lower and upper value,
	// and changing the following segments to be full-range
	ToBlock(segmentIndex int, lower, upper SegInt) ExtendedSegmentSeries

	ToPrefixBlock() ExtendedSegmentSeries

	Increment(int64) ExtendedSegmentSeries
	IncrementBoundary(int64) ExtendedSegmentSeries

	GetLower() ExtendedSegmentSeries
	GetUpper() ExtendedSegmentSeries

	AssignPrefixForSingleBlock() ExtendedSegmentSeries
	AssignMinPrefixForBlock() ExtendedSegmentSeries

	Iterator() ExtendedSegmentSeriesIterator
	PrefixIterator() ExtendedSegmentSeriesIterator
	PrefixBlockIterator() ExtendedSegmentSeriesIterator

	AdjustPrefixLen(BitCount) ExtendedSegmentSeries
	AdjustPrefixLenZeroed(BitCount) (ExtendedSegmentSeries, addrerr.IncompatibleAddressError)
	SetPrefixLen(BitCount) ExtendedSegmentSeries
	SetPrefixLenZeroed(BitCount) (ExtendedSegmentSeries, addrerr.IncompatibleAddressError)
	WithoutPrefixLen() ExtendedSegmentSeries

	ReverseBytes() (ExtendedSegmentSeries, addrerr.IncompatibleAddressError)
	ReverseBits(perByte bool) (ExtendedSegmentSeries, addrerr.IncompatibleAddressError)
	ReverseSegments() ExtendedSegmentSeries
}

// WrappedAddress is the implementation of ExtendedSegmentSeries for Address
type WrappedAddress struct {
	*Address
}

func (addr WrappedAddress) Unwrap() AddressSegmentSeries {
	res := addr.Address
	if res == nil {
		return nil
	}
	return res
}

func (addr WrappedAddress) ToIPv4() IPv4AddressSegmentSeries {
	return addr.Address.ToIPv4()
}

func (addr WrappedAddress) ToIPv6() IPv6AddressSegmentSeries {
	return addr.Address.ToIPv6()
}

func (addr WrappedAddress) ToIP() IPAddressSegmentSeries {
	return addr.Address.ToIP()
}

func (addr WrappedAddress) ToMAC() MACAddressSegmentSeries {
	return addr.Address.ToMAC()
}

//func (w WrappedAddress) GetNetworkMask() ExtendedSegmentSeries {
//	return WrappedAddress{w.Address.GetNetworkMask()}
//}
//
//func (w WrappedAddress) GetHostMask() ExtendedSegmentSeries {
//	return WrappedAddress{w.Address.GetHostMask()}
//}
//
//func (w WrappedAddress) SequentialBlockIterator() ExtendedSegmentSeriesIterator {
//	return ipaddressSeriesIterator{w.Address.SequentialBlockIterator()}
//}
//
//func (w WrappedAddress) BlockIterator(segmentCount int) ExtendedSegmentSeriesIterator {
//	return ipaddressSeriesIterator{w.Address.BlockIterator(segmentCount)}
//}

func (addr WrappedAddress) Iterator() ExtendedSegmentSeriesIterator {
	return addressSeriesIterator{addr.Address.Iterator()}
}

func (addr WrappedAddress) PrefixIterator() ExtendedSegmentSeriesIterator {
	return addressSeriesIterator{addr.Address.PrefixIterator()}
}

func (addr WrappedAddress) PrefixBlockIterator() ExtendedSegmentSeriesIterator {
	return addressSeriesIterator{addr.Address.PrefixBlockIterator()}
}

// creates a sequential block by changing the segment at the given index to have the given lower and upper value,
// and changing the following segments to be full-range
func (addr WrappedAddress) ToBlock(segmentIndex int, lower, upper SegInt) ExtendedSegmentSeries {
	return WrapAddress(addr.Address.ToBlock(segmentIndex, lower, upper))
}

//func (w WrappedAddress) ToPrefixBlockLen(bitCount BitCount) ExtendedSegmentSeries {
//	return WrappedAddress{w.Address.ToPrefixBlockLen(bitCount)}
//}

func (addr WrappedAddress) ToPrefixBlock() ExtendedSegmentSeries {
	return WrapAddress(addr.Address.ToPrefixBlock())
}

//func (w WrappedAddress) ToZeroHostLen(bitCount BitCount) (ExtendedSegmentSeries,addrerr.IncompatibleAddressError) {
//	return wrapAddrWithErr(w.Address.ToZeroHostLen(bitCount)) //in Address/Section
//}
//
//func (w WrappedAddress) ToZeroHost() (ExtendedSegmentSeries,addrerr.IncompatibleAddressError) {
//	return wrapAddrWithErr(w.Address.ToZeroHost()) // in Address/Section/Segment
//}
//
//func (w WrappedAddress) ToMaxHostLen(bitCount BitCount) (ExtendedSegmentSeries,addrerr.IncompatibleAddressError) {
//	return wrapAddrWithErr(w.Address.ToMaxHostLen(bitCount))
//}
//
//func (w WrappedAddress) ToMaxHost() (ExtendedSegmentSeries,addrerr.IncompatibleAddressError) {
//	return wrapAddrWithErr(w.Address.ToMaxHost())
//}
//
//func (w WrappedAddress) ToZeroNetwork() ExtendedSegmentSeries {
//	return WrappedAddress{w.Address.ToZeroNetwork()} //Address/Section.  ToZeroHost() is in Address/Section/Segment
//}

func (addr WrappedAddress) Increment(i int64) ExtendedSegmentSeries {
	return convAddrToIntf(addr.Address.Increment(i))
}

func (addr WrappedAddress) IncrementBoundary(i int64) ExtendedSegmentSeries {
	return convAddrToIntf(addr.Address.IncrementBoundary(i))
}

func (addr WrappedAddress) GetLower() ExtendedSegmentSeries {
	return WrapAddress(addr.Address.GetLower())
}

func (addr WrappedAddress) GetUpper() ExtendedSegmentSeries {
	return WrapAddress(addr.Address.GetUpper())
}

func (addr WrappedAddress) GetSection() *AddressSection {
	return addr.Address.GetSection()
}

func (addr WrappedAddress) AssignPrefixForSingleBlock() ExtendedSegmentSeries {
	return convAddrToIntf(addr.Address.AssignPrefixForSingleBlock())
}

func (addr WrappedAddress) AssignMinPrefixForBlock() ExtendedSegmentSeries {
	return WrapAddress(addr.Address.AssignMinPrefixForBlock())
}

func (addr WrappedAddress) WithoutPrefixLen() ExtendedSegmentSeries {
	return WrapAddress(addr.Address.WithoutPrefixLen())
}

//func (w WrappedAddress) SpanWithPrefixBlocks() []ExtendedSegmentSeries {
//	return w.Address.spanWithPrefixBlocks()
//}
//
//func (w WrappedAddress) SpanWithSequentialBlocks() []ExtendedSegmentSeries {
//	return w.Address.spanWithSequentialBlocks()
//}
//
//func (w WrappedAddress) CoverWithPrefixBlock() ExtendedSegmentSeries {
//	return w.Address.coverSeriesWithPrefixBlock()
//}

func (addr WrappedAddress) Contains(other ExtendedSegmentSeries) bool {
	a, ok := other.Unwrap().(AddressType)
	return ok && addr.Address.Contains(a)
}

func (addr WrappedAddress) Equal(other ExtendedSegmentSeries) bool {
	a, ok := other.Unwrap().(AddressType)
	return ok && addr.Address.Equal(a)
}

func (addr WrappedAddress) CompareSize(other ExtendedSegmentSeries) int {
	if a, ok := other.Unwrap().(AddressType); ok {
		return addr.Address.CompareSize(a)
	}
	return addr.GetCount().Cmp(other.GetCount())
}

func (addr WrappedAddress) SetPrefixLen(prefixLen BitCount) ExtendedSegmentSeries {
	return WrapAddress(addr.Address.SetPrefixLen(prefixLen))
}

func (addr WrappedAddress) SetPrefixLenZeroed(prefixLen BitCount) (ExtendedSegmentSeries, addrerr.IncompatibleAddressError) {
	return wrapAddrWithErr(addr.Address.SetPrefixLenZeroed(prefixLen))
}

func (addr WrappedAddress) AdjustPrefixLen(prefixLen BitCount) ExtendedSegmentSeries {
	return WrapAddress(addr.Address.AdjustPrefixLen(prefixLen))
}

func (addr WrappedAddress) AdjustPrefixLenZeroed(prefixLen BitCount) (ExtendedSegmentSeries, addrerr.IncompatibleAddressError) {
	return wrapAddrWithErr(addr.Address.AdjustPrefixLenZeroed(prefixLen))
}

func (addr WrappedAddress) ReverseBytes() (ExtendedSegmentSeries, addrerr.IncompatibleAddressError) {
	return wrapAddrWithErr(addr.Address.ReverseBytes())
}

func (addr WrappedAddress) ReverseBits(perByte bool) (ExtendedSegmentSeries, addrerr.IncompatibleAddressError) {
	a, err := addr.Address.ReverseBits(perByte)
	if err != nil {
		return nil, err
	}
	return WrapAddress(a), nil
}

func (addr WrappedAddress) ReverseSegments() ExtendedSegmentSeries {
	return WrapAddress(addr.Address.ReverseSegments())
}

type WrappedAddressSection struct {
	*AddressSection
}

func (section WrappedAddressSection) Unwrap() AddressSegmentSeries {
	res := section.AddressSection
	if res == nil {
		return nil
	}
	return res
}

func (section WrappedAddressSection) ToIPv4() IPv4AddressSegmentSeries {
	return section.AddressSection.ToIPv4()
}

func (section WrappedAddressSection) ToIPv6() IPv6AddressSegmentSeries {
	return section.AddressSection.ToIPv6()
}

func (section WrappedAddressSection) ToIP() IPAddressSegmentSeries {
	return section.AddressSection.ToIP()
}

func (section WrappedAddressSection) ToMAC() MACAddressSegmentSeries {
	return section.AddressSection.ToMAC()
}

//func (w WrappedAddressSection) GetNetworkMask() ExtendedSegmentSeries {
//	return WrappedAddressSection{w.AddressSection.GetNetworkMask()}
//}
//
//func (w WrappedAddressSection) GetHostMask() ExtendedSegmentSeries {
//	return WrappedAddressSection{w.AddressSection.GetHostMask()}
//}
//
//func (w WrappedAddressSection) SequentialBlockIterator() ExtendedSegmentSeriesIterator {
//	return ipsectionSeriesIterator{w.AddressSection.SequentialBlockIterator()}
//}
//
//func (w WrappedAddressSection) BlockIterator(segmentCount int) ExtendedSegmentSeriesIterator {
//	return ipsectionSeriesIterator{w.AddressSection.BlockIterator(segmentCount)}
//}

func (section WrappedAddressSection) Iterator() ExtendedSegmentSeriesIterator {
	return sectionSeriesIterator{section.AddressSection.Iterator()}
}

func (section WrappedAddressSection) PrefixIterator() ExtendedSegmentSeriesIterator {
	return sectionSeriesIterator{section.AddressSection.PrefixIterator()}
}

func (section WrappedAddressSection) PrefixBlockIterator() ExtendedSegmentSeriesIterator {
	return sectionSeriesIterator{section.AddressSection.PrefixBlockIterator()}
}

// creates a sequential block by changing the segment at the given index to have the given lower and upper value,
// and changing the following segments to be full-range
func (section WrappedAddressSection) ToBlock(segmentIndex int, lower, upper SegInt) ExtendedSegmentSeries {
	return WrapSection(section.AddressSection.ToBlock(segmentIndex, lower, upper))
}

//func (w WrappedAddressSection) ToPrefixBlockLen(bitCount BitCount) ExtendedSegmentSeries {
//	return WrappedAddressSection{w.AddressSection.ToPrefixBlockLen(bitCount)}
//}

func (section WrappedAddressSection) ToPrefixBlock() ExtendedSegmentSeries {
	return WrapSection(section.AddressSection.ToPrefixBlock())
}

//func (w WrappedAddressSection) ToZeroHostLen(bitCount BitCount) (ExtendedSegmentSeries,addrerr.IncompatibleAddressError) {
//	return wrapSectWithErr(w.AddressSection.ToZeroHostLen(bitCount))
//}
//
//func (w WrappedAddressSection) ToZeroHost() (ExtendedSegmentSeries,addrerr.IncompatibleAddressError) {
//	return wrapSectWithErr(w.AddressSection.ToZeroHost())
//}
//
//func (w WrappedAddressSection) ToMaxHostLen(bitCount BitCount) (ExtendedSegmentSeries,addrerr.IncompatibleAddressError) {
//	return wrapSectWithErr(w.AddressSection.ToMaxHostLen(bitCount))
//}
//
//func (w WrappedAddressSection) ToMaxHost() (ExtendedSegmentSeries,addrerr.IncompatibleAddressError) {
//	return wrapSectWithErr(w.AddressSection.ToMaxHost())
//}
//
//func (w WrappedAddressSection) ToZeroNetwork() ExtendedSegmentSeries {
//	return WrappedAddressSection{w.AddressSection.ToZeroNetwork()}
//}

func (section WrappedAddressSection) Increment(i int64) ExtendedSegmentSeries {
	return convSectToIntf(section.AddressSection.Increment(i))
}

func (section WrappedAddressSection) IncrementBoundary(i int64) ExtendedSegmentSeries {
	return convSectToIntf(section.AddressSection.IncrementBoundary(i))
}

func (section WrappedAddressSection) GetLower() ExtendedSegmentSeries {
	return WrapSection(section.AddressSection.GetLower())
}

func (section WrappedAddressSection) GetUpper() ExtendedSegmentSeries {
	return WrapSection(section.AddressSection.GetUpper())
}

func (section WrappedAddressSection) GetSection() *AddressSection {
	return section.AddressSection
}

func (section WrappedAddressSection) AssignPrefixForSingleBlock() ExtendedSegmentSeries {
	return convSectToIntf(section.AddressSection.AssignPrefixForSingleBlock())
}

func (section WrappedAddressSection) AssignMinPrefixForBlock() ExtendedSegmentSeries {
	return WrapSection(section.AddressSection.AssignMinPrefixForBlock())
}

func (section WrappedAddressSection) WithoutPrefixLen() ExtendedSegmentSeries {
	return WrapSection(section.AddressSection.WithoutPrefixLen())
}

//func (w WrappedAddressSection) SpanWithPrefixBlocks() []ExtendedSegmentSeries {
//	return w.AddressSection.spanWithPrefixBlocks()
//}
//
//func (w WrappedAddressSection) SpanWithSequentialBlocks() []ExtendedSegmentSeries {
//	return w.AddressSection.spanWithSequentialBlocks()
//}
//
//func (w WrappedAddressSection) CoverWithPrefixBlock() ExtendedSegmentSeries {
//	return w.AddressSection.coverSeriesWithPrefixBlock()
//}

func (section WrappedAddressSection) Contains(other ExtendedSegmentSeries) bool {
	s, ok := other.Unwrap().(AddressSectionType)
	return ok && section.AddressSection.Contains(s)
}

func (section WrappedAddressSection) CompareSize(other ExtendedSegmentSeries) int {
	if s, ok := other.Unwrap().(AddressSectionType); ok {
		return section.AddressSection.CompareSize(s)
	}
	return section.GetCount().Cmp(other.GetCount())
}

func (section WrappedAddressSection) Equal(other ExtendedSegmentSeries) bool {
	s, ok := other.Unwrap().(AddressSectionType)
	return ok && section.AddressSection.Equal(s)
}

func (section WrappedAddressSection) SetPrefixLen(prefixLen BitCount) ExtendedSegmentSeries {
	return WrapSection(section.AddressSection.SetPrefixLen(prefixLen))
}

func (section WrappedAddressSection) SetPrefixLenZeroed(prefixLen BitCount) (ExtendedSegmentSeries, addrerr.IncompatibleAddressError) {
	return wrapSectWithErr(section.AddressSection.SetPrefixLenZeroed(prefixLen))
}

func (section WrappedAddressSection) AdjustPrefixLen(adjustment BitCount) ExtendedSegmentSeries {
	return WrapSection(section.AddressSection.AdjustPrefixLen(adjustment))
}

func (section WrappedAddressSection) AdjustPrefixLenZeroed(adjustment BitCount) (ExtendedSegmentSeries, addrerr.IncompatibleAddressError) {
	return wrapSectWithErr(section.AddressSection.AdjustPrefixLenZeroed(adjustment))
}

func (section WrappedAddressSection) ReverseBytes() (ExtendedSegmentSeries, addrerr.IncompatibleAddressError) {
	return wrapSectWithErr(section.AddressSection.ReverseBytes())
}

func (section WrappedAddressSection) ReverseBits(perByte bool) (ExtendedSegmentSeries, addrerr.IncompatibleAddressError) {
	return wrapSectWithErr(section.AddressSection.ReverseBits(perByte))
}

func (section WrappedAddressSection) ReverseSegments() ExtendedSegmentSeries {
	return WrapSection(section.AddressSection.ReverseSegments())
}

var _ ExtendedSegmentSeries = WrappedAddress{}
var _ ExtendedSegmentSeries = WrappedAddressSection{}

// In go, a nil value is not coverted to a nil interface, it is converted to a non-nil interface instance with underlying value nil
func convAddrToIntf(addr *Address) ExtendedSegmentSeries {
	if addr == nil {
		return nil
	}
	return WrapAddress(addr)
}

func convSectToIntf(sect *AddressSection) ExtendedSegmentSeries {
	if sect == nil {
		return nil
	}
	return WrapSection(sect)
}

func wrapSectWithErr(section *AddressSection, err addrerr.IncompatibleAddressError) (ExtendedSegmentSeries, addrerr.IncompatibleAddressError) {
	if err == nil {
		return WrapSection(section), nil
	}
	return nil, err
}

func wrapAddrWithErr(addr *Address, err addrerr.IncompatibleAddressError) (ExtendedSegmentSeries, addrerr.IncompatibleAddressError) {
	if err == nil {
		return WrapAddress(addr), nil
	}
	return nil, err
}

func WrapAddress(addr *Address) WrappedAddress {
	return WrappedAddress{addr}
}

func WrapSection(section *AddressSection) WrappedAddressSection {
	return WrappedAddressSection{section}
}
