package ipaddr

import "github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrerr"

// ExtendedSegmentSeries wraps either an Address or AddressSection.
// ExtendedSegmentSeries can be used to write code that works with both Addresses and Address Sections,
// going further than AddressSegmentSeries to offer additional methods with the series types in their signature.
type ExtendedSegmentSeries interface {
	AddressSegmentSeries

	ToCustomString(stringOptions StringOptions) string

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

	//GetNetworkSection() *AddressSection
	//GetHostSection() *AddressSection
	//GetNetworkSectionLen(BitCount) *AddressSection
	//GetHostSectionLen(BitCount) *AddressSection

	//GetNetworkMask() ExtendedSegmentSeries
	//GetHostMask() ExtendedSegmentSeries

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

	//ToPrefixBlockLen(BitCount) ExtendedSegmentSeries
	ToPrefixBlock() ExtendedSegmentSeries

	//ToZeroHostLen(BitCount) (ExtendedSegmentSeries,addrerr.IncompatibleAddressError)
	//ToZeroHost() (ExtendedSegmentSeries,addrerr.IncompatibleAddressError)
	//ToMaxHostLen(BitCount) (ExtendedSegmentSeries,addrerr.IncompatibleAddressError)
	//ToMaxHost() (ExtendedSegmentSeries,addrerr.IncompatibleAddressError)
	//ToZeroNetwork() ExtendedSegmentSeries

	Increment(int64) ExtendedSegmentSeries
	IncrementBoundary(int64) ExtendedSegmentSeries

	GetLower() ExtendedSegmentSeries
	GetUpper() ExtendedSegmentSeries

	AssignPrefixForSingleBlock() ExtendedSegmentSeries
	AssignMinPrefixForBlock() ExtendedSegmentSeries

	//SequentialBlockIterator() ExtendedSegmentSeriesIterator
	//BlockIterator(segmentCount int) ExtendedSegmentSeriesIterator
	Iterator() ExtendedSegmentSeriesIterator
	//PrefixIterator() ExtendedSegmentSeriesIterator
	PrefixBlockIterator() ExtendedSegmentSeriesIterator

	//SpanWithPrefixBlocks() []ExtendedSegmentSeries
	//SpanWithSequentialBlocks() []ExtendedSegmentSeries

	//CoverWithPrefixBlock() ExtendedSegmentSeries

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

func (w WrappedAddress) Unwrap() AddressSegmentSeries {
	res := w.Address
	if res == nil {
		return nil
	}
	return res
}

func (w WrappedAddress) ToIPv4() IPv4AddressSegmentSeries {
	return w.Address.ToIPv4()
}

func (w WrappedAddress) ToIPv6() IPv6AddressSegmentSeries {
	return w.Address.ToIPv6()
}

func (w WrappedAddress) ToIP() IPAddressSegmentSeries {
	return w.Address.ToIP()
}

func (w WrappedAddress) ToMAC() MACAddressSegmentSeries {
	return w.Address.ToMAC()
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

func (w WrappedAddress) Iterator() ExtendedSegmentSeriesIterator {
	return addressSeriesIterator{w.Address.Iterator()}
}

//func (w WrappedAddress) PrefixIterator() ExtendedSegmentSeriesIterator {
//	return ipaddressSeriesIterator{w.Address.PrefixIterator()}
//}

func (w WrappedAddress) PrefixBlockIterator() ExtendedSegmentSeriesIterator {
	return addressSeriesIterator{w.Address.PrefixBlockIterator()}
}

// creates a sequential block by changing the segment at the given index to have the given lower and upper value,
// and changing the following segments to be full-range
func (w WrappedAddress) ToBlock(segmentIndex int, lower, upper SegInt) ExtendedSegmentSeries {
	return WrapAddress(w.Address.ToBlock(segmentIndex, lower, upper))
}

//func (w WrappedAddress) ToPrefixBlockLen(bitCount BitCount) ExtendedSegmentSeries {
//	return WrappedAddress{w.Address.ToPrefixBlockLen(bitCount)}
//}

func (w WrappedAddress) ToPrefixBlock() ExtendedSegmentSeries {
	return WrapAddress(w.Address.ToPrefixBlock())
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

func (w WrappedAddress) Increment(i int64) ExtendedSegmentSeries {
	return convAddrToIntf(w.Address.Increment(i))
}

func (w WrappedAddress) IncrementBoundary(i int64) ExtendedSegmentSeries {
	return convAddrToIntf(w.Address.IncrementBoundary(i))
}

func (w WrappedAddress) GetLower() ExtendedSegmentSeries {
	return WrapAddress(w.Address.GetLower())
}

func (w WrappedAddress) GetUpper() ExtendedSegmentSeries {
	return WrapAddress(w.Address.GetUpper())
}

func (w WrappedAddress) GetSection() *AddressSection {
	return w.Address.GetSection()
}

func (w WrappedAddress) AssignPrefixForSingleBlock() ExtendedSegmentSeries {
	return convAddrToIntf(w.Address.AssignPrefixForSingleBlock())
}

func (w WrappedAddress) AssignMinPrefixForBlock() ExtendedSegmentSeries {
	return WrapAddress(w.Address.AssignMinPrefixForBlock())
}

func (w WrappedAddress) WithoutPrefixLen() ExtendedSegmentSeries {
	return WrapAddress(w.Address.WithoutPrefixLen())
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

func (w WrappedAddress) Contains(other ExtendedSegmentSeries) bool {
	addr, ok := other.Unwrap().(AddressType)
	return ok && w.Address.Contains(addr)
}

func (w WrappedAddress) Equal(other ExtendedSegmentSeries) bool {
	addr, ok := other.Unwrap().(AddressType)
	return ok && w.Address.Equal(addr)
}

func (w WrappedAddress) CompareSize(other ExtendedSegmentSeries) int {
	if addr, ok := other.Unwrap().(AddressType); ok {
		return w.Address.CompareSize(addr)
	}
	return w.GetCount().Cmp(other.GetCount())
}

func (w WrappedAddress) SetPrefixLen(prefixLen BitCount) ExtendedSegmentSeries {
	return WrapAddress(w.Address.SetPrefixLen(prefixLen))
}

func (w WrappedAddress) SetPrefixLenZeroed(prefixLen BitCount) (ExtendedSegmentSeries, addrerr.IncompatibleAddressError) {
	return wrapAddrWithErr(w.Address.SetPrefixLenZeroed(prefixLen))
}

func (w WrappedAddress) AdjustPrefixLen(prefixLen BitCount) ExtendedSegmentSeries {
	return WrapAddress(w.Address.AdjustPrefixLen(prefixLen))
}

func (w WrappedAddress) AdjustPrefixLenZeroed(prefixLen BitCount) (ExtendedSegmentSeries, addrerr.IncompatibleAddressError) {
	return wrapAddrWithErr(w.Address.AdjustPrefixLenZeroed(prefixLen))
}

func (w WrappedAddress) ReverseBytes() (ExtendedSegmentSeries, addrerr.IncompatibleAddressError) {
	return wrapAddrWithErr(w.Address.ReverseBytes())
}

func (w WrappedAddress) ReverseBits(perByte bool) (ExtendedSegmentSeries, addrerr.IncompatibleAddressError) {
	addr, err := w.Address.ReverseBits(perByte)
	if err != nil {
		return nil, err
	}
	return WrapAddress(addr), nil
}

func (w WrappedAddress) ReverseSegments() ExtendedSegmentSeries {
	return WrapAddress(w.Address.ReverseSegments())
}

type WrappedAddressSection struct {
	*AddressSection
}

func (w WrappedAddressSection) Unwrap() AddressSegmentSeries {
	res := w.AddressSection
	if res == nil {
		return nil
	}
	return res
}

func (w WrappedAddressSection) ToIPv4() IPv4AddressSegmentSeries {
	return w.AddressSection.ToIPv4()
}

func (w WrappedAddressSection) ToIPv6() IPv6AddressSegmentSeries {
	return w.AddressSection.ToIPv6()
}

func (w WrappedAddressSection) ToIP() IPAddressSegmentSeries {
	return w.AddressSection.ToIP()
}

func (w WrappedAddressSection) ToMAC() MACAddressSegmentSeries {
	return w.AddressSection.ToMAC()
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

func (w WrappedAddressSection) Iterator() ExtendedSegmentSeriesIterator {
	return sectionSeriesIterator{w.AddressSection.Iterator()}
}

//func (w WrappedAddressSection) PrefixIterator() ExtendedSegmentSeriesIterator {
//	return ipsectionSeriesIterator{w.AddressSection.PrefixIterator()}
//}

func (w WrappedAddressSection) PrefixBlockIterator() ExtendedSegmentSeriesIterator {
	return sectionSeriesIterator{w.AddressSection.PrefixBlockIterator()}
}

// creates a sequential block by changing the segment at the given index to have the given lower and upper value,
// and changing the following segments to be full-range
func (w WrappedAddressSection) ToBlock(segmentIndex int, lower, upper SegInt) ExtendedSegmentSeries {
	return WrapSection(w.AddressSection.ToBlock(segmentIndex, lower, upper))
}

//func (w WrappedAddressSection) ToPrefixBlockLen(bitCount BitCount) ExtendedSegmentSeries {
//	return WrappedAddressSection{w.AddressSection.ToPrefixBlockLen(bitCount)}
//}

func (w WrappedAddressSection) ToPrefixBlock() ExtendedSegmentSeries {
	return WrapSection(w.AddressSection.ToPrefixBlock())
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

func (w WrappedAddressSection) Increment(i int64) ExtendedSegmentSeries {
	return convSectToIntf(w.AddressSection.Increment(i))
}

func (w WrappedAddressSection) IncrementBoundary(i int64) ExtendedSegmentSeries {
	return convSectToIntf(w.AddressSection.IncrementBoundary(i))
}

func (w WrappedAddressSection) GetLower() ExtendedSegmentSeries {
	return WrapSection(w.AddressSection.GetLower())
}

func (w WrappedAddressSection) GetUpper() ExtendedSegmentSeries {
	return WrapSection(w.AddressSection.GetUpper())
}

func (w WrappedAddressSection) GetSection() *AddressSection {
	return w.AddressSection
}

func (w WrappedAddressSection) AssignPrefixForSingleBlock() ExtendedSegmentSeries {
	return convSectToIntf(w.AddressSection.AssignPrefixForSingleBlock())
}

func (w WrappedAddressSection) AssignMinPrefixForBlock() ExtendedSegmentSeries {
	return WrapSection(w.AddressSection.AssignMinPrefixForBlock())
}

func (w WrappedAddressSection) WithoutPrefixLen() ExtendedSegmentSeries {
	return WrapSection(w.AddressSection.WithoutPrefixLen())
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

func (w WrappedAddressSection) Contains(other ExtendedSegmentSeries) bool {
	addr, ok := other.Unwrap().(AddressSectionType)
	return ok && w.AddressSection.Contains(addr)
}

func (w WrappedAddressSection) CompareSize(other ExtendedSegmentSeries) int {
	if addr, ok := other.Unwrap().(AddressSectionType); ok {
		return w.AddressSection.CompareSize(addr)
	}
	return w.GetCount().Cmp(other.GetCount())
}

func (w WrappedAddressSection) Equal(other ExtendedSegmentSeries) bool {
	addr, ok := other.Unwrap().(AddressSectionType)
	return ok && w.AddressSection.Equal(addr)
}

func (w WrappedAddressSection) SetPrefixLen(prefixLen BitCount) ExtendedSegmentSeries {
	return WrapSection(w.AddressSection.SetPrefixLen(prefixLen))
}

func (w WrappedAddressSection) SetPrefixLenZeroed(prefixLen BitCount) (ExtendedSegmentSeries, addrerr.IncompatibleAddressError) {
	return wrapSectWithErr(w.AddressSection.SetPrefixLenZeroed(prefixLen))
}

func (w WrappedAddressSection) AdjustPrefixLen(adjustment BitCount) ExtendedSegmentSeries {
	return WrapSection(w.AddressSection.AdjustPrefixLen(adjustment))
}

func (w WrappedAddressSection) AdjustPrefixLenZeroed(adjustment BitCount) (ExtendedSegmentSeries, addrerr.IncompatibleAddressError) {
	return wrapSectWithErr(w.AddressSection.AdjustPrefixLenZeroed(adjustment))
}

func (w WrappedAddressSection) ReverseBytes() (ExtendedSegmentSeries, addrerr.IncompatibleAddressError) {
	return wrapSectWithErr(w.AddressSection.ReverseBytes())
}

func (w WrappedAddressSection) ReverseBits(perByte bool) (ExtendedSegmentSeries, addrerr.IncompatibleAddressError) {
	return wrapSectWithErr(w.AddressSection.ReverseBits(perByte))
}

func (w WrappedAddressSection) ReverseSegments() ExtendedSegmentSeries {
	return WrapSection(w.AddressSection.ReverseSegments())
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
