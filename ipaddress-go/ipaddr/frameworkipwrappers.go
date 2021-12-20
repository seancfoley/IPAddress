package ipaddr

// ExtendedIPSegmentSeries wraps either an IPAddress or IPAddressSection.
// ExtendedIPSegmentSeries can be used to write code that works with both IP Addresses and IP Address Sections,
// going further than IPAddressSegmentSeries to offer additional methods, methods with the series types in their signature.
type ExtendedIPSegmentSeries interface {
	IPAddressSegmentSeries

	ToCustomString(stringOptions IPStringOptions) string

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

	ToZeroHostLen(BitCount) (ExtendedIPSegmentSeries, IncompatibleAddressError)
	ToZeroHost() (ExtendedIPSegmentSeries, IncompatibleAddressError)
	ToMaxHostLen(BitCount) (ExtendedIPSegmentSeries, IncompatibleAddressError)
	ToMaxHost() (ExtendedIPSegmentSeries, IncompatibleAddressError)
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
	AdjustPrefixLenZeroed(BitCount) (ExtendedIPSegmentSeries, IncompatibleAddressError)
	SetPrefixLen(BitCount) ExtendedIPSegmentSeries
	SetPrefixLenZeroed(BitCount) (ExtendedIPSegmentSeries, IncompatibleAddressError)
	WithoutPrefixLen() ExtendedIPSegmentSeries

	ReverseBytes() (ExtendedIPSegmentSeries, IncompatibleAddressError)
	ReverseBits(perByte bool) (ExtendedIPSegmentSeries, IncompatibleAddressError)
	ReverseSegments() ExtendedIPSegmentSeries
}

type WrappedIPAddress struct {
	*IPAddress
}

func (w WrappedIPAddress) Unwrap() IPAddressSegmentSeries {
	res := w.IPAddress
	if res == nil {
		return nil
	}
	return res
}

func (w WrappedIPAddress) ToIPv4() IPv4AddressSegmentSeries {
	return w.IPAddress.ToIPv4()
}

func (w WrappedIPAddress) ToIPv6() IPv6AddressSegmentSeries {
	return w.IPAddress.ToIPv6()
}

func (w WrappedIPAddress) GetNetworkMask() ExtendedIPSegmentSeries {
	return WrapIPAddress(w.IPAddress.GetNetworkMask())
}

func (w WrappedIPAddress) GetHostMask() ExtendedIPSegmentSeries {
	return WrapIPAddress(w.IPAddress.GetHostMask())
}

func (w WrappedIPAddress) SequentialBlockIterator() ExtendedIPSegmentSeriesIterator {
	return ipaddressSeriesIterator{w.IPAddress.SequentialBlockIterator()}
}

func (w WrappedIPAddress) BlockIterator(segmentCount int) ExtendedIPSegmentSeriesIterator {
	return ipaddressSeriesIterator{w.IPAddress.BlockIterator(segmentCount)}
}

func (w WrappedIPAddress) Iterator() ExtendedIPSegmentSeriesIterator {
	return ipaddressSeriesIterator{w.IPAddress.Iterator()}
}

func (w WrappedIPAddress) PrefixIterator() ExtendedIPSegmentSeriesIterator {
	return ipaddressSeriesIterator{w.IPAddress.PrefixIterator()}
}

func (w WrappedIPAddress) PrefixBlockIterator() ExtendedIPSegmentSeriesIterator {
	return ipaddressSeriesIterator{w.IPAddress.PrefixBlockIterator()}
}

// creates a sequential block by changing the segment at the given index to have the given lower and upper value,
// and changing the following segments to be full-range
func (w WrappedIPAddress) ToBlock(segmentIndex int, lower, upper SegInt) ExtendedIPSegmentSeries {
	return WrapIPAddress(w.IPAddress.ToBlock(segmentIndex, lower, upper))
}

func (w WrappedIPAddress) ToPrefixBlockLen(bitCount BitCount) ExtendedIPSegmentSeries {
	return WrapIPAddress(w.IPAddress.ToPrefixBlockLen(bitCount))
}

func (w WrappedIPAddress) ToPrefixBlock() ExtendedIPSegmentSeries {
	return WrapIPAddress(w.IPAddress.ToPrefixBlock())
}

func (w WrappedIPAddress) ToZeroHostLen(bitCount BitCount) (ExtendedIPSegmentSeries, IncompatibleAddressError) {
	return wrapIPAddrWithErr(w.IPAddress.ToZeroHostLen(bitCount)) //in IPAddress/Section
}

func (w WrappedIPAddress) ToZeroHost() (ExtendedIPSegmentSeries, IncompatibleAddressError) {
	return wrapIPAddrWithErr(w.IPAddress.ToZeroHost()) // in IPAddress/Section/Segment
}

func (w WrappedIPAddress) ToMaxHostLen(bitCount BitCount) (ExtendedIPSegmentSeries, IncompatibleAddressError) {
	return wrapIPAddrWithErr(w.IPAddress.ToMaxHostLen(bitCount))
}

func (w WrappedIPAddress) ToMaxHost() (ExtendedIPSegmentSeries, IncompatibleAddressError) {
	return wrapIPAddrWithErr(w.IPAddress.ToMaxHost())
}

func (w WrappedIPAddress) ToZeroNetwork() ExtendedIPSegmentSeries {
	return WrapIPAddress(w.IPAddress.ToZeroNetwork()) //IPAddress/Section.  ToZeroHost() is in IPAddress/Section/Segment
}

func (w WrappedIPAddress) Increment(i int64) ExtendedIPSegmentSeries {
	return convIPAddrToIntf(w.IPAddress.Increment(i))
}

func (w WrappedIPAddress) IncrementBoundary(i int64) ExtendedIPSegmentSeries {
	return convIPAddrToIntf(w.IPAddress.IncrementBoundary(i))
}

func (w WrappedIPAddress) GetLower() ExtendedIPSegmentSeries {
	return WrapIPAddress(w.IPAddress.GetLower())
}

func (w WrappedIPAddress) GetUpper() ExtendedIPSegmentSeries {
	return WrapIPAddress(w.IPAddress.GetUpper())
}

func (w WrappedIPAddress) GetSection() *IPAddressSection {
	return w.IPAddress.GetSection()
}

func (w WrappedIPAddress) AssignPrefixForSingleBlock() ExtendedIPSegmentSeries {
	return convIPAddrToIntf(w.IPAddress.AssignPrefixForSingleBlock())
}

func (w WrappedIPAddress) AssignMinPrefixForBlock() ExtendedIPSegmentSeries {
	return WrapIPAddress(w.IPAddress.AssignMinPrefixForBlock())
}

func (w WrappedIPAddress) WithoutPrefixLen() ExtendedIPSegmentSeries {
	return WrapIPAddress(w.IPAddress.WithoutPrefixLen())
}

func (w WrappedIPAddress) SpanWithPrefixBlocks() []ExtendedIPSegmentSeries {
	return w.IPAddress.spanWithPrefixBlocks()
}

func (w WrappedIPAddress) SpanWithSequentialBlocks() []ExtendedIPSegmentSeries {
	return w.IPAddress.spanWithSequentialBlocks()
}

func (w WrappedIPAddress) CoverWithPrefixBlock() ExtendedIPSegmentSeries {
	return w.IPAddress.coverSeriesWithPrefixBlock()
}

func (w WrappedIPAddress) Contains(other ExtendedIPSegmentSeries) bool {
	addr, ok := other.Unwrap().(AddressType)
	return ok && w.IPAddress.Contains(addr)
}

func (w WrappedIPAddress) CompareSize(other ExtendedIPSegmentSeries) int {
	if addr, ok := other.Unwrap().(AddressType); ok {
		return w.IPAddress.CompareSize(addr)
	}
	return w.GetCount().Cmp(other.GetCount())
}

func (w WrappedIPAddress) Equal(other ExtendedIPSegmentSeries) bool {
	addr, ok := other.Unwrap().(AddressType)
	return ok && w.IPAddress.Equal(addr)
}

func (w WrappedIPAddress) SetPrefixLen(prefixLen BitCount) ExtendedIPSegmentSeries {
	return WrapIPAddress(w.IPAddress.SetPrefixLen(prefixLen))
}

func (w WrappedIPAddress) SetPrefixLenZeroed(prefixLen BitCount) (ExtendedIPSegmentSeries, IncompatibleAddressError) {
	return wrapIPAddrWithErr(w.IPAddress.SetPrefixLenZeroed(prefixLen))
}

func (w WrappedIPAddress) AdjustPrefixLen(prefixLen BitCount) ExtendedIPSegmentSeries {
	return WrapIPAddress(w.IPAddress.AdjustPrefixLen(prefixLen))
}

func (w WrappedIPAddress) AdjustPrefixLenZeroed(prefixLen BitCount) (ExtendedIPSegmentSeries, IncompatibleAddressError) {
	return wrapIPAddrWithErr(w.IPAddress.AdjustPrefixLenZeroed(prefixLen))
}

func (w WrappedIPAddress) ReverseBytes() (ExtendedIPSegmentSeries, IncompatibleAddressError) {
	return wrapIPAddrWithErr(w.IPAddress.ReverseBytes())
}

func (w WrappedIPAddress) ReverseBits(perByte bool) (ExtendedIPSegmentSeries, IncompatibleAddressError) {
	return wrapIPAddrWithErr(w.IPAddress.ReverseBits(perByte))
}

func (w WrappedIPAddress) ReverseSegments() ExtendedIPSegmentSeries {
	return WrapIPAddress(w.IPAddress.ReverseSegments())
}

type WrappedIPAddressSection struct {
	*IPAddressSection
}

func (w WrappedIPAddressSection) Unwrap() IPAddressSegmentSeries {
	res := w.IPAddressSection
	if res == nil {
		return nil
	}
	return res
}

func (w WrappedIPAddressSection) ToIPv4() IPv4AddressSegmentSeries {
	return w.IPAddressSection.ToIPv4()
}

func (w WrappedIPAddressSection) ToIPv6() IPv6AddressSegmentSeries {
	return w.IPAddressSection.ToIPv6()
}

func (w WrappedIPAddressSection) GetNetworkMask() ExtendedIPSegmentSeries {
	return WrapIPSection(w.IPAddressSection.GetNetworkMask())
}

func (w WrappedIPAddressSection) GetHostMask() ExtendedIPSegmentSeries {
	return WrapIPSection(w.IPAddressSection.GetHostMask())
}

func (w WrappedIPAddressSection) SequentialBlockIterator() ExtendedIPSegmentSeriesIterator {
	return ipsectionSeriesIterator{w.IPAddressSection.SequentialBlockIterator()}
}

func (w WrappedIPAddressSection) BlockIterator(segmentCount int) ExtendedIPSegmentSeriesIterator {
	return ipsectionSeriesIterator{w.IPAddressSection.BlockIterator(segmentCount)}
}

func (w WrappedIPAddressSection) Iterator() ExtendedIPSegmentSeriesIterator {
	return ipsectionSeriesIterator{w.IPAddressSection.Iterator()}
}

func (w WrappedIPAddressSection) PrefixIterator() ExtendedIPSegmentSeriesIterator {
	return ipsectionSeriesIterator{w.IPAddressSection.PrefixIterator()}
}

func (w WrappedIPAddressSection) PrefixBlockIterator() ExtendedIPSegmentSeriesIterator {
	return ipsectionSeriesIterator{w.IPAddressSection.PrefixBlockIterator()}
}

// creates a sequential block by changing the segment at the given index to have the given lower and upper value,
// and changing the following segments to be full-range
func (w WrappedIPAddressSection) ToBlock(segmentIndex int, lower, upper SegInt) ExtendedIPSegmentSeries {
	return WrapIPSection(w.IPAddressSection.ToBlock(segmentIndex, lower, upper))
}

func (w WrappedIPAddressSection) ToPrefixBlockLen(bitCount BitCount) ExtendedIPSegmentSeries {
	return WrapIPSection(w.IPAddressSection.ToPrefixBlockLen(bitCount))
}

func (w WrappedIPAddressSection) ToPrefixBlock() ExtendedIPSegmentSeries {
	return WrapIPSection(w.IPAddressSection.ToPrefixBlock())
}

func (w WrappedIPAddressSection) ToZeroHostLen(bitCount BitCount) (ExtendedIPSegmentSeries, IncompatibleAddressError) {
	return wrapIPSectWithErr(w.IPAddressSection.ToZeroHostLen(bitCount))
}

func (w WrappedIPAddressSection) ToZeroHost() (ExtendedIPSegmentSeries, IncompatibleAddressError) {
	return wrapIPSectWithErr(w.IPAddressSection.ToZeroHost())
}

func (w WrappedIPAddressSection) ToMaxHostLen(bitCount BitCount) (ExtendedIPSegmentSeries, IncompatibleAddressError) {
	return wrapIPSectWithErr(w.IPAddressSection.ToMaxHostLen(bitCount))
}

func (w WrappedIPAddressSection) ToMaxHost() (ExtendedIPSegmentSeries, IncompatibleAddressError) {
	return wrapIPSectWithErr(w.IPAddressSection.ToMaxHost())
}

func (w WrappedIPAddressSection) ToZeroNetwork() ExtendedIPSegmentSeries {
	return WrapIPSection(w.IPAddressSection.ToZeroNetwork())
}

func (w WrappedIPAddressSection) Increment(i int64) ExtendedIPSegmentSeries {
	return convIPSectToIntf(w.IPAddressSection.Increment(i))
}

func (w WrappedIPAddressSection) IncrementBoundary(i int64) ExtendedIPSegmentSeries {
	return convIPSectToIntf(w.IPAddressSection.IncrementBoundary(i))
}

func (w WrappedIPAddressSection) GetLower() ExtendedIPSegmentSeries {
	return WrapIPSection(w.IPAddressSection.GetLower())
}

func (w WrappedIPAddressSection) GetUpper() ExtendedIPSegmentSeries {
	return WrapIPSection(w.IPAddressSection.GetUpper())
}

func (w WrappedIPAddressSection) GetSection() *IPAddressSection {
	return w.IPAddressSection
}

func (w WrappedIPAddressSection) AssignPrefixForSingleBlock() ExtendedIPSegmentSeries {
	return convIPSectToIntf(w.IPAddressSection.AssignPrefixForSingleBlock())
}

func (w WrappedIPAddressSection) AssignMinPrefixForBlock() ExtendedIPSegmentSeries {
	return WrapIPSection(w.IPAddressSection.AssignMinPrefixForBlock())
}

func (w WrappedIPAddressSection) WithoutPrefixLen() ExtendedIPSegmentSeries {
	return WrapIPSection(w.IPAddressSection.WithoutPrefixLen())
}

func (w WrappedIPAddressSection) SpanWithPrefixBlocks() []ExtendedIPSegmentSeries {
	return w.IPAddressSection.spanWithPrefixBlocks()
}

func (w WrappedIPAddressSection) SpanWithSequentialBlocks() []ExtendedIPSegmentSeries {
	return w.IPAddressSection.spanWithSequentialBlocks()
}

func (w WrappedIPAddressSection) CoverWithPrefixBlock() ExtendedIPSegmentSeries {
	return w.IPAddressSection.coverSeriesWithPrefixBlock()
}

func (w WrappedIPAddressSection) Contains(other ExtendedIPSegmentSeries) bool {
	addr, ok := other.Unwrap().(AddressSectionType)
	return ok && w.IPAddressSection.Contains(addr)
}

func (w WrappedIPAddressSection) Equal(other ExtendedIPSegmentSeries) bool {
	addr, ok := other.Unwrap().(AddressSectionType)
	return ok && w.IPAddressSection.Equal(addr)
}

func (w WrappedIPAddressSection) CompareSize(other ExtendedIPSegmentSeries) int {
	if addr, ok := other.Unwrap().(AddressSectionType); ok {
		return w.IPAddressSection.CompareSize(addr)
	}
	return w.GetCount().Cmp(other.GetCount())
}

func (w WrappedIPAddressSection) SetPrefixLen(prefixLen BitCount) ExtendedIPSegmentSeries {
	return WrapIPSection(w.IPAddressSection.SetPrefixLen(prefixLen))
}

func (w WrappedIPAddressSection) SetPrefixLenZeroed(prefixLen BitCount) (ExtendedIPSegmentSeries, IncompatibleAddressError) {
	return wrapIPSectWithErr(w.IPAddressSection.SetPrefixLenZeroed(prefixLen))
}

func (w WrappedIPAddressSection) AdjustPrefixLen(prefixLen BitCount) ExtendedIPSegmentSeries {
	return WrapIPSection(w.IPAddressSection.AdjustPrefixLen(prefixLen))
}

func (w WrappedIPAddressSection) AdjustPrefixLenZeroed(prefixLen BitCount) (ExtendedIPSegmentSeries, IncompatibleAddressError) {
	return wrapIPSectWithErr(w.IPAddressSection.AdjustPrefixLenZeroed(prefixLen))
}

func (w WrappedIPAddressSection) ReverseBytes() (ExtendedIPSegmentSeries, IncompatibleAddressError) {
	return wrapIPSectWithErr(w.IPAddressSection.ReverseBytes())
}

func (w WrappedIPAddressSection) ReverseBits(perByte bool) (ExtendedIPSegmentSeries, IncompatibleAddressError) {
	return wrapIPSectWithErr(w.IPAddressSection.ReverseBits(perByte))
}

func (w WrappedIPAddressSection) ReverseSegments() ExtendedIPSegmentSeries {
	return WrapIPSection(w.IPAddressSection.ReverseSegments())
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

func wrapIPSectWithErr(section *IPAddressSection, err IncompatibleAddressError) (ExtendedIPSegmentSeries, IncompatibleAddressError) {
	if err == nil {
		return WrapIPSection(section), nil
	}
	return nil, err
}

func wrapIPAddrWithErr(addr *IPAddress, err IncompatibleAddressError) (ExtendedIPSegmentSeries, IncompatibleAddressError) {
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
