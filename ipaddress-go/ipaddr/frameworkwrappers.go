package ipaddr

// ExtendedIPSegmentSeries can be used to write code that works on either IP Addresses or IP Address Sections,
// going further than IPAddressSegmentSeries to offer additional methods with series types in their signature
type ExtendedIPSegmentSeries interface {
	IPAddressSegmentSeries

	// Unwrap returns the wrapped section or address as an IPAddressSegmentSeries
	Unwrap() IPAddressSegmentSeries

	// not sure about the return types on these 5, probably should be *IPAddressSection?  Because the wrapper types are geared for that type anyway
	//GetSection() AddressSectionType  //TODO

	//GetNetworkSection() AddressSectionType  //TODO

	//GetHostSection() AddressSectionType  //TODO

	//GetNetworkSectionLen(BitCount) AddressSectionType  //TODO

	//GetHostSectionLen(BitCount) AddressSectionType  //TODO
	//

	//GetNetworkMask() ExtendedIPSegmentSeries  //TODO

	//GetHostMask() ExtendedIPSegmentSeries  //TODO

	// creates a sequential block by changing the segment at the given index to have the given lower and upper value,
	// and changing the following segments to be full-range
	ToBlock(segmentIndex int, lower, upper SegInt) ExtendedIPSegmentSeries // see Java createSequentialBlockSection

	ToPrefixBlockLen(BitCount) ExtendedIPSegmentSeries

	ToPrefixBlock() ExtendedIPSegmentSeries

	ToZeroHostLen(BitCount) (ExtendedIPSegmentSeries, IncompatibleAddressError)

	ToZeroHost() (ExtendedIPSegmentSeries, IncompatibleAddressError)

	ToMaxHostLen(BitCount) (ExtendedIPSegmentSeries, IncompatibleAddressError)

	ToMaxHost() (ExtendedIPSegmentSeries, IncompatibleAddressError)

	ToZeroNetwork() ExtendedIPSegmentSeries

	Increment(int64) ExtendedIPSegmentSeries

	GetLower() ExtendedIPSegmentSeries

	GetUpper() ExtendedIPSegmentSeries

	AssignPrefixForSingleBlock() ExtendedIPSegmentSeries

	//AssignMinPrefixForBlock() ExtendedIPSegmentSeries  //TODO uses GetMinPrefixLengthForBlock I presume which we have already

	SequentialBlockIterator() ExtendedIPSegmentSeriesIterator

	BlockIterator(segmentCount int) ExtendedIPSegmentSeriesIterator

	Iterator() ExtendedIPSegmentSeriesIterator

	PrefixIterator() ExtendedIPSegmentSeriesIterator

	PrefixBlockIterator() ExtendedIPSegmentSeriesIterator

	SpanWithPrefixBlocks() []ExtendedIPSegmentSeries

	CoverWithPrefixBlock() ExtendedIPSegmentSeries

	Contains(other ExtendedIPSegmentSeries) bool

	SetPrefixLen(BitCount) ExtendedIPSegmentSeries

	WithoutPrefixLen() ExtendedIPSegmentSeries

	//ReverseBytes() ExtendedIPSegmentSeries //TODO

	//ReverseBits(bool) ExtendedIPSegmentSeries //TODO

	//ReverseSegments(bool) ExtendedIPSegmentSeries //TODO

}

type WrappedIPAddress struct {
	*IPAddress
}

func (w WrappedIPAddress) Unwrap() IPAddressSegmentSeries {
	return w.IPAddress
}

func (w WrappedIPAddress) SequentialBlockIterator() ExtendedIPSegmentSeriesIterator {
	return addressSeriesIterator{w.IPAddress.SequentialBlockIterator()}
}

func (w WrappedIPAddress) BlockIterator(segmentCount int) ExtendedIPSegmentSeriesIterator {
	return addressSeriesIterator{w.IPAddress.BlockIterator(segmentCount)}
}

func (w WrappedIPAddress) Iterator() ExtendedIPSegmentSeriesIterator {
	return addressSeriesIterator{w.IPAddress.Iterator()}
}

func (w WrappedIPAddress) PrefixIterator() ExtendedIPSegmentSeriesIterator {
	return addressSeriesIterator{w.IPAddress.PrefixIterator()}
}

func (w WrappedIPAddress) PrefixBlockIterator() ExtendedIPSegmentSeriesIterator {
	return addressSeriesIterator{w.IPAddress.PrefixBlockIterator()}
}

// creates a sequential block by changing the segment at the given index to have the given lower and upper value,
// and changing the following segments to be full-range
func (w WrappedIPAddress) ToBlock(segmentIndex int, lower, upper SegInt) ExtendedIPSegmentSeries {
	return WrappedIPAddress{w.IPAddress.ToBlock(segmentIndex, lower, upper)}
}

func (w WrappedIPAddress) GetSequentialBlockIndex() int {
	return w.IPAddress.GetSequentialBlockIndex()
}

func (w WrappedIPAddress) ToPrefixBlockLen(bitCount BitCount) ExtendedIPSegmentSeries {
	return WrappedIPAddress{w.IPAddress.ToPrefixBlockLen(bitCount)}
}

func (w WrappedIPAddress) ToPrefixBlock() ExtendedIPSegmentSeries {
	return WrappedIPAddress{w.IPAddress.ToPrefixBlock()}
}

func (w WrappedIPAddress) ToZeroHostLen(bitCount BitCount) (ExtendedIPSegmentSeries, IncompatibleAddressError) {
	return wrapAddrWithErr(w.IPAddress.ToZeroHostLen(bitCount)) //in IPAddress/Section
}

func (w WrappedIPAddress) ToZeroHost() (ExtendedIPSegmentSeries, IncompatibleAddressError) {
	return wrapAddrWithErr(w.IPAddress.ToZeroHost()) // in IPAddress/Section/Segment
}

func (w WrappedIPAddress) ToMaxHostLen(bitCount BitCount) (ExtendedIPSegmentSeries, IncompatibleAddressError) {
	return wrapAddrWithErr(w.IPAddress.ToMaxHostLen(bitCount))
}

func (w WrappedIPAddress) ToMaxHost() (ExtendedIPSegmentSeries, IncompatibleAddressError) {
	return wrapAddrWithErr(w.IPAddress.ToMaxHost())
}

func (w WrappedIPAddress) ToZeroNetwork() ExtendedIPSegmentSeries {
	return WrappedIPAddress{w.IPAddress.ToZeroNetwork()} //IPAddress/Section.  ToZeroHost() is in IPAddress/Section/Segment
}

func (w WrappedIPAddress) Increment(i int64) ExtendedIPSegmentSeries {
	return convAddrToIntf(w.IPAddress.Increment(i))
}

func (w WrappedIPAddress) GetLower() ExtendedIPSegmentSeries {
	return WrappedIPAddress{w.IPAddress.GetLower()}
}

func (w WrappedIPAddress) GetUpper() ExtendedIPSegmentSeries {
	return WrappedIPAddress{w.IPAddress.GetUpper()}
}

func (w WrappedIPAddress) AssignPrefixForSingleBlock() ExtendedIPSegmentSeries {
	return convAddrToIntf(w.IPAddress.AssignPrefixForSingleBlock())
}

//func (w WrappedIPAddress) AssignMinPrefixForBlock() ExtendedIPSegmentSeries { //TODO reinstate
//	return w.IPAddressSection.AssignMinPrefixForBlock())
//}

func (w WrappedIPAddress) WithoutPrefixLen() ExtendedIPSegmentSeries {
	return WrappedIPAddress{w.IPAddress.WithoutPrefixLen()}
}

func (w WrappedIPAddress) SpanWithPrefixBlocks() []ExtendedIPSegmentSeries {
	return w.IPAddress.spanWithPrefixBlocks()
}

func (w WrappedIPAddress) CoverWithPrefixBlock() ExtendedIPSegmentSeries {
	return w.IPAddress.coverSeriesWithPrefixBlock()
}

func (w WrappedIPAddress) Contains(other ExtendedIPSegmentSeries) bool {
	addr, ok := other.(AddressType)
	return ok && w.IPAddress.Contains(addr)
}

func (w WrappedIPAddress) SetPrefixLen(prefixLen BitCount) ExtendedIPSegmentSeries {
	return WrappedIPAddress{w.IPAddress.SetPrefixLen(prefixLen)}
}

type WrappedIPAddressSection struct {
	*IPAddressSection
}

func (w WrappedIPAddressSection) Unwrap() IPAddressSegmentSeries {
	return w.IPAddressSection
}

func (w WrappedIPAddressSection) SequentialBlockIterator() ExtendedIPSegmentSeriesIterator {
	return sectionSeriesIterator{w.IPAddressSection.SequentialBlockIterator()}
}

func (w WrappedIPAddressSection) BlockIterator(segmentCount int) ExtendedIPSegmentSeriesIterator {
	return sectionSeriesIterator{w.IPAddressSection.BlockIterator(segmentCount)}
}

func (w WrappedIPAddressSection) Iterator() ExtendedIPSegmentSeriesIterator {
	return sectionSeriesIterator{w.IPAddressSection.Iterator()}
}

func (w WrappedIPAddressSection) PrefixIterator() ExtendedIPSegmentSeriesIterator {
	return sectionSeriesIterator{w.IPAddressSection.PrefixIterator()}
}

func (w WrappedIPAddressSection) PrefixBlockIterator() ExtendedIPSegmentSeriesIterator {
	return sectionSeriesIterator{w.IPAddressSection.PrefixBlockIterator()}
}

// creates a sequential block by changing the segment at the given index to have the given lower and upper value,
// and changing the following segments to be full-range
func (w WrappedIPAddressSection) ToBlock(segmentIndex int, lower, upper SegInt) ExtendedIPSegmentSeries {
	return WrappedIPAddressSection{w.IPAddressSection.ToBlock(segmentIndex, lower, upper)}
}

func (w WrappedIPAddressSection) GetSequentialBlockIndex() int {
	return w.IPAddressSection.GetSequentialBlockIndex()
}

func (w WrappedIPAddressSection) ToPrefixBlockLen(bitCount BitCount) ExtendedIPSegmentSeries {
	return WrappedIPAddressSection{w.IPAddressSection.ToPrefixBlockLen(bitCount)}
}

func (w WrappedIPAddressSection) ToPrefixBlock() ExtendedIPSegmentSeries {
	return WrappedIPAddressSection{w.IPAddressSection.ToPrefixBlock()}
}

func (w WrappedIPAddressSection) ToZeroHostLen(bitCount BitCount) (ExtendedIPSegmentSeries, IncompatibleAddressError) {
	return wrapSectWithErr(w.IPAddressSection.ToZeroHostLen(bitCount))
}

func (w WrappedIPAddressSection) ToZeroHost() (ExtendedIPSegmentSeries, IncompatibleAddressError) {
	return wrapSectWithErr(w.IPAddressSection.ToZeroHost())
}

func (w WrappedIPAddressSection) ToMaxHostLen(bitCount BitCount) (ExtendedIPSegmentSeries, IncompatibleAddressError) {
	return wrapSectWithErr(w.IPAddressSection.ToMaxHostLen(bitCount))
}

func (w WrappedIPAddressSection) ToMaxHost() (ExtendedIPSegmentSeries, IncompatibleAddressError) {
	return wrapSectWithErr(w.IPAddressSection.ToMaxHost())
}

func (w WrappedIPAddressSection) ToZeroNetwork() ExtendedIPSegmentSeries {
	return WrappedIPAddressSection{w.IPAddressSection.ToZeroNetwork()}
}

func (w WrappedIPAddressSection) Increment(i int64) ExtendedIPSegmentSeries {
	return convSectToIntf(w.IPAddressSection.Increment(i))
}

func (w WrappedIPAddressSection) GetLower() ExtendedIPSegmentSeries {
	return WrappedIPAddressSection{w.IPAddressSection.GetLower()}
}

func (w WrappedIPAddressSection) GetUpper() ExtendedIPSegmentSeries {
	return WrappedIPAddressSection{w.IPAddressSection.GetUpper()}
}

//func (w WrappedIPAddressSection) CompareTo(series ExtendedIPSegmentSeries) int {
//	return w.IPAddressSection.CompareTo(series)
//}

func (w WrappedIPAddressSection) AssignPrefixForSingleBlock() ExtendedIPSegmentSeries {
	return convSectToIntf(w.IPAddressSection.AssignPrefixForSingleBlock())
}

//func (w WrappedIPAddressSection) AssignMinPrefixForBlock() ExtendedIPSegmentSeries { //TODO reinstate
//	return w.IPAddressSection.AssignMinPrefixForBlock()
//}

func (w WrappedIPAddressSection) WithoutPrefixLen() ExtendedIPSegmentSeries {
	return WrappedIPAddressSection{w.IPAddressSection.WithoutPrefixLen()}
}

func (w WrappedIPAddressSection) SpanWithPrefixBlocks() []ExtendedIPSegmentSeries {
	return w.IPAddressSection.spanWithPrefixBlocks()
}

func (w WrappedIPAddressSection) CoverWithPrefixBlock() ExtendedIPSegmentSeries {
	return w.IPAddressSection.coverSeriesWithPrefixBlock()
}

func (w WrappedIPAddressSection) Contains(other ExtendedIPSegmentSeries) bool {
	addr, ok := other.(AddressSectionType)
	return ok && w.IPAddressSection.Contains(addr)
}

func (w WrappedIPAddressSection) SetPrefixLen(prefixLen BitCount) ExtendedIPSegmentSeries {
	return WrappedIPAddressSection{w.IPAddressSection.SetPrefixLen(prefixLen)}
}

var _ ExtendedIPSegmentSeries = WrappedIPAddress{}
var _ ExtendedIPSegmentSeries = WrappedIPAddressSection{}

func cloneIPv4Sections(sect *IPv4AddressSection, orig []*IPv4AddressSection) []ExtendedIPSegmentSeries {
	origCount := len(orig)
	count := origCount
	if sect != nil {
		count++
	}
	result := make([]ExtendedIPSegmentSeries, count)
	if sect != nil {
		result[origCount] = WrappedIPAddressSection{sect.ToIPAddressSection()}
	}
	for i := range orig {
		result[i] = WrappedIPAddressSection{orig[i].ToIPAddressSection()} // unlike Java, return types matter with interfaces - https://play.golang.org/p/HZR8FSp42a9 )
	}
	return result
}

func cloneIPv6Sections(sect *IPv6AddressSection, orig []*IPv6AddressSection) []ExtendedIPSegmentSeries {
	origCount := len(orig)
	count := origCount
	if sect != nil {
		count++
	}
	result := make([]ExtendedIPSegmentSeries, count)
	if sect != nil {
		result[origCount] = WrappedIPAddressSection{sect.ToIPAddressSection()}
	}
	for i := range orig {
		result[i] = WrappedIPAddressSection{orig[i].ToIPAddressSection()} // unlike Java, return types matter with interfaces - https://play.golang.org/p/HZR8FSp42a9 )
	}
	return result
}

func cloneIPAddrs(addr *IPAddress, orig []*IPAddress) []ExtendedIPSegmentSeries {
	origCount := len(orig)
	count := origCount
	if addr != nil {
		count++
	}
	result := make([]ExtendedIPSegmentSeries, count)
	if addr != nil {
		result[origCount] = WrappedIPAddress{addr.init()}
	}
	for i := range orig {
		result[i] = WrappedIPAddress{orig[i].init()} // unlike Java, return types matter with interfaces - https://play.golang.org/p/HZR8FSp42a9 )
	}
	return result
}

func cloneIPv4Addrs(sect *IPv4Address, orig []*IPv4Address) []ExtendedIPSegmentSeries {
	origCount := len(orig)
	count := origCount
	if sect != nil {
		count++
	}
	result := make([]ExtendedIPSegmentSeries, count)
	if sect != nil {
		result[origCount] = WrappedIPAddress{sect.ToIPAddress().init()}
	}
	for i := range orig {
		result[i] = WrappedIPAddress{orig[i].ToIPAddress().init()} // unlike Java, return types matter with interfaces - https://play.golang.org/p/HZR8FSp42a9 )
	}
	return result
}

func cloneIPv6Addrs(sect *IPv6Address, orig []*IPv6Address) []ExtendedIPSegmentSeries {
	origCount := len(orig)
	count := origCount
	if sect != nil {
		count++
	}
	result := make([]ExtendedIPSegmentSeries, count)
	if sect != nil {
		result[origCount] = WrappedIPAddress{sect.ToIPAddress().init()}
	}
	for i := range orig {
		result[i] = WrappedIPAddress{orig[i].ToIPAddress().init()} // unlike Java, return types matter with interfaces - https://play.golang.org/p/HZR8FSp42a9 )
	}
	return result
}

func cloneToIPSections(orig []ExtendedIPSegmentSeries) []*IPAddressSection {
	result := make([]*IPAddressSection, len(orig))
	for i := range result {
		result[i] = orig[i].(WrappedIPAddressSection).IPAddressSection
	}
	return result
}

func cloneToIPv4Sections(orig []ExtendedIPSegmentSeries) []*IPv4AddressSection {
	result := make([]*IPv4AddressSection, len(orig))
	for i := range result {
		result[i] = orig[i].(WrappedIPAddressSection).ToIPv4AddressSection()
	}
	return result
}

func cloneToIPv6Sections(orig []ExtendedIPSegmentSeries) []*IPv6AddressSection {
	result := make([]*IPv6AddressSection, len(orig))
	for i := range result {
		result[i] = orig[i].(WrappedIPAddressSection).ToIPv6AddressSection()
	}
	return result
}

func cloneToIPAddrs(orig []ExtendedIPSegmentSeries) []*IPAddress {
	result := make([]*IPAddress, len(orig))
	for i := range result {
		result[i] = orig[i].(WrappedIPAddress).IPAddress
	}
	return result
}

func cloneToIPv4Addrs(orig []ExtendedIPSegmentSeries) []*IPv4Address {
	result := make([]*IPv4Address, len(orig))
	for i := range result {
		result[i] = orig[i].(WrappedIPAddress).ToIPv4Address()
	}
	return result
}

func cloneToIPv6Addrs(orig []ExtendedIPSegmentSeries) []*IPv6Address {
	result := make([]*IPv6Address, len(orig))
	for i := range result {
		result[i] = orig[i].(WrappedIPAddress).ToIPv6Address()
	}
	return result
}

// In go, a nil value is not coverted to a nil interface, it is converted to a non-nil interface instance with underlying value nil
func convAddrToIntf(addr *IPAddress) ExtendedIPSegmentSeries {
	if addr == nil {
		return nil
	}
	return WrappedIPAddress{addr}
}

func convSectToIntf(sect *IPAddressSection) ExtendedIPSegmentSeries {
	if sect == nil {
		return nil
	}
	return WrappedIPAddressSection{sect}
}

func wrapSectWithErr(section *IPAddressSection, err IncompatibleAddressError) (ExtendedIPSegmentSeries, IncompatibleAddressError) {
	if err == nil {
		return WrappedIPAddressSection{section}, nil
	}
	return nil, err
}

func wrapAddrWithErr(addr *IPAddress, err IncompatibleAddressError) (ExtendedIPSegmentSeries, IncompatibleAddressError) {
	if err == nil {
		return WrappedIPAddress{addr}, nil
	}
	return nil, err
}
