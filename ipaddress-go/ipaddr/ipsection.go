package ipaddr

import (
	"math/big"
	"sync/atomic"
	"unsafe"
)

func createIPSection(segments []*AddressDivision, addrType addrType, startIndex int8) *IPAddressSection {
	return &IPAddressSection{
		ipAddressSectionInternal{
			addressSectionInternal{
				addressDivisionGroupingInternal{
					addressDivisionGroupingBase: addressDivisionGroupingBase{
						divisions: standardDivArray{segments},
						addrType:  addrType,
						cache:     &valueCache{},
					},
					addressSegmentIndex: startIndex,
				},
			},
		},
	}
}

func deriveIPAddressSection(from *IPAddressSection, segments []*AddressDivision) (res *IPAddressSection) {
	res = createIPSection(segments, from.getAddrType(), from.addressSegmentIndex)
	res.init()
	return
}

//func deriveIPAddressSectionPrefLen(from *IPAddressSection, segments []*AddressDivision, prefixLength PrefixLen) (res *IPAddressSection) {
//	res = createIPSection(segments, from.getAddrType(), from.addressSegmentIndex)
//	assignPrefixSubnet(prefixLength, segments, res)
//	return
//}

func deriveIPAddressSectionSingle(from *IPAddressSection, segments []*AddressDivision /* cloneSegments bool,*/, prefixLength PrefixLen, singleOnly bool) (res *IPAddressSection) {
	res = deriveIPAddressSection(from, segments)
	if prefixLength != nil && !singleOnly {
		assignPrefixSubnet(prefixLength, segments, res)
	}
	return
}

//
//
//
//
type ipAddressSectionInternal struct {
	addressSectionInternal
}

func (section *ipAddressSectionInternal) GetSegment(index int) *IPAddressSegment {
	return section.getDivision(index).ToIPAddressSegment()
}

//func (section *ipAddressSectionInternal) GetGenericIPDivision(index int) IPAddressGenericDivision {
//	return section.GetSegment(index)
//}

func (section *ipAddressSectionInternal) GetIPVersion() IPVersion {
	addrType := section.getAddrType()
	if addrType.isIPv4() {
		return IPv4
	} else if addrType.isIPv6() {
		return IPv6
	}
	return INDETERMINATE_VERSION
}

func (section *ipAddressSectionInternal) GetNetworkPrefixLength() PrefixLen {
	return section.prefixLength
}

//func (section *ipAddressSectionInternal) CompareSize(other AddressDivisionSeries) int {
//	//func (section *ipAddressSectionInternal) CompareSize(other *IPAddressSection) int {
//	if !section.IsMultiple() {
//		if other.IsMultiple() {
//			return -1
//		}
//		return 0
//	}
//	if !other.IsMultiple() {
//		return 1
//	}
//	if otherGrouping, ok := other.(AddressDivisionGroupingType); ok { Without caching, this is no faster
//		otherSeries := otherGrouping.ToAddressDivisionGrouping()
//		if section.IsSinglePrefixBlock() && otherSeries.IsSinglePrefixBlock() {
//			bits := section.GetBitCount() - section.GetPrefixLength()
//			otherBits := other.GetBitCount() - otherSeries.GetPrefixLength()
//			return bits - otherBits
//		}
//	}
//	return section.GetCount().CmpAbs(other.GetCount())
//}

// GetBlockMaskPrefixLength returns the prefix length if this address section is equivalent to the mask for a CIDR prefix block.
// Otherwise, it returns null.
// A CIDR network mask is an address with all 1s in the network section and then all 0s in the host section.
// A CIDR host mask is an address with all 0s in the network section and then all 1s in the host section.
// The prefix length is the length of the network section.
//
// Also, keep in mind that the prefix length returned by this method is not equivalent to the prefix length of this object,
// indicating the network and host section of this address.
// The prefix length returned here indicates the whether the value of this address can be used as a mask for the network and host
// section of any other address.  Therefore the two values can be different values, or one can be null while the other is not.
//
// This method applies only to the lower value of the range if this section represents multiple values.
func (section *ipAddressSectionInternal) GetBlockMaskPrefixLength(network bool) PrefixLen {
	cache := section.cache
	if cache == nil {
		return nil
	}
	cachedMaskLens := cache.cachedMaskLens
	if cachedMaskLens == nil {
		networkMaskLen, hostMaskLen := section.checkForPrefixMask()
		res := &maskLenSetting{networkMaskLen, hostMaskLen}
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.cachedMaskLens))
		atomic.StorePointer(dataLoc, unsafe.Pointer(res))
	}
	if network {
		return cache.cachedMaskLens.networkMaskLen
	}
	return cache.cachedMaskLens.hostMaskLen
}

func (section *ipAddressSectionInternal) checkForPrefixMask() (networkMaskLen, hostMaskLen PrefixLen) {
	count := section.GetSegmentCount()
	if count == 0 {
		return
	}
	firstSeg := section.GetSegment(0)
	checkingNetworkFront, checkingHostFront := true, true
	var checkingNetworkBack, checkingHostBack bool
	var prefixedSeg int
	prefixedSegPrefixLen := BitCount(0)
	maxVal := firstSeg.GetMaxValue()
	for i := 0; i < count; i++ {
		seg := section.GetSegment(i)
		val := seg.GetSegmentValue()
		if val == 0 {
			if checkingNetworkFront {
				prefixedSeg = i
				checkingNetworkFront, checkingNetworkBack = false, true
			} else if !checkingHostFront && !checkingNetworkBack {
				return
			}
			checkingHostBack = false
		} else if val == maxVal {
			if checkingHostFront {
				prefixedSeg = i
				checkingHostFront, checkingHostBack = false, true
			} else if !checkingHostBack && !checkingNetworkFront {
				return
			}
			checkingNetworkBack = false
		} else {
			segNetworkMaskLen, segHostMaskLen := seg.checkForPrefixMask()
			if segNetworkMaskLen != nil {
				if checkingNetworkFront {
					prefixedSegPrefixLen = *segNetworkMaskLen
					checkingNetworkBack = true
					prefixedSeg = i
				} else {
					return
				}
			} else if segHostMaskLen != nil {
				if checkingHostFront {
					prefixedSegPrefixLen = *segHostMaskLen
					checkingHostBack = true
					prefixedSeg = i
				} else {
					return
				}
			} else {
				return
			}
			checkingNetworkFront, checkingHostFront = false, false
		}
	}
	if checkingNetworkFront {
		// all ones
		networkMaskLen = cache(section.GetBitCount())
		hostMaskLen = cache(0)
	} else if checkingHostFront {
		// all zeros
		hostMaskLen = cache(section.GetBitCount())
		networkMaskLen = cache(0)
	} else if checkingNetworkBack {
		// ending in zeros, network mask
		networkMaskLen = getNetworkPrefixLength(firstSeg.GetBitCount(), prefixedSegPrefixLen, prefixedSeg)
	} else if checkingHostBack {
		// ending in ones, host mask
		hostMaskLen = getNetworkPrefixLength(firstSeg.GetBitCount(), prefixedSegPrefixLen, prefixedSeg)
	}
	return
}

func (section *ipAddressSectionInternal) IncludesZeroHost() bool {
	networkPrefixLength := section.GetPrefixLength()
	return networkPrefixLength != nil && section.IncludesZeroHostLen(*networkPrefixLength)
}

func (section *ipAddressSectionInternal) IncludesZeroHostLen(networkPrefixLength BitCount) bool {
	networkPrefixLength = checkSubnet(section, networkPrefixLength)
	bitsPerSegment := section.GetBitsPerSegment()
	bytesPerSegment := section.GetBytesPerSegment()
	prefixedSegmentIndex := getHostSegmentIndex(networkPrefixLength, bytesPerSegment, bitsPerSegment)
	divCount := section.GetSegmentCount()
	for i := prefixedSegmentIndex; i < divCount; i++ {
		div := section.GetSegment(i)
		segmentPrefixLength := getPrefixedSegmentPrefixLength(bitsPerSegment, networkPrefixLength, i)
		if segmentPrefixLength != nil {
			mask := div.GetSegmentHostMask(*segmentPrefixLength)
			if (mask & div.GetSegmentValue()) != 0 {
				return false
			}
			for i++; i < divCount; i++ {
				div = section.GetSegment(i)
				if !div.includesZero() {
					return false
				}
			}
		}
	}
	return true
}

func (section *ipAddressSectionInternal) IncludesMaxHost() bool {
	networkPrefixLength := section.GetPrefixLength()
	return networkPrefixLength != nil && section.IncludesMaxHostLen(*networkPrefixLength)
}

func (section *ipAddressSectionInternal) IncludesMaxHostLen(networkPrefixLength BitCount) bool {
	networkPrefixLength = checkSubnet(section, networkPrefixLength)
	bitsPerSegment := section.GetBitsPerSegment()
	bytesPerSegment := section.GetBytesPerSegment()
	prefixedSegmentIndex := getHostSegmentIndex(networkPrefixLength, bytesPerSegment, bitsPerSegment)
	divCount := section.GetSegmentCount()
	for i := prefixedSegmentIndex; i < divCount; i++ {
		div := section.GetSegment(i)
		segmentPrefixLength := getPrefixedSegmentPrefixLength(bitsPerSegment, networkPrefixLength, i)
		if segmentPrefixLength != nil {
			mask := div.GetSegmentHostMask(*segmentPrefixLength)
			if (mask & div.getUpperSegmentValue()) != mask {
				return false
			}
			for i++; i < divCount; i++ {
				div = section.GetSegment(i)
				if !div.includesMax() {
					return false
				}
			}
		}
	}
	return true
}

func (section *ipAddressSectionInternal) toZeroHost() (res *IPAddressSection, err IncompatibleAddressException) {
	segmentCount := section.GetSegmentCount()
	if segmentCount == 0 {
		return section.toIPAddressSection(), nil
	}
	if !section.IsPrefixed() {
		mask := section.addrType.getIPNetwork().GetPrefixedNetworkMask(0)
		res = mask.GetSubSection(0, segmentCount)
		return
	}
	if section.IncludesZeroHost() && section.IsSingleNetwork() {
		res = section.getLower().ToIPAddressSection() //cached
		return
	}
	return section.createZeroHost(false)
}

// boundariesOnly: whether we care if the masking works for all values in a range.
// For instance, 1.2.3.2-4/31 cannot be zero-hosted, because applyng to the boundaries results in 1.2.3.2-4/31,
// and that includes 1.2.3.3/31 which does not have host of zero.
// So in that case, we'd normally have IncompatibleAddressException.  boundariesOnly as true avoids the exception,
// if we are really just interested in getting the zero-host boundaries,
// and we don't care about the remaining values in-between.
func (section *ipAddressSectionInternal) createZeroHost(boundariesOnly bool) (*IPAddressSection, IncompatibleAddressException) {
	prefixLength := section.GetNetworkPrefixLength() //we know it is prefixed here so no panic on the derefence
	mask := section.addrType.getIPNetwork().GetNetworkMask(*prefixLength)
	res, err := getSubnetSegments(
		section.ToAddressSection(),
		getNetworkSegmentIndex(*prefixLength, section.GetBytesPerSegment(), section.GetBitsPerSegment()),
		prefixLength,
		!boundariesOnly, //verifyMask
		section.getDivision,
		func(i int) SegInt { return mask.GetSegment(i).GetSegmentValue() })
	return res.ToIPAddressSection(), err
}

func (section *ipAddressSectionInternal) toZeroHostLen(prefixLength BitCount) (*IPAddressSection, IncompatibleAddressException) {
	var minIndex int
	if section.IsPrefixed() {
		existingPrefLen := *section.GetNetworkPrefixLength()
		if prefixLength == existingPrefLen {
			return section.toZeroHost()
		}
		if prefixLength < existingPrefLen {
			minIndex = getNetworkSegmentIndex(prefixLength, section.GetBytesPerSegment(), section.GetBitsPerSegment())
		} else {
			minIndex = getNetworkSegmentIndex(existingPrefLen, section.GetBytesPerSegment(), section.GetBitsPerSegment())
		}
	} else {
		minIndex = getNetworkSegmentIndex(prefixLength, section.GetBytesPerSegment(), section.GetBitsPerSegment())
	}
	mask := section.addrType.getIPNetwork().GetNetworkMask(prefixLength)
	res, err := getSubnetSegments(
		section.ToAddressSection(),
		minIndex,
		nil,
		true,
		section.getDivision,
		func(i int) SegInt { return mask.GetSegment(i).GetSegmentValue() })
	return res.ToIPAddressSection(), err
}

func (section *ipAddressSectionInternal) toZeroNetwork() *IPAddressSection {
	segmentCount := section.GetSegmentCount()
	if segmentCount == 0 {
		return section.toIPAddressSection()
	}
	if !section.IsPrefixed() {
		mask := section.addrType.getIPNetwork().GetHostMask(section.GetBitCount())
		return mask.GetSubSection(0, segmentCount)
	}
	return section.createZeroNetwork()
}

func (section *ipAddressSectionInternal) createZeroNetwork() *IPAddressSection {
	prefixLength := section.GetNetworkPrefixLength() // we know it is prefixed here so no panic on the derefence
	mask := section.addrType.getIPNetwork().GetHostMask(*prefixLength)
	res, _ := getSubnetSegments(
		section.toAddressSection(),
		0,
		prefixLength,
		false,
		section.getDivision,
		func(i int) SegInt { return mask.GetSegment(i).GetSegmentValue() })
	return res.ToIPAddressSection()
}

func (section *ipAddressSectionInternal) toMaxHost() (res *IPAddressSection, err IncompatibleAddressException) {
	segmentCount := section.GetSegmentCount()
	if segmentCount == 0 {
		return section.toIPAddressSection(), nil
	}
	if !section.IsPrefixed() {
		mask := section.addrType.getIPNetwork().GetPrefixedHostMask(0)
		res = mask.GetSubSection(0, segmentCount)
		return
	}
	if section.IncludesZeroHost() && section.IsSingleNetwork() {
		return section.getUpper().ToIPAddressSection(), nil // cached
	}
	return section.createMaxHost()
}

func (section *ipAddressSectionInternal) createMaxHost() (*IPAddressSection, IncompatibleAddressException) {
	prefixLength := section.GetNetworkPrefixLength() // we know it is prefixed here so no panic on the derefence
	mask := section.addrType.getIPNetwork().GetHostMask(*prefixLength)
	return getOredSegments(
		section.toIPAddressSection(),
		prefixLength,
		true,
		section.getDivision,
		func(i int) SegInt { return mask.GetSegment(i).GetSegmentValue() },
		true)
}

func (section *ipAddressSectionInternal) toMaxHostLen(prefixLength BitCount) (*IPAddressSection, IncompatibleAddressException) {
	if section.IsPrefixed() && prefixLength == *section.GetNetworkPrefixLength() {
		return section.toMaxHost()
	}
	mask := section.addrType.getIPNetwork().GetHostMask(prefixLength)
	return getOredSegments(
		section.toIPAddressSection(),
		nil,
		true,
		section.getDivision,
		func(i int) SegInt { return mask.GetSegment(i).GetSegmentValue() },
		true)
}

// IsSingleNetwork returns whether the network section of the address, the prefix, consists of a single value
func (section *ipAddressSectionInternal) IsSingleNetwork() bool {
	networkPrefixLength := section.GetNetworkPrefixLength()
	if networkPrefixLength == nil {
		return !section.IsMultiple()
	}
	prefLen := *networkPrefixLength
	if prefLen >= section.GetBitCount() {
		return !section.IsMultiple()
	}
	bitsPerSegment := section.GetBitsPerSegment()
	prefixedSegmentIndex := getNetworkSegmentIndex(prefLen, section.GetBytesPerSegment(), bitsPerSegment)
	if prefixedSegmentIndex < 0 {
		return true
	}
	for i := 0; i < prefixedSegmentIndex; i++ {
		if section.getDivision(i).IsMultiple() {
			return false
		}
	}
	div := section.GetSegment(prefixedSegmentIndex)
	divPrefLen := getPrefixedSegmentPrefixLength(bitsPerSegment, prefLen, prefixedSegmentIndex)
	shift := bitsPerSegment - *divPrefLen
	return (div.GetSegmentValue() >> shift) == (div.GetUpperSegmentValue() >> shift)
}

// IsZeroHost returns whether this section has a prefix length and if so,
// whether the host section is zero for this section or all sections in this set of address sections.
// If the host section is zero length (there are no host bits at all), returns false.
func (section *ipAddressSectionInternal) IsZeroHost() bool {
	if !section.IsPrefixed() {
		return false
	}
	return section.IsZeroHostLen(*section.GetNetworkPrefixLength())
}

// IsZeroHostLen returns whether the host is zero for the given prefix length for this section or all sections in this set of address sections.
// If this section already has a prefix length, then that prefix length is ignored.
// If the host section is zero length (there are no host bits at all), returns false.
func (section *ipAddressSectionInternal) IsZeroHostLen(prefLen BitCount) bool {
	segmentCount := section.GetSegmentCount()
	if segmentCount == 0 {
		return false
	} else if prefLen < 0 {
		prefLen = 0
	}
	bitsPerSegment := section.GetBitsPerSegment()
	// Note: 1.2.3.4/32 has a zero host
	prefixedSegmentIndex := getHostSegmentIndex(prefLen, section.GetBytesPerSegment(), bitsPerSegment)
	if prefixedSegmentIndex < segmentCount {
		segmentPrefixLength := getPrefixedSegmentPrefixLength(bitsPerSegment, prefLen, prefixedSegmentIndex)
		if segmentPrefixLength != nil {
			i := prefixedSegmentIndex
			div := section.GetSegment(i)
			if div.isMultiple() || (div.GetSegmentHostMask(*segmentPrefixLength)&div.getSegmentValue()) != 0 {
				return false
			}
			for i++; i < segmentCount; i++ {
				div := section.GetSegment(i)
				if !div.IsZero() {
					return false
				}
			}
		}
	}
	return true
}

//func (section *ipAddressSectionInternal) setPrefixLen(prefixLen BitCount) *IPAddressSection {
//	res, _ := setIPPrefixLength(section.toIPAddressSection(), prefixLen, false, true)
//	return res
//} TODO remove
//
//func (section *ipAddressSectionInternal) setPrefixLenZeroed(prefixLen BitCount, zeroHostIsBlock bool) (*IPAddressSection, IncompatibleAddressException) {
//	return setIPPrefixLength(section.toIPAddressSection(), prefixLen, true, !zeroHostIsBlock)
//} TODO remove
//

func (section *ipAddressSectionInternal) checkSectionCount(other *IPAddressSection) SizeMismatchException {
	if other.GetSegmentCount() < section.GetSegmentCount() {
		return &sizeMismatchException{incompatibleAddressException{addressException{str: "ipaddress.error.sizeMismatch"}}}
	}
	return nil
}

// error can be IncompatibleAddressException or SizeMismatchException
func (section *ipAddressSectionInternal) mask(msk *IPAddressSection, retainPrefix bool) (*IPAddressSection, IncompatibleAddressException) {
	if err := section.checkSectionCount(msk); err != nil {
		return nil, err
	}
	var prefLen PrefixLen
	if retainPrefix {
		prefLen = section.GetPrefixLength()
	}
	res, _ := getSubnetSegments(
		section.toAddressSection(),
		0,
		prefLen,
		true,
		section.getDivision,
		func(i int) SegInt { return msk.GetSegment(i).GetSegmentValue() })
	return res.ToIPAddressSection(), nil
}

func (section *ipAddressSectionInternal) spanWithPrefixBlocks() []ExtendedIPSegmentSeries {
	wrapped := WrappedIPAddressSection{section.toIPAddressSection()}
	if section.IsSequential() {
		if section.IsSinglePrefixBlock() {
			return []ExtendedIPSegmentSeries{wrapped}
		}
		return getSpanningPrefixBlocks(wrapped, wrapped)
	}
	return spanWithPrefixBlocks(wrapped)
}

func (section *ipAddressSectionInternal) ToOctalString(with0Prefix bool) (string, IncompatibleAddressException) {
	return cacheStrErr(&section.getStringCache().octalString,
		func() (string, IncompatibleAddressException) {
			return section.toOctalStringZoned(with0Prefix, noZone)
		})
}

func (section *ipAddressSectionInternal) toOctalStringZoned(with0Prefix bool, zone Zone) (string, IncompatibleAddressException) {
	if with0Prefix {
		return section.toLongStringZoned(zone, octalPrefixedParams)
	}
	return section.toLongStringZoned(zone, octalParams)
}

func (section *ipAddressSectionInternal) ToBinaryString(with0bPrefix bool) (string, IncompatibleAddressException) {
	return cacheStrErr(&section.getStringCache().binaryString,
		func() (string, IncompatibleAddressException) {
			return section.toBinaryStringZoned(with0bPrefix, noZone)
		})
}

func (section *ipAddressSectionInternal) toBinaryStringZoned(with0bPrefix bool, zone Zone) (string, IncompatibleAddressException) {
	if with0bPrefix {
		return section.toLongStringZoned(zone, binaryPrefixedParams)
	}
	return section.toLongStringZoned(zone, binaryParams)
}

func (section *ipAddressSectionInternal) ToNormalizedWildcardString() string {
	if sect := section.toIPv4AddressSection(); sect != nil {
		return sect.ToNormalizedWildcardString()
	} else if sect := section.toIPv6AddressSection(); sect != nil {
		return sect.ToNormalizedWildcardString()
	}
	return "0"
}

func (section *ipAddressSectionInternal) ToCanonicalWildcardString() string {
	if sect := section.toIPv4AddressSection(); sect != nil {
		return sect.ToCanonicalWildcardString()
	} else if sect := section.toIPv6AddressSection(); sect != nil {
		return sect.ToCanonicalWildcardString()
	}
	return "0"
}

func (section *ipAddressSectionInternal) ToSegmentedBinaryString() string {
	if sect := section.toIPv4AddressSection(); sect != nil {
		return sect.ToSegmentedBinaryString()
	} else if sect := section.toIPv6AddressSection(); sect != nil {
		return sect.ToSegmentedBinaryString()
	}
	return "0"
}

func (section *ipAddressSectionInternal) ToSQLWildcardString() string {
	if sect := section.toIPv4AddressSection(); sect != nil {
		return sect.ToSQLWildcardString()
	} else if sect := section.toIPv6AddressSection(); sect != nil {
		return sect.ToSQLWildcardString()
	}
	return "0"
}

func (section *ipAddressSectionInternal) ToFullString() string {
	if sect := section.toIPv4AddressSection(); sect != nil {
		return sect.ToFullString()
	} else if sect := section.toIPv6AddressSection(); sect != nil {
		return sect.ToFullString()
	}
	return "0"
}

func (section *ipAddressSectionInternal) ToReverseDNSString() string {
	if sect := section.toIPv4AddressSection(); sect != nil {
		return sect.ToReverseDNSString()
	} else if sect := section.toIPv6AddressSection(); sect != nil {
		return sect.ToReverseDNSString()
	}
	return "0"
}

func (section *ipAddressSectionInternal) ToPrefixLengthString() string {
	if sect := section.toIPv4AddressSection(); sect != nil {
		return sect.ToPrefixLengthString()
	} else if sect := section.toIPv6AddressSection(); sect != nil {
		return sect.ToPrefixLengthString()
	}
	return "0"
}

func (section *ipAddressSectionInternal) ToSubnetString() string {
	if sect := section.toIPv4AddressSection(); sect != nil {
		return sect.ToNormalizedWildcardString()
	} else if sect := section.toIPv6AddressSection(); sect != nil {
		return sect.ToPrefixLengthString()
	}
	return "0"
}

func (section *ipAddressSectionInternal) ToCompressedWildcardString() string {
	if sect := section.toIPv4AddressSection(); sect != nil {
		return sect.ToCompressedWildcardString()
	} else if sect := section.toIPv6AddressSection(); sect != nil {
		return sect.ToCompressedWildcardString()
	}
	return "0"
}

func (section *ipAddressSectionInternal) ToAddressSection() *AddressSection {
	return (*AddressSection)(unsafe.Pointer(section))
}

func (section *ipAddressSectionInternal) toIPAddressSection() *IPAddressSection {
	return (*IPAddressSection)(unsafe.Pointer(section))
}

//
//
//
// An IPAddress section has segments, which are divisions of equal length and size
type IPAddressSection struct {
	ipAddressSectionInternal
}

func (section *IPAddressSection) GetCount() *big.Int {
	if sect := section.ToIPv4AddressSection(); sect != nil {
		return sect.GetCount()
	} else if sect := section.ToIPv6AddressSection(); sect != nil {
		return sect.GetCount()
	}
	return section.addressDivisionGroupingBase.GetCount()
}

func (section *IPAddressSection) GetPrefixCount() *big.Int {
	if sect := section.ToIPv4AddressSection(); sect != nil {
		return sect.GetPrefixCount()
	} else if sect := section.ToIPv6AddressSection(); sect != nil {
		return sect.GetPrefixCount()
	}
	return section.addressDivisionGroupingBase.GetPrefixCount()
}

func (section *IPAddressSection) GetPrefixCountLen(prefixLen BitCount) *big.Int {
	if sect := section.ToIPv4AddressSection(); sect != nil {
		return sect.GetPrefixCountLen(prefixLen)
	} else if sect := section.ToIPv6AddressSection(); sect != nil {
		return sect.GetPrefixCountLen(prefixLen)
	}
	return section.addressDivisionGroupingBase.GetPrefixCountLen(prefixLen)
}

func (section *IPAddressSection) IsIPv4AddressSection() bool {
	return section != nil && section.matchesIPv4Section()
}

func (section *IPAddressSection) IsIPv6AddressSection() bool {
	return section != nil && section.matchesIPv6Section()
}

func (section *IPAddressSection) ToIPv6AddressSection() *IPv6AddressSection {
	if section.IsIPv6AddressSection() {
		return (*IPv6AddressSection)(unsafe.Pointer(section))
	}
	return nil
}

func (section *IPAddressSection) ToIPv4AddressSection() *IPv4AddressSection {
	if section.IsIPv4AddressSection() {
		return (*IPv4AddressSection)(unsafe.Pointer(section))
	}
	return nil
}

func (section *IPAddressSection) IsIPv4() bool { // we allow nil receivers to allow this to be called following a failed converion like ToIPAddressSection()
	return section != nil && section.matchesIPv4Section()
}

func (section *IPAddressSection) IsIPv6() bool {
	return section != nil && section.matchesIPv6Section()
}

// Gets the subsection from the series starting from the given index
// The first segment is at index 0.
func (section *IPAddressSection) GetTrailingSection(index int) *IPAddressSection {
	return section.GetSubSection(index, section.GetSegmentCount())
}

// GetSubSection gets the subsection from the series starting from the given index and ending just before the give endIndex
// The first segment is at index 0.
func (section *IPAddressSection) GetSubSection(index, endIndex int) *IPAddressSection {
	return section.getSubSection(index, endIndex).ToIPAddressSection()
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (section *IPAddressSection) CopySubSegments(start, end int, segs []*IPAddressSegment) (count int) {
	return section.visitSubSegments(start, end, func(index int, div *AddressDivision) bool { segs[index] = div.ToIPAddressSegment(); return false }, len(segs))
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (section *IPAddressSection) CopySegments(segs []*IPAddressSegment) (count int) {
	return section.visitSegments(func(index int, div *AddressDivision) bool { segs[index] = div.ToIPAddressSegment(); return false }, len(segs))
}

// GetSegments returns a slice with the address segments.  The returned slice is not backed by the same array as this section.
func (section *IPAddressSection) GetSegments() (res []*IPAddressSegment) {
	res = make([]*IPAddressSegment, section.GetSegmentCount())
	section.CopySegments(res)
	return
}

func (section *IPAddressSection) GetLower() *IPAddressSection {
	return section.getLower().ToIPAddressSection()
}

func (section *IPAddressSection) GetUpper() *IPAddressSection {
	return section.getUpper().ToIPAddressSection()
}

func (section *IPAddressSection) ToZeroHost() (res *IPAddressSection, err IncompatibleAddressException) {
	return section.toZeroHost()
}

func (section *IPAddressSection) ToZeroHostLen(prefixLength BitCount) (*IPAddressSection, IncompatibleAddressException) {
	return section.ToZeroHostLen(prefixLength)
}

func (section *IPAddressSection) ToZeroNetwork() *IPAddressSection {
	return section.toZeroNetwork()
}

func (section *IPAddressSection) ToMaxHost() (res *IPAddressSection, err IncompatibleAddressException) {
	return section.toMaxHost()
}

func (section *IPAddressSection) ToMaxHostLen(prefixLength BitCount) (*IPAddressSection, IncompatibleAddressException) {
	return section.toMaxHostLen(prefixLength)
}

func (section *IPAddressSection) WithoutPrefixLen() *IPAddressSection {
	return section.withoutPrefixLen().ToIPAddressSection()
}

func (section *IPAddressSection) SetPrefixLen(prefixLen BitCount) *IPAddressSection {
	return section.setPrefixLen(prefixLen).ToIPAddressSection()
}

func (section *IPAddressSection) SetPrefixLenZeroed(prefixLen BitCount) (*IPAddressSection, IncompatibleAddressException) {
	res, err := section.setPrefixLenZeroed(prefixLen)
	return res.ToIPAddressSection(), err
}

func (section *IPAddressSection) ToPrefixBlock() *IPAddressSection {
	return section.toPrefixBlock().ToIPAddressSection()
}

func (section *IPAddressSection) ToPrefixBlockLen(prefLen BitCount) *IPAddressSection {
	return section.toPrefixBlockLen(prefLen).ToIPAddressSection()
}

func (section *IPAddressSection) AssignPrefixForSingleBlock() *IPAddressSection {
	return section.assignPrefixForSingleBlock().ToIPAddressSection()
}

func (section *IPAddressSection) ToBlock(segmentIndex int, lower, upper SegInt) *IPAddressSection {
	return section.toBlock(segmentIndex, lower, upper).ToIPAddressSection()
}

func (section *IPAddressSection) Iterator() IPSectionIterator {
	return ipSectionIterator{section.sectionIterator(nil)}
}

func (section *IPAddressSection) PrefixIterator() IPSectionIterator {
	return ipSectionIterator{section.prefixIterator(false)}
}

func (section *IPAddressSection) PrefixBlockIterator() IPSectionIterator {
	return ipSectionIterator{section.prefixIterator(true)}
}

func (section *IPAddressSection) BlockIterator(segmentCount int) IPSectionIterator {
	return ipSectionIterator{section.blockIterator(segmentCount)}
}

func (section *IPAddressSection) SequentialBlockIterator() IPSectionIterator {
	return ipSectionIterator{section.sequentialBlockIterator()}
}

func (section *IPAddressSection) IncrementBoundary(increment int64) *IPAddressSection {
	return section.incrementBoundary(increment).ToIPAddressSection()
}

func (section *IPAddressSection) Increment(increment int64) *IPAddressSection {
	return section.increment(increment).ToIPAddressSection()
}

//func (section *IPAddressSection) spanWithPrefixBlocks() []ExtendedIPSegmentSeries {
//	xxx
//	if section.IsIPv4AddressSection() {
//		return section.ToIPv4AddressSection().spanWithPrefixBlocks()
//	} else if section.IsIPv6AddressSection() {
//		return section.ToIPv6AddressSection().spanWithPrefixBlocks()
//	}
//	return nil
//}

func (section *IPAddressSection) SpanWithPrefixBlocks() []*IPAddressSection {
	if section.IsSequential() {
		if section.IsSinglePrefixBlock() {
			return []*IPAddressSection{section}
		}
		wrapped := WrappedIPAddressSection{section}
		spanning := getSpanningPrefixBlocks(wrapped, wrapped)
		return cloneToIPSections(spanning)
	}
	wrapped := WrappedIPAddressSection{section}
	return cloneToIPSections(spanWithPrefixBlocks(wrapped))
}

func (section *IPAddressSection) SpanWithSequentialBlocks() []*IPAddressSection {
	if section.IsSequential() {
		return []*IPAddressSection{section}
	}
	wrapped := WrappedIPAddressSection{section}
	return cloneToIPSections(spanWithSequentialBlocks(wrapped))
}

var (
	rangeWildcard                 = new(WildcardsBuilder).ToWildcards()
	allWildcards                  = new(WildcardOptionsBuilder).SetWildcardOptions(WILDCARDS_ALL).ToOptions()
	wildcardsRangeOnlyNetworkOnly = new(WildcardOptionsBuilder).SetWildcards(rangeWildcard).ToOptions()
	allSQLWildcards               = new(WildcardOptionsBuilder).SetWildcardOptions(WILDCARDS_ALL).SetWildcards(
		new(WildcardsBuilder).SetWildcard(SegmentSqlWildcardStr).SetSingleWildcard(SegmentSqlSingleWildcardStr).ToWildcards()).ToOptions()
)

func BitsPerSegment(version IPVersion) BitCount {
	if version == IPv4 {
		return IPv4BitsPerSegment
	}
	return IPv6BitsPerSegment
}

func assignPrefixSubnet(prefixLength PrefixLen, segments []*AddressDivision, res *IPAddressSection) {
	segLen := len(segments)
	if segLen > 0 {
		prefLen := *prefixLength
		if isPrefixSubnetSegs(segments, prefLen, false) {
			applyPrefixToSegments(
				prefLen,
				segments,
				res.GetBitsPerSegment(),
				res.GetBytesPerSegment(),
				(*AddressDivision).toPrefixedNetworkDivision)
			if !res.isMultiple {
				res.isMultiple = res.GetSegment(segLen - 1).IsMultiple()
			}
		}
	}
	return
}

// handles prefix blocks subnets, and ensures segment prefixes match the section prefix
func assignPrefix(prefixLength PrefixLen, segments []*AddressDivision, res *IPAddressSection, singleOnly bool, boundaryBits, maxBits BitCount) {
	//if prefixLength != nil {
	prefLen := *prefixLength
	if prefLen < 0 {
		prefLen = 0
	} else if prefLen > boundaryBits {
		prefLen = boundaryBits
		prefixLength = &boundaryBits
	}
	segLen := len(segments)
	if segLen > 0 {
		segsPrefLen := res.prefixLength
		if segsPrefLen != nil {
			sp := *segsPrefLen
			if sp < prefLen { //if the segments have a shorter prefix length, then use that
				prefLen = sp
				prefixLength = segsPrefLen
			}
		}
		var segProducer func(*AddressDivision, PrefixLen) *AddressDivision
		applyPrefixSubnet := !singleOnly && isPrefixSubnetSegs(segments, prefLen, false)
		if applyPrefixSubnet {
			segProducer = (*AddressDivision).toPrefixedNetworkDivision
		} else {
			segProducer = (*AddressDivision).toPrefixedDivision
		}
		applyPrefixToSegments(
			prefLen,
			segments,
			res.GetBitsPerSegment(),
			res.GetBytesPerSegment(),
			segProducer)
		if applyPrefixSubnet && !res.isMultiple {
			res.isMultiple = res.GetSegment(segLen - 1).IsMultiple()
		}
	}
	res.prefixLength = prefixLength
	return
}

// Starting from the first host bit according to the prefix, if the section is a sequence of zeros in both low and high values,
// followed by a sequence where low values are zero and high values are 1, then the section is a subnet prefix.
//
// Note that this includes sections where hosts are all zeros, or sections where hosts are full range of values,
// so the sequence of zeros can be empty and the sequence of where low values are zero and high values are 1 can be empty as well.
// However, if they are both empty, then this returns false, there must be at least one bit in the sequence.
func isPrefixSubnetSegs(sectionSegments []*AddressDivision, networkPrefixLength BitCount, fullRangeOnly bool) bool {
	segmentCount := len(sectionSegments)
	if segmentCount == 0 {
		return false
	}
	seg := sectionSegments[0]
	return isPrefixSubnet(
		func(segmentIndex int) SegInt {
			return sectionSegments[segmentIndex].ToAddressSegment().GetSegmentValue()
		},
		func(segmentIndex int) SegInt {
			return sectionSegments[segmentIndex].ToAddressSegment().GetUpperSegmentValue()
		},
		segmentCount,
		seg.GetByteCount(),
		seg.GetBitCount(),
		seg.ToAddressSegment().GetMaxValue(),
		networkPrefixLength,
		fullRangeOnly)
}

func applyPrefixToSegments(
	sectionPrefixBits BitCount,
	segments []*AddressDivision,
	segmentBitCount BitCount,
	segmentByteCount int,
	segProducer func(*AddressDivision, PrefixLen) *AddressDivision) {
	var i int
	if sectionPrefixBits != 0 {
		i = getNetworkSegmentIndex(sectionPrefixBits, segmentByteCount, segmentBitCount)
	}
	for ; i < len(segments); i++ {
		pref := getPrefixedSegmentPrefixLength(segmentBitCount, sectionPrefixBits, i)
		if pref != nil {
			segments[i] = segProducer(segments[i], pref)
		}
	}
}

func normalizePrefixBoundary(
	sectionPrefixBits BitCount,
	segments []*AddressDivision,
	segmentBitCount BitCount,
	segmentByteCount int,
	segmentCreator func(val, upperVal SegInt, prefLen PrefixLen) *AddressDivision) {
	//we've already verified segment prefixes.  We simply need to check the case where the prefix is at a segment boundary,
	//whether the network side has the correct prefix
	networkSegmentIndex := getNetworkSegmentIndex(sectionPrefixBits, segmentByteCount, segmentBitCount)
	if networkSegmentIndex >= 0 {
		segment := segments[networkSegmentIndex].ToIPAddressSegment()
		if !segment.IsPrefixed() {
			segments[networkSegmentIndex] = segmentCreator(segment.GetSegmentValue(), segment.GetUpperSegmentValue(), cacheBitCount(segmentBitCount))
		}
	}
}

func toSegments(
	bytes []byte,
	segmentCount int,
	bytesPerSegment int,
	bitsPerSegment BitCount,
	expectedByteCount int,
	creator AddressSegmentCreator,
	prefixLength PrefixLen) (segments []*AddressDivision, err AddressValueException) {

	//We allow two formats of bytes:
	//1. two's complement: top bit indicates sign.  Ranging over all 16-byte lengths gives all addresses, from both positive and negative numbers
	//  Also, we allow sign extension to shorter and longer byte lengths.  For example, -1, -1, -2 is the same as just -2.  So if this were IPv4, we allow -1, -1, -1, -1, -2 and we allow -2.
	//  This is compatible with BigInteger.  If we have a positive number like 2, we allow 0, 0, 0, 0, 2 and we allow just 2.
	//  But the top bit must be 0 for 0-sign extension. So if we have 255 as a positive number, we allow 0, 255 but not 255.
	//  Just 255 is considered negative and equivalent to -1, and extends to -1, -1, -1, -1 or the address 255.255.255.255, not 0.0.0.255
	//
	//2. Unsigned values
	//  We interpret 0, -1, -1, -1, -1 as 255.255.255.255 even though this is not a sign extension of -1, -1, -1, -1.
	//  In this case, we also allow any 4 byte value to be considered a positive unsigned number, and thus we always allow leading zeros.
	//  In the case of extending byte array values that are shorter than the required length,
	//  unsigned values must have a leading zero in cases where the top bit is 1, because the two's complement format takes precedence.
	//  So the single value 255 must have an additional 0 byte in front to be considered unsigned, as previously shown.
	//  The single value 255 is considered -1 and is extended to become the address 255.255.255.255,
	//  but for the unsigned positive value 255 you must use the two bytes 0, 255 which become the address 0.0.0.255.
	//  Once again, this is compatible with BigInteger.
	byteLen := len(bytes)
	missingBytes := expectedByteCount - byteLen
	startIndex := 0

	//First we handle the situation where we have too many bytes.  Extra bytes can be all zero-bits, or they can be the negative sign extension of all one-bits.
	if missingBytes < 0 {
		expectedStartIndex := byteLen - expectedByteCount
		higherStartIndex := expectedStartIndex - 1
		expectedExtendedValue := bytes[higherStartIndex]
		if expectedExtendedValue != 0 {
			mostSignificantBit := bytes[expectedStartIndex] >> 7
			if mostSignificantBit != 0 {
				if expectedExtendedValue != 0xff { //0xff or -1
					err = &addressValueException{
						addressException: addressException{key: "ipaddress.error.exceeds.size"},
						val:              int(expectedExtendedValue),
					}
					return
				}
			} else {
				err = &addressValueException{
					addressException: addressException{key: "ipaddress.error.exceeds.size"},
					val:              int(expectedExtendedValue),
				}
				return
			}
		}
		for startIndex < higherStartIndex {
			higherStartIndex--
			if bytes[higherStartIndex] != expectedExtendedValue {
				err = &addressValueException{
					addressException: addressException{key: "ipaddress.error.exceeds.size"},
					val:              int(expectedExtendedValue),
				}
				return
			}
		}
		startIndex = expectedStartIndex
		missingBytes = 0
	}
	segments = createSegmentArray(segmentCount)
	for i, segmentIndex := 0, 0; i < expectedByteCount; segmentIndex++ {
		segmentPrefixLength := getSegmentPrefixLength(bitsPerSegment, prefixLength, segmentIndex)
		var value SegInt
		k := bytesPerSegment + i
		j := i
		if j < missingBytes {
			mostSignificantBit := bytes[startIndex] >> 7
			if mostSignificantBit == 0 { //sign extension
				j = missingBytes
			} else { //sign extension
				upper := k
				if missingBytes < k {
					upper = missingBytes
				}
				for ; j < upper; j++ {
					value <<= 8
					value |= 0xff
				}
			}
		}
		for ; j < k; j++ {
			byteValue := bytes[startIndex+j-missingBytes]
			value <<= 8
			value |= SegInt(byteValue)
		}
		i = k
		seg := creator.createSegment(value, value, segmentPrefixLength)
		segments[segmentIndex] = seg
	}
	return
}

func createSegmentsUint64(
	segments []*AddressDivision, // empty
	highBytes,
	lowBytes uint64,
	bytesPerSegment int,
	bitsPerSegment BitCount,
	creator AddressSegmentCreator,
	prefixLength PrefixLen) []*AddressDivision {
	segmentMask := ^(^SegInt(0) << bitsPerSegment)
	lowSegCount := getHostSegmentIndex(64, bytesPerSegment, bitsPerSegment)
	segLen := len(segments)
	lowIndex := segLen - lowSegCount
	if lowIndex < 0 {
		lowIndex = 0
	}
	segmentIndex := segLen - 1
	bytes := lowBytes
	for {
		for {
			segmentPrefixLength := getSegmentPrefixLength(bitsPerSegment, prefixLength, segmentIndex)
			value := segmentMask & SegInt(bytes)
			seg := creator.createSegment(value, value, segmentPrefixLength)
			segments[segmentIndex] = seg
			segmentIndex--
			if segmentIndex < lowIndex {
				break
			}
			bytes >>= bitsPerSegment
		}
		if lowIndex == 0 {
			break
		}
		lowIndex = 0
		bytes = highBytes
	}
	return segments
}

func createSegments(
	lowerValueProvider,
	upperValueProvider SegmentValueProvider,
	segmentCount int,
	bitsPerSegment BitCount,
	creator AddressSegmentCreator,
	prefixLength PrefixLen) (segments []*AddressDivision, isMultiple bool) {
	segments = createSegmentArray(segmentCount)
	for segmentIndex := 0; segmentIndex < segmentCount; segmentIndex++ {
		segmentPrefixLength := getSegmentPrefixLength(bitsPerSegment, prefixLength, segmentIndex)
		var value, value2 SegInt = 0, 0
		if lowerValueProvider == nil {
			value = upperValueProvider(segmentIndex)
			value2 = value
		} else {
			value = lowerValueProvider(segmentIndex)
			if upperValueProvider != nil {
				value2 = upperValueProvider(segmentIndex)
				if !isMultiple && value2 != value {
					isMultiple = true

				}
			} else {
				value2 = value
			}
		}
		seg := creator.createSegment(value, value2, segmentPrefixLength)
		segments[segmentIndex] = seg
	}
	return
}

func setPrefixLength(
	original *AddressSection,
	networkPrefixLength BitCount,
	withZeros bool,
) (res *AddressSection, err IncompatibleAddressException) {
	existingPrefixLength := original.GetPrefixLength()
	if existingPrefixLength != nil && networkPrefixLength == *existingPrefixLength {
		res = original
		return
	}
	checkSubnet(original, networkPrefixLength)
	var minPrefIndex, maxPrefIndex int
	var minPrefLen, maxPrefLen BitCount
	verifyMask := false
	bitsPerSegment := original.GetBitsPerSegment()
	bytesPerSegment := original.GetBytesPerSegment()
	prefIndex := getNetworkSegmentIndex(networkPrefixLength, bytesPerSegment, bitsPerSegment)
	var startIndex int
	if existingPrefixLength != nil {
		existingPrefLen := *existingPrefixLength
		existingPrefIndex := getNetworkSegmentIndex(existingPrefLen, bytesPerSegment, bitsPerSegment)
		verifyMask = true
		if prefIndex > existingPrefIndex {
			maxPrefIndex = prefIndex
			minPrefIndex = existingPrefIndex
		} else {
			maxPrefIndex = existingPrefIndex
			minPrefIndex = prefIndex
		}
		if withZeros {
			if networkPrefixLength < existingPrefLen {
				minPrefLen = networkPrefixLength
				maxPrefLen = existingPrefLen
			} else {
				minPrefLen = existingPrefLen
				maxPrefLen = networkPrefixLength
			}
			startIndex = minPrefIndex
		} else {
			startIndex = minPrefIndex
			minPrefIndex = original.GetSegmentCount() // used for zeroing, so setting it to the end causes no zeroing
		}
	} else {
		minPrefIndex = original.GetSegmentCount()
		startIndex = prefIndex
	}
	maxVal := original.GetMaxSegmentValue()
	return getSubnetSegments(
		original,
		startIndex,
		cacheBitCount(networkPrefixLength),
		verifyMask,
		func(i int) *AddressDivision {
			return original.getDivision(i)
		},
		func(i int) SegInt {
			if i >= minPrefIndex {
				if i <= maxPrefIndex {
					minSegPrefLen := *getPrefixedSegmentPrefixLength(bitsPerSegment, minPrefLen, i)
					minMask := maxVal << (bitsPerSegment - minSegPrefLen)
					maxSegPrefLen := getPrefixedSegmentPrefixLength(bitsPerSegment, maxPrefLen, i)
					if maxSegPrefLen != nil {
						maxMask := maxVal << (bitsPerSegment - minSegPrefLen)
						return minMask | maxMask
					}
					return minMask
				}
			}
			return maxVal
		})
}

func getSubnetSegments( // called by methods to adjust/remove/setPrefixLength, masking methods, zero host and zero network methods
	original *AddressSection,
	startIndex int,
	networkPrefixLength PrefixLen,
	verifyMask bool,
	segProducer func(int) *AddressDivision,
	segmentMaskProducer func(int) SegInt,
) (res *AddressSection, err IncompatibleAddressException) {
	if networkPrefixLength != nil {
		prefLen := *networkPrefixLength
		if prefLen < 0 {
			networkPrefixLength = cacheBits(0)
		} else {
			if addressBitLength := original.GetBitCount(); prefLen > addressBitLength {
				networkPrefixLength = cacheBitCount(addressBitLength)
			}
		}
	}
	bitsPerSegment := original.GetBitsPerSegment()
	count := original.GetSegmentCount()
	for i := startIndex; i < count; i++ {
		segmentPrefixLength := getSegmentPrefixLength(bitsPerSegment, networkPrefixLength, i)
		seg := segProducer(i)
		//note that the mask can represent a range (for example a CIDR mask),
		//but we use the lowest value (maskSegment.value) in the range when masking (ie we discard the range)
		maskValue := segmentMaskProducer(i)
		origValue, origUpperValue := seg.getSegmentValue(), seg.getUpperSegmentValue()
		value, upperValue := origValue, origUpperValue
		if verifyMask {
			mask64 := uint64(maskValue)
			val64 := uint64(value)
			upperVal64 := uint64(upperValue)
			masker := maskRange(val64, upperVal64, mask64, seg.GetMaxValue())
			if !masker.IsSequential() {
				err = &incompatibleAddressException{addressException{key: "ipaddress.error.maskMismatch"}}
				return
			}
			value = SegInt(masker.GetMaskedLower(val64, mask64))
			upperValue = SegInt(masker.GetMaskedUpper(upperVal64, mask64))
		} else {
			value &= maskValue
			upperValue &= maskValue
		}
		if !segsSame(segmentPrefixLength, seg.getDivisionPrefixLength(), value, origValue, upperValue, origUpperValue) {
			newSegments := createSegmentArray(count)
			original.copySubSegmentsToSlice(0, i, newSegments)
			newSegments[i] = createAddressDivision(seg.deriveNewMultiSeg(value, upperValue, segmentPrefixLength))
			for i++; i < count; i++ {
				segmentPrefixLength = getSegmentPrefixLength(bitsPerSegment, networkPrefixLength, i)
				seg = segProducer(i)
				maskValue = segmentMaskProducer(i)
				origValue, origUpperValue = seg.getSegmentValue(), seg.getUpperSegmentValue()
				value, upperValue = origValue, origUpperValue
				if verifyMask {
					mask64 := uint64(maskValue)
					val64 := uint64(value)
					upperVal64 := uint64(upperValue)
					masker := maskRange(val64, upperVal64, mask64, seg.GetMaxValue())
					if !masker.IsSequential() {
						err = &incompatibleAddressException{addressException{key: "ipaddress.error.maskMismatch"}}
						return
					}
					value = SegInt(masker.GetMaskedLower(val64, mask64))
					upperValue = SegInt(masker.GetMaskedUpper(upperVal64, mask64))
				} else {
					value &= maskValue
					upperValue &= maskValue
				}
				if !segsSame(segmentPrefixLength, seg.getDivisionPrefixLength(), value, origValue, upperValue, origUpperValue) {
					newSegments[i] = createAddressDivision(seg.deriveNewMultiSeg(value, upperValue, segmentPrefixLength))
				} else {
					newSegments[i] = seg
				}
			}
			res = deriveAddressSectionPrefLen(original, newSegments, networkPrefixLength)
			//res = creator(newSegments, networkPrefixLength)
			return
		}
	}
	res = original
	return
}

func getOredSegments(
	original *IPAddressSection,
	networkPrefixLength PrefixLen,
	verifyMask bool,
	segProducer func(int) *AddressDivision,
	segmentMaskProducer func(int) SegInt,
	singleOnly bool) (res *IPAddressSection, err IncompatibleAddressException) {

	if networkPrefixLength != nil {
		prefLen := *networkPrefixLength
		if prefLen < 0 {
			networkPrefixLength = cacheBits(0)
		} else {
			if addressBitLength := original.GetBitCount(); prefLen > addressBitLength {
				networkPrefixLength = cacheBitCount(addressBitLength)
			}
		}
	}
	bitsPerSegment := original.GetBitsPerSegment()
	count := original.GetSegmentCount()
	for i := 0; i < count; i++ {
		segmentPrefixLength := getSegmentPrefixLength(bitsPerSegment, networkPrefixLength, i)
		seg := segProducer(i)
		//note that the mask can represent a range (for example a CIDR mask),
		//but we use the lowest value (maskSegment.value) in the range when masking (ie we discard the range)
		maskValue := segmentMaskProducer(i)
		origValue, origUpperValue := seg.getSegmentValue(), seg.getUpperSegmentValue()
		value, upperValue := origValue, origUpperValue
		if verifyMask {
			mask64 := uint64(maskValue)
			val64 := uint64(value)
			upperVal64 := uint64(upperValue)
			masker := bitwiseOrRange(val64, upperVal64, mask64, seg.GetMaxValue())
			if !masker.IsSequential() {
				err = &incompatibleAddressException{addressException{key: "ipaddress.error.maskMismatch"}}
				return
			}
			value = SegInt(masker.GetOredLower(val64, mask64))
			upperValue = SegInt(masker.GetOredUpper(upperVal64, mask64))
		} else {
			value |= maskValue
			upperValue |= maskValue
		}
		if !segsSame(segmentPrefixLength, seg.getDivisionPrefixLength(), value, origValue, upperValue, origUpperValue) {
			newSegments := createSegmentArray(count)
			original.copySubSegmentsToSlice(0, i, newSegments)
			newSegments[i] = createAddressDivision(seg.deriveNewMultiSeg(value, upperValue, segmentPrefixLength))
			for i++; i < count; i++ {
				segmentPrefixLength = getSegmentPrefixLength(bitsPerSegment, networkPrefixLength, i)
				seg = segProducer(i)
				maskValue = segmentMaskProducer(i)
				value = seg.getSegmentValue()
				upperValue = seg.getUpperSegmentValue()
				if verifyMask {
					mask64 := uint64(maskValue)
					val64 := uint64(value)
					upperVal64 := uint64(upperValue)
					masker := bitwiseOrRange(val64, upperVal64, mask64, seg.GetMaxValue())
					if !masker.IsSequential() {
						err = &incompatibleAddressException{addressException{key: "ipaddress.error.maskMismatch"}}
						return
					}
					value = SegInt(masker.GetOredLower(val64, mask64))
					upperValue = SegInt(masker.GetOredUpper(upperVal64, mask64))

				} else {
					value |= maskValue
					upperValue |= maskValue
				}
				if !segsSame(segmentPrefixLength, seg.getDivisionPrefixLength(), value, origValue, upperValue, origUpperValue) {
					newSegments[i] = createAddressDivision(seg.deriveNewMultiSeg(value, upperValue, segmentPrefixLength))
				} else {
					newSegments[i] = seg
				}
			}
			res = deriveIPAddressSectionSingle(original, newSegments, networkPrefixLength, singleOnly)
			return
		}
	}
	res = original
	return
}

func checkSectionCounts(sections []ExtendedIPSegmentSeries) SizeMismatchException {
	if length := len(sections); length > 1 {
		segCount := sections[0].GetSegmentCount()
		for i := 1; i < length; i++ {
			section := sections[i]
			if section == nil {
				continue
			}
			if section.GetSegmentCount() != segCount {
				return &sizeMismatchException{incompatibleAddressException{addressException{key: "ipaddress.error.sizeMismatch"}}}
			}
		}
	}
	return nil
}
