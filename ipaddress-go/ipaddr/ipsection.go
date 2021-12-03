package ipaddr

import (
	"math/big"
	"sync/atomic"
	"unsafe"
)

func createIPSection(segments []*AddressDivision, prefixLength PrefixLen, addrType addrType) *IPAddressSection {
	sect := &IPAddressSection{
		ipAddressSectionInternal{
			addressSectionInternal{
				addressDivisionGroupingInternal{
					addressDivisionGroupingBase: addressDivisionGroupingBase{
						divisions:    standardDivArray{segments},
						addrType:     addrType,
						cache:        &valueCache{},
						prefixLength: prefixLength,
					},
				},
			},
		},
	}
	assignStringCache(&sect.addressDivisionGroupingBase, addrType)
	return sect
}

func createInitializedIPSection(segments []*AddressDivision, prefixLength PrefixLen, addrType addrType) *IPAddressSection {
	result := createIPSection(segments, prefixLength, addrType)
	_ = result.initMultAndPrefLen() // assigns isMult and checks prefix length
	return result
}

func deriveIPAddressSection(from *IPAddressSection, segments []*AddressDivision) (res *IPAddressSection) {
	res = createIPSection(segments, nil, from.getAddrType())
	_ = res.initMultAndPrefLen()
	return
}

func deriveIPAddressSectionPrefLen(from *IPAddressSection, segments []*AddressDivision, prefixLength PrefixLen) (res *IPAddressSection) {
	res = createIPSection(segments, prefixLength, from.getAddrType())
	_ = res.initMultAndPrefLen()
	return
}

//func deriveIPAddressSectionPrefLen(from *IPAddressSection, segments []*AddressDivision, prefixLength PrefixLen) (res *IPAddressSection) {
//	res = createIPSection(segments, from.getAddrType(), from.addressSegmentIndex)
//	assignPrefixSubnet(prefixLength, segments, res)
//	return
//}

func deriveIPAddressSectionSingle(from *IPAddressSection, segments []*AddressDivision /* cloneSegments bool,*/, prefixLength PrefixLen, singleOnly bool) (res *IPAddressSection) {
	res = deriveIPAddressSectionPrefLen(from, segments, prefixLength)
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
	return IndeterminateIPVersion
}

func (section *ipAddressSectionInternal) GetNetworkPrefixLen() PrefixLen {
	return section.prefixLength
}

//func (section *ipAddressSectionInternal) CompareSize(other AddressDivisionSeries) int {
//	//func (section *ipAddressSectionInternal) CompareSize(other *IPAddressSection) int {
//	if !section.isMult() {
//		if other.isMult() {
//			return -1
//		}
//		return 0
//	}
//	if !other.isMult() {
//		return 1
//	}
//	if otherGrouping, ok := other.(StandardDivisionGroupingType); ok { Without caching, this is no faster
//		otherSeries := otherGrouping.ToAddressDivisionGrouping()
//		if section.IsSinglePrefixBlock() && otherSeries.IsSinglePrefixBlock() {
//			bits := section.GetBitCount() - section.GetPrefixLen()
//			otherBits := other.GetBitCount() - otherSeries.GetPrefixLen()
//			return bits - otherBits
//		}
//	}
//	return section.getCount().CmpAbs(other.getCount())
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
func (section *ipAddressSectionInternal) GetBlockMaskPrefixLen(network bool) PrefixLen {
	cache := section.cache
	if cache == nil {
		return nil // no prefix
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
					checkingHostBack = false
					prefixedSeg = i
				} else {
					return
				}
			} else if segHostMaskLen != nil {
				if checkingHostFront {
					prefixedSegPrefixLen = *segHostMaskLen
					checkingHostBack = true
					checkingNetworkBack = false
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
		networkMaskLen = cacheBitCount(section.GetBitCount())
		hostMaskLen = cacheBitCount(0)
	} else if checkingHostFront {
		// all zeros
		hostMaskLen = cacheBitCount(section.GetBitCount())
		networkMaskLen = cacheBitCount(0)
	} else if checkingNetworkBack {
		// ending in zeros, network mask
		networkMaskLen = getNetworkPrefixLen(firstSeg.GetBitCount(), prefixedSegPrefixLen, prefixedSeg)
	} else if checkingHostBack {
		// ending in ones, host mask
		hostMaskLen = getNetworkPrefixLen(firstSeg.GetBitCount(), prefixedSegPrefixLen, prefixedSeg)
	}
	return
}

func (section *ipAddressSectionInternal) IncludesZeroHost() bool {
	networkPrefixLength := section.GetPrefixLen()
	return networkPrefixLength != nil && section.IncludesZeroHostLen(*networkPrefixLength)
}

func (section *ipAddressSectionInternal) IncludesZeroHostLen(networkPrefixLength BitCount) bool {
	networkPrefixLength = checkSubnet(section.toIPAddressSection(), networkPrefixLength)
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
	networkPrefixLength := section.GetPrefixLen()
	return networkPrefixLength != nil && section.IncludesMaxHostLen(*networkPrefixLength)
}

func (section *ipAddressSectionInternal) IncludesMaxHostLen(networkPrefixLength BitCount) bool {
	networkPrefixLength = checkSubnet(section.toIPAddressSection(), networkPrefixLength)
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

func (section *ipAddressSectionInternal) toZeroHost(boundariesOnly bool) (res *IPAddressSection, err IncompatibleAddressError) {
	segmentCount := section.GetSegmentCount()
	if segmentCount == 0 {
		return section.toIPAddressSection(), nil
	}
	var prefLen BitCount
	if section.IsPrefixed() {
		prefLen = *section.GetPrefixLen()
	}
	if section.IsZeroHostLen(prefLen) {
		return section.toIPAddressSection(), nil
	}
	if section.IncludesZeroHost() && section.IsSingleNetwork() {
		res = section.getLower().ToIPAddressSection() //cached
		return
	}
	if !section.IsPrefixed() {
		mask := section.addrType.getIPNetwork().GetPrefixedNetworkMask(0)
		res = mask.GetSubSection(0, segmentCount)
		return
	}
	return section.createZeroHost(prefLen, boundariesOnly)
	//return sect.ToIPAddressSection(), err
}

// boundariesOnly: whether we care if the masking works for all values in a range.
// For instance, 1.2.3.2-4/31 cannot be zero-hosted, because applyng to the boundaries results in 1.2.3.2-4/31,
// and that includes 1.2.3.3/31 which does not have host of zero.
// So in that case, we'd normally have IncompatibleAddressError.  boundariesOnly as true avoids the exception,
// if we are really just interested in getting the zero-host boundaries,
// and we don't care about the remaining values in-between.
func (section *ipAddressSectionInternal) createZeroHost(prefLen BitCount, boundariesOnly bool) (*IPAddressSection, IncompatibleAddressError) {
	mask := section.addrType.getIPNetwork().GetNetworkMask(prefLen)
	return section.getSubnetSegments(
		getNetworkSegmentIndex(prefLen, section.GetBytesPerSegment(), section.GetBitsPerSegment()),
		cacheBitCount(prefLen),
		!boundariesOnly, //verifyMask
		section.getDivision,
		func(i int) SegInt { return mask.GetSegment(i).GetSegmentValue() })
}

func (section *ipAddressSectionInternal) toZeroHostLen(prefixLength BitCount) (*IPAddressSection, IncompatibleAddressError) {
	var minIndex int
	if section.IsPrefixed() {
		existingPrefLen := *section.GetNetworkPrefixLen()
		if prefixLength == existingPrefLen {
			return section.toZeroHost(false)
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
	return section.getSubnetSegments(
		minIndex,
		nil,
		true,
		section.getDivision,
		func(i int) SegInt { return mask.GetSegment(i).GetSegmentValue() })
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
	prefixLength := section.GetNetworkPrefixLen() // we know it is prefixed here so no panic on the derefence
	mask := section.addrType.getIPNetwork().GetHostMask(*prefixLength)
	res, _ := section.getSubnetSegments(
		0,
		prefixLength,
		false,
		section.getDivision,
		func(i int) SegInt { return mask.GetSegment(i).GetSegmentValue() })
	return res
}

func (section *ipAddressSectionInternal) toMaxHost() (res *IPAddressSection, err IncompatibleAddressError) {
	segmentCount := section.GetSegmentCount()
	if segmentCount == 0 {
		return section.toIPAddressSection(), nil
	}
	if !section.IsPrefixed() {
		mask := section.addrType.getIPNetwork().GetPrefixedHostMask(0)
		res = mask.GetSubSection(0, segmentCount)
		return
	}
	if section.IsMaxHostLen(*section.GetPrefixLen()) {
		return section.toIPAddressSection(), nil
	}
	if section.IncludesMaxHost() && section.IsSingleNetwork() {
		return section.getUpper().ToIPAddressSection(), nil // cached
	}
	return section.createMaxHost()
}

func (section *ipAddressSectionInternal) createMaxHost() (*IPAddressSection, IncompatibleAddressError) {
	prefixLength := section.GetNetworkPrefixLen() // we know it is prefixed here so no panic on the derefence
	mask := section.addrType.getIPNetwork().GetHostMask(*prefixLength)
	return section.getOredSegments(
		prefixLength,
		true,
		section.getDivision,
		func(i int) SegInt { return mask.GetSegment(i).GetSegmentValue() })
}

func (section *ipAddressSectionInternal) toMaxHostLen(prefixLength BitCount) (*IPAddressSection, IncompatibleAddressError) {
	if section.IsPrefixed() && prefixLength == *section.GetNetworkPrefixLen() {
		return section.toMaxHost()
	}
	mask := section.addrType.getIPNetwork().GetHostMask(prefixLength)
	return section.getOredSegments(
		nil,
		true,
		section.getDivision,
		func(i int) SegInt { return mask.GetSegment(i).GetSegmentValue() })
}

// IsSingleNetwork returns whether the network section of the address, the prefix, consists of a single value
func (section *ipAddressSectionInternal) IsSingleNetwork() bool {
	networkPrefixLength := section.GetNetworkPrefixLen()
	if networkPrefixLength == nil {
		return !section.isMultiple()
	}
	prefLen := *networkPrefixLength
	if prefLen >= section.GetBitCount() {
		return !section.isMultiple()
	}
	bitsPerSegment := section.GetBitsPerSegment()
	prefixedSegmentIndex := getNetworkSegmentIndex(prefLen, section.GetBytesPerSegment(), bitsPerSegment)
	if prefixedSegmentIndex < 0 {
		return true
	}
	for i := 0; i < prefixedSegmentIndex; i++ {
		if section.getDivision(i).isMultiple() {
			return false
		}
	}
	div := section.GetSegment(prefixedSegmentIndex)
	divPrefLen := getPrefixedSegmentPrefixLength(bitsPerSegment, prefLen, prefixedSegmentIndex)
	shift := bitsPerSegment - *divPrefLen
	return (div.GetSegmentValue() >> uint(shift)) == (div.GetUpperSegmentValue() >> uint(shift))
}

// IsMaxHost returns whether this section has a prefix length and if so,
// whether the host section is the maximum value for this section or all sections in this set of address sections.
// If the host section is zero length (there are no host bits at all), returns false.
func (section *ipAddressSectionInternal) IsMaxHost() bool {
	if !section.IsPrefixed() {
		return false
	}
	return section.IsMaxHostLen(*section.GetNetworkPrefixLen())
}

// IsMaxHostLen returns whether the host is the max value for the given prefix length for this section.
// If this section already has a prefix length, then that prefix length is ignored.
// If the host section is zero length (there are no host bits at all), returns true.
func (section *ipAddressSectionInternal) IsMaxHostLen(prefLen BitCount) bool {
	divCount := section.GetSegmentCount()
	if divCount == 0 {
		return true
	} else if prefLen < 0 {
		prefLen = 0
	}
	bytesPerSegment := section.GetBytesPerSegment()
	bitsPerSegment := section.GetBitsPerSegment()
	// Note: 1.2.3.4/32 has a max host
	prefixedSegmentIndex := getHostSegmentIndex(prefLen, bytesPerSegment, bitsPerSegment)
	if prefixedSegmentIndex < divCount {
		segmentPrefixLength := getPrefixedSegmentPrefixLength(bitsPerSegment, prefLen, prefixedSegmentIndex)
		i := prefixedSegmentIndex
		div := section.GetSegment(i)
		mask := div.GetSegmentHostMask(*segmentPrefixLength)
		if div.isMultiple() || (mask&div.getSegmentValue()) != mask {
			return false
		}
		i++
		for ; i < divCount; i++ {
			div = section.GetSegment(i)
			if !div.IsMax() {
				return false
			}
		}
	}
	return true
}

// IsZeroHost returns whether this section has a prefix length and if so,
// whether the host section is zero for this section or all sections in this set of address sections.
func (section *ipAddressSectionInternal) IsZeroHost() bool {
	if !section.IsPrefixed() {
		return false
	}
	return section.IsZeroHostLen(*section.GetNetworkPrefixLen())
}

// IsZeroHostLen returns whether the host is zero for the given prefix length for this section or all sections in this set of address sections.
// If this section already has a prefix length, then that prefix length is ignored.
// If the host section is zero length (there are no host bits at all), returns true.
func (section *ipAddressSectionInternal) IsZeroHostLen(prefLen BitCount) bool {
	segmentCount := section.GetSegmentCount()
	if segmentCount == 0 {
		return true
	} else if prefLen < 0 {
		prefLen = 0
	}
	bitsPerSegment := section.GetBitsPerSegment()
	// Note: 1.2.3.4/32 has a zero host
	prefixedSegmentIndex := getHostSegmentIndex(prefLen, section.GetBytesPerSegment(), bitsPerSegment)
	if prefixedSegmentIndex < segmentCount {
		segmentPrefixLength := getPrefixedSegmentPrefixLength(bitsPerSegment, prefLen, prefixedSegmentIndex)
		//if segmentPrefixLength != nil {
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
		//}
	}
	return true
}

func (section *ipAddressSectionInternal) adjustPrefixLength(adjustment BitCount, withZeros bool) (*IPAddressSection, IncompatibleAddressError) {
	if adjustment == 0 && section.IsPrefixed() {
		return section.toIPAddressSection(), nil
	}
	prefix := section.getAdjustedPrefix(adjustment, true, true)
	//prefix := original.getAdjustedPrefix(adjustment, false, false)
	//bitCount := original.GetBitCount()
	//if prefix > bitCount {
	//	xxxx
	//	if !original.IsPrefixed() {
	//		res = original.toIPAddressSection()
	//		return
	//	}
	//	var maskPrefix BitCount
	//	if withZeros {
	//		maskPrefix = *original.GetNetworkPrefixLen()
	//	} else {
	//		maskPrefix = bitCount
	//	}
	//	mask := original.addrType.getIPNetwork().GetNetworkMask(maskPrefix)
	//	return original.getSubnetSegments(
	//		0,
	//		nil,
	//		withZeros,
	//		original.getDivision,
	//		func(i int) SegInt { return mask.GetSegment(i).GetSegmentValue() })
	//}
	//if prefix < 0 {
	//	prefix = 0
	//}
	sec, err := section.setPrefixLength(prefix, withZeros)
	return sec.ToIPAddressSection(), err
}

func (section *ipAddressSectionInternal) adjustPrefixLen(adjustment BitCount) *IPAddressSection {
	// no zeroing
	res, _ := section.adjustPrefixLength(adjustment, false)
	return res
}

func (section *ipAddressSectionInternal) adjustPrefixLenZeroed(adjustment BitCount) (*IPAddressSection, IncompatibleAddressError) {
	return section.adjustPrefixLength(adjustment, true)
}

func (section *ipAddressSectionInternal) withoutPrefixLen() *IPAddressSection {
	if !section.IsPrefixed() {
		return section.toIPAddressSection()
	}
	if section.hasNoDivisions() {
		return createIPSection(section.getDivisionsInternal(), nil, section.getAddrType())
	}
	existingPrefixLength := *section.GetPrefixLen()
	maxVal := section.GetMaxSegmentValue()
	var startIndex int
	if existingPrefixLength > 0 {
		bitsPerSegment := section.GetBitsPerSegment()
		bytesPerSegment := section.GetBytesPerSegment()
		startIndex = getNetworkSegmentIndex(existingPrefixLength, bytesPerSegment, bitsPerSegment)
	}
	res, _ := section.getSubnetSegments(
		startIndex,
		nil,
		false,
		func(i int) *AddressDivision {
			return section.getDivision(i)
		},
		func(i int) SegInt {
			return maxVal
		},
	)
	return res
}

func (section *ipAddressSectionInternal) checkSectionCount(other *IPAddressSection) SizeMismatchError {
	if other.GetSegmentCount() < section.GetSegmentCount() {
		return &sizeMismatchError{incompatibleAddressError{addressError{key: "ipaddress.error.sizeMismatch"}}}
	}
	return nil
}

// error can be IncompatibleAddressError or SizeMismatchError
func (section *ipAddressSectionInternal) mask(msk *IPAddressSection, retainPrefix bool) (*IPAddressSection, IncompatibleAddressError) {
	if err := section.checkSectionCount(msk); err != nil {
		return nil, err
	}
	var prefLen PrefixLen
	if retainPrefix {
		prefLen = section.GetPrefixLen()
	}
	return section.getSubnetSegments(
		0,
		prefLen,
		true,
		section.getDivision,
		func(i int) SegInt { return msk.GetSegment(i).GetSegmentValue() })
}

// error can be IncompatibleAddressError or SizeMismatchError
func (section *ipAddressSectionInternal) bitwiseOr(msk *IPAddressSection, retainPrefix bool) (*IPAddressSection, IncompatibleAddressError) {
	if err := section.checkSectionCount(msk); err != nil {
		return nil, err
	}
	var prefLen PrefixLen
	if retainPrefix {
		prefLen = section.GetPrefixLen()
	}
	return section.getOredSegments(
		prefLen,
		true,
		section.getDivision,
		func(i int) SegInt { return msk.GetSegment(i).GetSegmentValue() })
}

func (section *ipAddressSectionInternal) matchesWithMask(other *IPAddressSection, mask *IPAddressSection) bool {
	if err := section.checkSectionCount(other); err != nil {
		return false
	} else if err := section.checkSectionCount(mask); err != nil {
		return false
	}
	divCount := section.GetSegmentCount()
	for i := 0; i < divCount; i++ {
		seg := section.GetSegment(i)
		maskSegment := mask.GetSegment(i)
		otherSegment := other.GetSegment(i)
		if !seg.MatchesValsWithMask(
			otherSegment.getSegmentValue(),
			otherSegment.getUpperSegmentValue(),
			maskSegment.getSegmentValue()) {
			return false
		}
	}
	return true
}

func (section *ipAddressSectionInternal) intersect(
	other *IPAddressSection,
	//IntFunction<S> segProducer,
	//IntFunction<S> otherSegProducer
) (res *IPAddressSection, err SizeMismatchError) {

	//check if they are comparable section.  We only check segment count, we do not care about start index.
	err = section.checkSectionCount(other)
	if err != nil {
		return
	}

	//larger prefix length should prevail?    hmmmmm... I would say that is true, choose the larger prefix
	pref := section.GetNetworkPrefixLen()
	otherPref := other.GetNetworkPrefixLen()
	if pref != nil {
		if otherPref != nil {
			if *otherPref > *pref {
				pref = otherPref
			}
		} else {
			pref = nil
		}
	}

	if other.Contains(section.toIPAddressSection()) {
		if PrefixEquals(pref, section.GetNetworkPrefixLen()) {
			res = section.toIPAddressSection()
			return
		}
	} else if !section.isMultiple() {
		return
	}
	if section.contains(other) {
		if PrefixEquals(pref, other.GetNetworkPrefixLen()) {
			res = other.toIPAddressSection()
			return
		}
	} else if !other.isMultiple() {
		return
	}

	segCount := section.GetSegmentCount()
	for i := 0; i < segCount; i++ {
		seg := section.GetSegment(i)
		otherSeg := other.GetSegment(i)
		lower := seg.GetSegmentValue()
		higher := seg.getUpperSegmentValue()
		otherLower := otherSeg.GetSegmentValue()
		otherHigher := otherSeg.getUpperSegmentValue()
		if otherLower > higher || lower > otherHigher {
			//no overlap in this segment means no overlap at all
			return
		}
	}

	// all segments have overlap
	segs := createSegmentArray(segCount)
	for i := 0; i < segCount; i++ {
		seg := section.GetSegment(i)
		otherSeg := other.GetSegment(i)
		segPref := getSegmentPrefixLength(seg.getBitCount(), pref, i)
		if seg.Contains(otherSeg) {
			if PrefixEquals(segPref, otherSeg.GetSegmentPrefixLen()) {
				segs[i] = otherSeg.ToAddressDivision()
				continue
			}
		}
		if otherSeg.Contains(seg) {
			if PrefixEquals(segPref, seg.GetSegmentPrefixLen()) {
				segs[i] = seg.ToAddressDivision()
				continue
			}
		}
		lower := seg.GetSegmentValue()
		higher := seg.getUpperSegmentValue()
		otherLower := otherSeg.GetSegmentValue()
		otherHigher := otherSeg.getUpperSegmentValue()
		if otherLower > lower {
			lower = otherLower
		}
		if otherHigher < higher {
			higher = otherHigher
		}
		segs[i] = createAddressDivision(seg.deriveNewMultiSeg(lower, higher, segPref))
		//int newLower = Math.max(lower, otherLower);
		//int newHigher = Math.min(higher, otherHigher);
		//segs[i] = addrCreator.createSegment(newLower, newHigher, segPref);
	}
	res = deriveIPAddressSectionPrefLen(section.toIPAddressSection(), segs, pref)
	//R result = addrCreator.createSection(segs);
	//return result;
	return
}

func (section *ipAddressSectionInternal) subtract(
	other *IPAddressSection,
	//IPAddressCreator<T, R, ?, S, ?> addrCreator,
	//IntFunction<S> segProducer,
	//SegFunction<R, R> prefixApplier
) (res []*IPAddressSection, err SizeMismatchError) {
	//check if they are comparable section
	//section.checkSectionCount(other);

	err = section.checkSectionCount(other)
	if err != nil {
		return
	}

	if !section.isMultiple() {
		if other.Contains(section.toIPAddressSection()) {
			return
		}
		res = []*IPAddressSection{section.toIPAddressSection()}
		return
		//result[0] = section;
		//return result;
	}
	//getDifference: same as removing the intersection
	//   section you confirm there is an intersection in each segment.
	// Then you remove each intersection, one at a time, leaving the other segments the same, since only one segment needs to differ.
	// To prevent adding the same section twice, use only the intersection (ie the relative complement of the diff)
	// of segments already handled and not the whole segment.

	// For example: 0-3.0-3.2.4 subtracting 1-4.1-3.2.4, the intersection is 1-3.1-3.2.4
	// The diff of the section segment is just 0, giving 0.0-3.2.4 (subtract the section segment, leave the others the same)
	// The diff of the second segment is also 0, but for the section segment we use the intersection since we handled the section already, giving 1-3.0.2.4
	// 	(take the intersection of the section segment, subtract the second segment, leave remaining segments the same)

	segCount := section.GetSegmentCount()
	for i := 0; i < segCount; i++ {
		seg := section.GetSegment(i)
		otherSeg := other.GetSegment(i)
		lower := seg.GetSegmentValue()
		higher := seg.getUpperSegmentValue()
		otherLower := otherSeg.GetSegmentValue()
		otherHigher := otherSeg.getUpperSegmentValue()
		if otherLower > higher || lower > otherHigher {
			//no overlap in this segment means no overlap at all
			res = []*IPAddressSection{section.toIPAddressSection()}
			return
		}
	}

	//S intersections[] = addrCreator.createSegmentArray(segCount);
	intersections := createSegmentArray(segCount)
	sections := make([]*IPAddressSection, 0, segCount<<1)
	//ArrayList<R> sections = new ArrayList<R>();
	for i := 0; i < segCount; i++ {
		seg := section.GetSegment(i)
		otherSeg := other.GetSegment(i)
		lower := seg.GetSegmentValue()
		higher := seg.getUpperSegmentValue()
		otherLower := otherSeg.GetSegmentValue()
		otherHigher := otherSeg.getUpperSegmentValue()
		if lower >= otherLower {
			if higher <= otherHigher {
				//this segment is contained in the other
				if seg.isPrefixed() {
					intersections[i] = createAddressDivision(seg.deriveNewMultiSeg(lower, higher, nil)) //addrCreator.createSegment(lower, higher, null);
				} else {
					intersections[i] = seg.ToAddressDivision()
				}
				continue
			}
			//otherLower <= lower <= otherHigher < higher
			intersections[i] = createAddressDivision(seg.deriveNewMultiSeg(lower, otherHigher, nil))
			section := section.createDiffSection(seg, otherHigher+1, higher, i, intersections)
			sections = append(sections, section)
		} else {
			//lower < otherLower <= otherHigher
			section := section.createDiffSection(seg, lower, otherLower-1, i, intersections)
			sections = append(sections, section)
			if higher <= otherHigher {
				intersections[i] = createAddressDivision(seg.deriveNewMultiSeg(otherLower, higher, nil))
			} else {
				//lower < otherLower <= otherHigher < higher
				intersections[i] = createAddressDivision(seg.deriveNewMultiSeg(otherLower, otherHigher, nil))
				section = section.createDiffSection(seg, otherHigher+1, higher, i, intersections)
				sections = append(sections, section)
			}
		}
	}
	if len(sections) == 0 {
		return
	}

	//apply the prefix to the sections
	//for each section, we figure out what each prefix length should be
	if section.IsPrefixed() {
		thisPrefix := *section.GetNetworkPrefixLen()
		for i := 0; i < len(sections); i++ {
			section := sections[i]
			bitCount := section.GetBitCount()
			totalPrefix := bitCount
			for j := section.GetSegmentCount() - 1; j >= 0; j-- {
				seg := section.GetSegment(j)
				segBitCount := seg.GetBitCount()
				segPrefix := seg.GetMinPrefixLenForBlock()
				if segPrefix == segBitCount {
					break
				} else {
					totalPrefix -= segBitCount
					if segPrefix != 0 {
						totalPrefix += segPrefix
						break
					}
				}
			}
			if totalPrefix != bitCount {
				if totalPrefix < thisPrefix {
					totalPrefix = thisPrefix
				}
				section = section.SetPrefixLen(totalPrefix)
				sections[i] = section
				//section = prefixApplier.apply(section, totalPrefix)
				//sections.set(i, section)
			}
		}
	}
	res = sections
	return
	//R result[] = addrCreator.createSectionArray(sections.size());
	//sections.toArray(result);
	//return result;
}

func (section *ipAddressSectionInternal) createDiffSection(
	//R original,
	seg *IPAddressSegment,
	lower,
	upper SegInt,
	diffIndex int,
	//IPAddressCreator<T, R, ?, S, ?> addrCreator,
	//IntFunction<S> segProducer,
	intersectingValues []*AddressDivision) *IPAddressSection {
	segCount := section.GetSegmentCount()
	segments := createSegmentArray(segCount)
	for j := 0; j < diffIndex; j++ {
		segments[j] = intersectingValues[j]
	}
	diff := createAddressDivision(seg.deriveNewMultiSeg(lower, upper, nil))
	segments[diffIndex] = diff
	for j := diffIndex + 1; j < segCount; j++ {
		segments[j] = section.getDivision(j)
	}
	return deriveIPAddressSection(section.toIPAddressSection(), segments)
	//R section = addrCreator.createSectionInternal(segments);
	//return section
}

func (section *ipAddressSectionInternal) spanWithPrefixBlocks() []ExtendedIPSegmentSeries {
	wrapped := WrapIPSection(section.toIPAddressSection())
	if section.IsSequential() {
		if section.IsSinglePrefixBlock() {
			return []ExtendedIPSegmentSeries{wrapped}
		}
		return getSpanningPrefixBlocks(wrapped, wrapped)
	}
	return spanWithPrefixBlocks(wrapped)
}

func (section *ipAddressSectionInternal) spanWithSequentialBlocks() []ExtendedIPSegmentSeries {
	wrapped := WrapIPSection(section.toIPAddressSection())
	if section.IsSequential() {
		return []ExtendedIPSegmentSeries{wrapped}
	}
	return spanWithSequentialBlocks(wrapped)
}

func (section *ipAddressSectionInternal) coverSeriesWithPrefixBlock() ExtendedIPSegmentSeries {
	if section.IsSinglePrefixBlock() {
		return WrapIPSection(section.toIPAddressSection())
	}
	return coverWithPrefixBlock(
		WrapIPSection(section.getLower().ToIPAddressSection()),
		WrapIPSection(section.getUpper().ToIPAddressSection()))
}

func (section *ipAddressSectionInternal) coverWithPrefixBlock() *IPAddressSection {
	if section.IsSinglePrefixBlock() {
		return section.toIPAddressSection()
	}
	res := coverWithPrefixBlock(
		WrapIPSection(section.getLower().ToIPAddressSection()),
		WrapIPSection(section.getUpper().ToIPAddressSection()))
	return res.(WrappedIPAddressSection).IPAddressSection
}

func (section *ipAddressSectionInternal) coverWithPrefixBlockTo(other *IPAddressSection) (*IPAddressSection, SizeMismatchError) {
	if err := section.checkSectionCount(other); err != nil {
		return nil, err
	}
	res := getCoveringPrefixBlock(
		WrapIPSection(section.toIPAddressSection()),
		WrapIPSection(other))
	return res.(WrappedIPAddressSection).IPAddressSection, nil
}

func (section *ipAddressSectionInternal) getNetworkSection() *IPAddressSection {
	var prefLen BitCount
	if section.IsPrefixed() {
		prefLen = *section.GetPrefixLen()
	} else {
		prefLen = section.GetBitCount()
	}
	return section.getNetworkSectionLen(prefLen)
}

func (section *ipAddressSectionInternal) getNetworkSectionLen(networkPrefixLength BitCount) *IPAddressSection {
	segmentCount := section.GetSegmentCount()
	if segmentCount == 0 {
		return section.toIPAddressSection()
	}
	networkPrefixLength = checkBitCount(networkPrefixLength, section.GetBitCount())
	bitsPerSegment := section.GetBitsPerSegment()
	prefixedSegmentIndex := getNetworkSegmentIndex(networkPrefixLength, section.GetBytesPerSegment(), bitsPerSegment)
	var newSegments []*AddressDivision
	if prefixedSegmentIndex >= 0 {
		segPrefLength := getPrefixedSegmentPrefixLength(bitsPerSegment, networkPrefixLength, prefixedSegmentIndex) // prefixedSegmentIndex of -1 already handled
		lastSeg := section.GetSegment(prefixedSegmentIndex)
		prefBits := *segPrefLength
		mask := ^SegInt(0) << uint(bitsPerSegment-prefBits)
		lower, upper := lastSeg.getSegmentValue()&mask, lastSeg.getUpperSegmentValue()|^mask
		networkSegmentCount := prefixedSegmentIndex + 1
		if networkSegmentCount == segmentCount && segsSame(segPrefLength, lastSeg.GetSegmentPrefixLen(), lower, lastSeg.getSegmentValue(), upper, lastSeg.getUpperSegmentValue()) {
			// the segment count and prefixed segment matches
			return section.toIPAddressSection()
		}
		newSegments = createSegmentArray(networkSegmentCount)
		//if networkSegmentCount > 0 {
		section.copySubSegmentsToSlice(0, prefixedSegmentIndex, newSegments)
		newSegments[prefixedSegmentIndex] = createAddressDivision(lastSeg.deriveNewMultiSeg(lower, upper, segPrefLength))
		//}
	} else {
		newSegments = createSegmentArray(0)
	}
	return deriveIPAddressSectionPrefLen(section.toIPAddressSection(), newSegments, cacheBitCount(networkPrefixLength))
}

func (section *ipAddressSectionInternal) getHostSection() *IPAddressSection {
	var prefLen BitCount
	if section.IsPrefixed() {
		prefLen = *section.GetPrefixLen()
	}
	return section.getHostSectionLen(prefLen)
}

func (section *ipAddressSectionInternal) getHostSectionLen(networkPrefixLength BitCount) *IPAddressSection {
	segmentCount := section.GetSegmentCount()
	if segmentCount == 0 {
		return section.toIPAddressSection()
	}
	networkPrefixLength = checkBitCount(networkPrefixLength, section.GetBitCount())
	bitsPerSegment := section.GetBitsPerSegment()
	prefixedSegmentIndex := getHostSegmentIndex(networkPrefixLength, section.GetBytesPerSegment(), bitsPerSegment)
	var prefLen PrefixLen
	var newSegments []*AddressDivision
	if prefixedSegmentIndex < segmentCount {
		firstSeg := section.GetSegment(prefixedSegmentIndex)
		segPrefLength := getPrefixedSegmentPrefixLength(bitsPerSegment, networkPrefixLength, prefixedSegmentIndex)
		prefLen = segPrefLength
		prefBits := *segPrefLength
		//mask the boundary segment
		mask := ^(^SegInt(0) << uint(bitsPerSegment-prefBits))
		divLower := uint64(firstSeg.getDivisionValue())
		divUpper := uint64(firstSeg.getUpperDivisionValue())
		divMask := uint64(mask)
		maxVal := uint64(^SegInt(0))
		masker := MaskRange(divLower, divUpper, divMask, maxVal)
		lower, upper := masker.GetMaskedLower(divLower, divMask), masker.GetMaskedUpper(divUpper, divMask)
		segLower, segUpper := SegInt(lower), SegInt(upper)
		if prefixedSegmentIndex == 0 && segsSame(segPrefLength, firstSeg.GetSegmentPrefixLen(), segLower, firstSeg.getSegmentValue(), segUpper, firstSeg.getUpperSegmentValue()) {
			// the segment count and prefixed segment matches
			return section.toIPAddressSection()
		}
		hostSegmentCount := segmentCount - prefixedSegmentIndex
		newSegments = createSegmentArray(hostSegmentCount)
		section.copySubSegmentsToSlice(prefixedSegmentIndex+1, prefixedSegmentIndex+hostSegmentCount, newSegments[1:])
		newSegments[0] = createAddressDivision(firstSeg.deriveNewMultiSeg(segLower, segUpper, segPrefLength))
	} else {
		prefLen = cacheBitCount(0)
		newSegments = createSegmentArray(0)
	}
	//newStartIndex := section.addressSegmentIndex + int8(prefixedSegmentIndex)
	addrType := section.getAddrType()
	if !section.isMultiple() {
		return createIPSection(newSegments, prefLen, addrType)
	}
	return createInitializedIPSection(newSegments, prefLen, addrType)
	//return deriveIPAddressSectionPrefLen(section.toIPAddressSection(), newSegments, segPrefLength)
}

func (section *ipAddressSectionInternal) getSubnetSegments( // called by methods to adjust/remove/set prefix length, masking methods, zero host and zero network methods
	startIndex int,
	networkPrefixLength PrefixLen,
	verifyMask bool,
	segProducer func(int) *AddressDivision,
	segmentMaskProducer func(int) SegInt,
) (*IPAddressSection, IncompatibleAddressError) {
	newSect, err := section.addressSectionInternal.getSubnetSegments(startIndex, networkPrefixLength, verifyMask, segProducer, segmentMaskProducer)
	return newSect.ToIPAddressSection(), err
}

func (section *ipAddressSectionInternal) getOredSegments(
	networkPrefixLength PrefixLen,
	verifyMask bool,
	segProducer func(int) *AddressDivision,
	segmentMaskProducer func(int) SegInt) (res *IPAddressSection, err IncompatibleAddressError) {
	networkPrefixLength = checkPrefLen(networkPrefixLength, section.GetBitCount())
	bitsPerSegment := section.GetBitsPerSegment()
	count := section.GetSegmentCount()
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
				err = &incompatibleAddressError{addressError{key: "ipaddress.error.maskMismatch"}}
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
			section.copySubSegmentsToSlice(0, i, newSegments)
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
						err = &incompatibleAddressError{addressError{key: "ipaddress.error.maskMismatch"}}
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
			res = deriveIPAddressSectionPrefLen(section.toIPAddressSection(), newSegments, networkPrefixLength)
			//res = deriveIPAddressSectionSingle(section.toIPAddressSection(), newSegments, networkPrefixLength, singleOnly)
			return
		}
	}
	res = section.toIPAddressSection()
	return
}

func (section *ipAddressSectionInternal) getNetwork() IPAddressNetwork {
	if addrType := section.getAddrType(); addrType.isIPv4() {
		return DefaultIPv4Network
	} else if addrType.isIPv6() {
		return DefaultIPv6Network
	}
	return nil
}

func (section *ipAddressSectionInternal) getNetworkMask(network IPAddressNetwork) *IPAddressSection {
	var prefLen BitCount
	if section.IsPrefixed() {
		prefLen = *section.GetNetworkPrefixLen()
	} else {
		prefLen = section.GetBitCount()
	}
	return network.GetNetworkMask(prefLen).GetSubSection(0, section.GetSegmentCount())
}

func (section *ipAddressSectionInternal) getHostMask(network IPAddressNetwork) *IPAddressSection {
	var prefLen BitCount
	if section.IsPrefixed() {
		prefLen = *section.GetNetworkPrefixLen()
	}
	return network.GetNetworkMask(prefLen).GetSubSection(0, section.GetSegmentCount())
}

// getLeadingBitCount returns the number of consecutive leading one or zero bits.
// If ones is true, returns the number of consecutive leading one bits.
// Otherwise, returns the number of consecutive leading zero bits.
//
// This method applies only to the lower value of the range if this division represents multiple values.
func (section *ipAddressSectionInternal) GetLeadingBitCount(ones bool) BitCount {
	count := section.GetSegmentCount()
	if count == 0 {
		return 0
	}
	var front SegInt
	if ones {
		front = section.GetSegment(0).GetMaxValue()
	}
	var prefixLen BitCount
	for i := 0; i < count; i++ {
		seg := section.GetSegment(i)
		value := seg.getSegmentValue()
		if value != front {
			return prefixLen + seg.GetLeadingBitCount(ones)
		}
		prefixLen += seg.getBitCount()
	}
	return prefixLen
}

func (section *ipAddressSectionInternal) GetTrailingBitCount(ones bool) BitCount {
	count := section.GetSegmentCount()
	if count == 0 {
		return 0
	}
	var back SegInt
	if ones {
		back = section.GetSegment(0).GetMaxValue()
	}
	var bitLen BitCount
	for i := count - 1; i >= 0; i-- {
		seg := section.GetSegment(i)
		value := seg.getSegmentValue()
		if value != back {
			return bitLen + seg.GetTrailingBitCount(ones)
		}
		bitLen += seg.getBitCount()
	}
	return bitLen
}

func (section *ipAddressSectionInternal) insert(index int, other *IPAddressSection, segmentToBitsShift uint) *IPAddressSection {
	return section.replaceLen(index, index, other, 0, other.GetSegmentCount(), segmentToBitsShift)
}

// Replaces segments starting from startIndex and ending before endIndex with the segments starting at replacementStartIndex and
//ending before replacementEndIndex from the replacement section
func (section *ipAddressSectionInternal) replaceLen(
	startIndex, endIndex int, replacement *IPAddressSection, replacementStartIndex, replacementEndIndex int, segmentToBitsShift uint) *IPAddressSection {

	segmentCount := section.GetSegmentCount()
	startIndex, endIndex, replacementStartIndex, replacementEndIndex =
		adjustIndices(startIndex, endIndex, segmentCount, replacementStartIndex, replacementEndIndex, replacement.GetSegmentCount())
	replacedCount := endIndex - startIndex
	replacementCount := replacementEndIndex - replacementStartIndex
	thizz := section.toAddressSection()
	if replacementCount == 0 && replacedCount == 0 { //keep in mind for ipvx, empty sections cannot have prefix lengths
		return section.toIPAddressSection()
	} else if segmentCount == replacedCount { //keep in mind for ipvx, empty sections cannot have prefix lengths
		return replacement
	}
	var newPrefixLen PrefixLen
	prefixLength := section.GetPrefixLen()
	startBits := BitCount(startIndex << segmentToBitsShift)
	if prefixLength != nil && *prefixLength <= startBits {
		newPrefixLen = prefixLength
		replacement = replacement.SetPrefixLen(0)
	} else {
		replacementEndBits := BitCount(replacementEndIndex << segmentToBitsShift)
		replacementPrefLen := replacement.GetPrefixLen()
		endIndexBits := BitCount(endIndex << segmentToBitsShift)
		if replacementPrefLen != nil && *replacementPrefLen <= replacementEndBits {
			var replacementPrefixLen BitCount
			replacementStartBits := BitCount(replacementStartIndex << segmentToBitsShift)
			replacementPrefLenIsZero := *replacementPrefLen <= replacementStartBits
			if !replacementPrefLenIsZero {
				replacementPrefixLen = *replacementPrefLen - replacementStartBits
			}
			newPrefixLen = cacheBitCount(startBits + replacementPrefixLen)
			if endIndex < segmentCount && (prefixLength == nil || *prefixLength > endIndexBits) {
				if replacedCount > 0 || replacementPrefLenIsZero {
					thizz = section.setPrefixLen(endIndexBits)
				} else {
					// this covers the case of a:5:6:7:8 is getting b:c:d/47 at index 1 to 1
					// We need "a" to have no prefix, and "5" to get prefix len 0
					// But setting "5" to have prefix len 0 gives "a" the prefix len 16
					// This is not a problem if any segments are getting replaced or the replacement segments have prefix length 0
					//
					// we move the non-replaced host segments from the end of this to the end of the replacement segments
					// and we also remove the prefix length from this
					additionalSegs := segmentCount - endIndex
					thizz = section.getSubSection(0, startIndex)
					//return section.ReplaceLen(index, index, other, 0, other.GetSegmentCount())

					replacement = replacement.insert(
						replacementEndIndex, section.getSubSection(endIndex, segmentCount).ToIPAddressSection(), segmentToBitsShift)
					replacementEndIndex += additionalSegs
				}
			}
		} else if prefixLength != nil {
			replacementBits := BitCount(replacementCount << segmentToBitsShift)
			var endPrefixBits BitCount
			if *prefixLength > endIndexBits {
				endPrefixBits = *prefixLength - endIndexBits
			}
			newPrefixLen = cacheBitCount(startBits + replacementBits + endPrefixBits)
		} // else newPrefixLen is nil
	}
	return thizz.replace(startIndex, endIndex, replacement.ToAddressSection(),
		replacementStartIndex, replacementEndIndex, newPrefixLen).ToIPAddressSection()
}

func (section *ipAddressSectionInternal) toNormalizedWildcardString() string {
	if sect := section.toIPv4AddressSection(); sect != nil {
		return sect.ToNormalizedWildcardString()
	} else if sect := section.toIPv6AddressSection(); sect != nil {
		return sect.ToNormalizedWildcardString()
	}
	return nilSection()
}

func (section *ipAddressSectionInternal) toCanonicalWildcardString() string {
	if sect := section.toIPv4AddressSection(); sect != nil {
		return sect.ToCanonicalWildcardString()
	} else if sect := section.toIPv6AddressSection(); sect != nil {
		return sect.ToCanonicalWildcardString()
	}
	return nilSection()
}

func (section *ipAddressSectionInternal) toSegmentedBinaryString() string {
	if sect := section.toIPv4AddressSection(); sect != nil {
		return sect.ToSegmentedBinaryString()
	} else if sect := section.toIPv6AddressSection(); sect != nil {
		return sect.ToSegmentedBinaryString()
	}
	return nilSection()
}

func (section *ipAddressSectionInternal) toSQLWildcardString() string {
	if sect := section.toIPv4AddressSection(); sect != nil {
		return sect.ToSQLWildcardString()
	} else if sect := section.toIPv6AddressSection(); sect != nil {
		return sect.ToSQLWildcardString()
	}
	return nilSection()
}

func (section *ipAddressSectionInternal) toFullString() string {
	if sect := section.toIPv4AddressSection(); sect != nil {
		return sect.ToFullString()
	} else if sect := section.toIPv6AddressSection(); sect != nil {
		return sect.ToFullString()
	}
	return nilSection()
}

func (section *ipAddressSectionInternal) toReverseDNSString() (string, IncompatibleAddressError) {
	if sect := section.toIPv4AddressSection(); sect != nil {
		return sect.ToReverseDNSString(), nil
	} else if sect := section.toIPv6AddressSection(); sect != nil {
		return sect.ToReverseDNSString()
	}
	return nilSection(), nil
}

func (section *ipAddressSectionInternal) toPrefixLenString() string {
	if sect := section.toIPv4AddressSection(); sect != nil {
		return sect.ToPrefixLenString()
	} else if sect := section.toIPv6AddressSection(); sect != nil {
		return sect.ToPrefixLenString()
	}
	return nilSection()
}

func (section *ipAddressSectionInternal) toSubnetString() string {
	if sect := section.toIPv4AddressSection(); sect != nil {
		return sect.ToNormalizedWildcardString()
	} else if sect := section.toIPv6AddressSection(); sect != nil {
		return sect.ToPrefixLenString()
	}
	return nilSection()
}

func (section *ipAddressSectionInternal) toCompressedWildcardString() string {
	if sect := section.toIPv4AddressSection(); sect != nil {
		return sect.ToCompressedWildcardString()
	} else if sect := section.toIPv6AddressSection(); sect != nil {
		return sect.ToCompressedWildcardString()
	}
	return nilSection()
}

func (section *ipAddressSectionInternal) toCustomString(stringOptions IPStringOptions) string {
	return toNormalizedIPZonedString(stringOptions, section.toIPAddressSection(), NoZone)
}

func (section *ipAddressSectionInternal) toCustomZonedString(stringOptions IPStringOptions, zone Zone) string {
	return toNormalizedIPZonedString(stringOptions, section.toIPAddressSection(), zone)
}

//func (section *ipAddressSectionInternal) ToAddressSection() *AddressSection {
//
//	return (*AddressSection)(section)
//}

func (section *ipAddressSectionInternal) Wrap() WrappedIPAddressSection {
	return WrapIPSection(section.toIPAddressSection())
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

func (section *IPAddressSection) Contains(other AddressSectionType) bool {
	if section == nil {
		return other == nil || other.ToAddressSection() == nil
	}
	return section.contains(other)
}

func (section *IPAddressSection) Equal(other AddressSectionType) bool {
	if section == nil {
		return other == nil || other.ToAddressSection() == nil
	}
	return section.equal(other)
}

func (section *IPAddressSection) Compare(item AddressItem) int {
	return CountComparator.Compare(section, item)
}

func (section *IPAddressSection) CompareSize(other StandardDivisionGroupingType) int {
	if section == nil {
		if other != nil && other.ToAddressDivisionGrouping() != nil {
			// we have size 0, other has size >= 1
			return -1
		}
		return 0
	}
	return section.compareSize(other)
}

func (section *IPAddressSection) GetCount() *big.Int {
	if section == nil {
		return bigZero()
	} else if sect := section.ToIPv4AddressSection(); sect != nil {
		return sect.GetCount()
	} else if sect := section.ToIPv6AddressSection(); sect != nil {
		return sect.GetCount()
	}
	return section.addressDivisionGroupingBase.getCount()
}

func (section *IPAddressSection) IsMultiple() bool {
	return section != nil && section.isMultiple()
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

// GetBlockCount returns the count of values in the initial (higher) count of divisions.
func (section *IPAddressSection) GetBlockCount(segmentCount int) *big.Int {
	if sect := section.ToIPv4AddressSection(); sect != nil {
		return sect.GetBlockCount(segmentCount)
	} else if sect := section.ToIPv6AddressSection(); sect != nil {
		return sect.GetBlockCount(segmentCount)
	}
	return section.addressDivisionGroupingBase.GetBlockCount(segmentCount)
}

func (section *IPAddressSection) IsIPv4AddressSection() bool {
	return section != nil && section.matchesIPv4SectionType()
}

func (section *IPAddressSection) IsIPv6AddressSection() bool {
	return section != nil && section.matchesIPv6SectionType()
}

func (section *IPAddressSection) ToAddressDivisionGrouping() *AddressDivisionGrouping {
	return section.ToAddressSection().ToAddressDivisionGrouping()
}

func (section *IPAddressSection) ToAddressSection() *AddressSection {
	return (*AddressSection)(unsafe.Pointer(section))
}

func (section *IPAddressSection) ToIPv6AddressSection() *IPv6AddressSection {
	if section.IsIPv6AddressSection() {
		return (*IPv6AddressSection)(section)
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
	return section.IsIPv4AddressSection()
}

func (section *IPAddressSection) IsIPv6() bool {
	return section.IsIPv6AddressSection()
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

func (section *IPAddressSection) GetNetworkSection() *IPAddressSection {
	return section.getNetworkSection()
}

func (section *IPAddressSection) GetNetworkSectionLen(prefLen BitCount) *IPAddressSection {
	return section.getNetworkSectionLen(prefLen)
}

func (section *IPAddressSection) GetHostSection() *IPAddressSection {
	return section.getHostSection()
}

func (section *IPAddressSection) GetHostSectionLen(prefLen BitCount) *IPAddressSection {
	return section.getHostSectionLen(prefLen)
}

func (section *IPAddressSection) GetNetworkMask() *IPAddressSection {
	return section.getNetworkMask(section.getNetwork())
}

func (section *IPAddressSection) GetHostMask() *IPAddressSection {
	return section.getHostMask(section.getNetwork())
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (section *IPAddressSection) CopySubSegments(start, end int, segs []*IPAddressSegment) (count int) {
	return section.visitSubDivisions(start, end, func(index int, div *AddressDivision) bool { segs[index] = div.ToIPAddressSegment(); return false }, len(segs))
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (section *IPAddressSection) CopySegments(segs []*IPAddressSegment) (count int) {
	return section.visitDivisions(func(index int, div *AddressDivision) bool { segs[index] = div.ToIPAddressSegment(); return false }, len(segs))
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

func (section *IPAddressSection) ToZeroHost() (res *IPAddressSection, err IncompatibleAddressError) {
	return section.toZeroHost(false)
}

func (section *IPAddressSection) ToZeroHostLen(prefixLength BitCount) (*IPAddressSection, IncompatibleAddressError) {
	return section.ToZeroHostLen(prefixLength)
}

func (section *IPAddressSection) ToZeroNetwork() *IPAddressSection {
	return section.toZeroNetwork()
}

func (section *IPAddressSection) ToMaxHost() (res *IPAddressSection, err IncompatibleAddressError) {
	return section.toMaxHost()
}

func (section *IPAddressSection) ToMaxHostLen(prefixLength BitCount) (*IPAddressSection, IncompatibleAddressError) {
	return section.toMaxHostLen(prefixLength)
}

func (section *IPAddressSection) WithoutPrefixLen() *IPAddressSection {
	return section.withoutPrefixLen()
}

func (section *IPAddressSection) SetPrefixLen(prefixLen BitCount) *IPAddressSection {
	return section.setPrefixLen(prefixLen).ToIPAddressSection()
}

func (section *IPAddressSection) SetPrefixLenZeroed(prefixLen BitCount) (*IPAddressSection, IncompatibleAddressError) {
	res, err := section.setPrefixLenZeroed(prefixLen)
	return res.ToIPAddressSection(), err
}

func (section *IPAddressSection) AdjustPrefixLen(prefixLen BitCount) *IPAddressSection {
	return section.adjustPrefixLen(prefixLen)
}

func (section *IPAddressSection) AdjustPrefixLenZeroed(prefixLen BitCount) (*IPAddressSection, IncompatibleAddressError) {
	return section.adjustPrefixLenZeroed(prefixLen)
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

func (section *IPAddressSection) AssignMinPrefixForBlock() *IPAddressSection {
	return section.assignMinPrefixForBlock().ToIPAddressSection()
}

func (section *IPAddressSection) ToBlock(segmentIndex int, lower, upper SegInt) *IPAddressSection {
	return section.toBlock(segmentIndex, lower, upper).ToIPAddressSection()
}

func (section *IPAddressSection) Iterator() IPSectionIterator {
	if section == nil {
		return ipSectionIterator{nilSectIterator()}
	}
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

func (section *IPAddressSection) SpanWithPrefixBlocks() []*IPAddressSection {
	if section.IsSequential() {
		if section.IsSinglePrefixBlock() {
			return []*IPAddressSection{section}
		}
		wrapped := WrapIPSection(section)
		spanning := getSpanningPrefixBlocks(wrapped, wrapped)
		return cloneToIPSections(spanning)
	}
	wrapped := WrapIPSection(section)
	return cloneToIPSections(spanWithPrefixBlocks(wrapped))
}

func (section *IPAddressSection) SpanWithSequentialBlocks() []*IPAddressSection {
	if section.IsSequential() {
		return []*IPAddressSection{section}
	}
	wrapped := WrapIPSection(section)
	return cloneToIPSections(spanWithSequentialBlocks(wrapped))
}

func (section *IPAddressSection) CoverWithPrefixBlock() *IPAddressSection {
	return section.coverWithPrefixBlock()
}

func (section *IPAddressSection) ReverseBits(perByte bool) (*IPAddressSection, IncompatibleAddressError) {
	res, err := section.reverseBits(perByte)
	return res.ToIPAddressSection(), err
}

func (section *IPAddressSection) ReverseBytes() (*IPAddressSection, IncompatibleAddressError) {
	res, err := section.reverseBytes(false)
	return res.ToIPAddressSection(), err
}

//func (section *IPAddressSection) ReverseBytesPerSegment() (*IPAddressSection, IncompatibleAddressError) {
//	res, err := section.reverseBytes(true)
//	return res.ToIPAddressSection(), err
//}

func (section *IPAddressSection) ReverseSegments() *IPAddressSection {
	if section.GetSegmentCount() <= 1 {
		if section.IsPrefixed() {
			return section.WithoutPrefixLen()
		}
		return section
	}
	res, _ := section.reverseSegments(
		func(i int) (*AddressSegment, IncompatibleAddressError) {
			return section.GetSegment(i).withoutPrefixLen().ToAddressSegment(), nil
		},
	)
	return res.ToIPAddressSection()
}

func (section *IPAddressSection) String() string {
	if section == nil {
		return nilString()
	}
	return section.toString()
}

func (section *IPAddressSection) ToCanonicalString() string {
	if section == nil {
		return nilString()
	}
	return section.toCanonicalString()
}

func (section *IPAddressSection) ToNormalizedString() string {
	if section == nil {
		return nilString()
	}
	return section.toNormalizedString()
}

func (section *IPAddressSection) ToCompressedString() string {
	if section == nil {
		return nilString()
	}
	return section.toCompressedString()
}

func (section *IPAddressSection) ToHexString(with0xPrefix bool) (string, IncompatibleAddressError) {
	if section == nil {
		return nilString(), nil
	}
	return section.toHexString(with0xPrefix)
}

func (section *IPAddressSection) ToOctalString(with0Prefix bool) (string, IncompatibleAddressError) {
	if section == nil {
		return nilString(), nil
	}
	return section.toOctalString(with0Prefix)
}

func (section *IPAddressSection) ToBinaryString(with0bPrefix bool) (string, IncompatibleAddressError) {
	if section == nil {
		return nilString(), nil
	}
	return section.toBinaryString(with0bPrefix)
}

func (section *IPAddressSection) ToNormalizedWildcardString() string {
	if section == nil {
		return nilString()
	}
	return section.toNormalizedWildcardString()
}

func (section *IPAddressSection) ToCanonicalWildcardString() string {
	if section == nil {
		return nilString()
	}
	return section.toCanonicalWildcardString()
}

func (section *IPAddressSection) ToSegmentedBinaryString() string {
	if section == nil {
		return nilString()
	}
	return section.toSegmentedBinaryString()
}

func (section *IPAddressSection) ToSQLWildcardString() string {
	if section == nil {
		return nilString()
	}
	return section.toSQLWildcardString()
}

func (section *IPAddressSection) ToFullString() string {
	if section == nil {
		return nilString()
	}
	return section.toFullString()
}

func (section *IPAddressSection) ToReverseDNSString() (string, IncompatibleAddressError) {
	if section == nil {
		return nilString(), nil
	}
	return section.toReverseDNSString()
}

func (section *IPAddressSection) ToPrefixLenString() string {
	if section == nil {
		return nilString()
	}
	return section.toPrefixLenString()
}

func (section *IPAddressSection) ToSubnetString() string {
	if section == nil {
		return nilString()
	}
	return section.toSubnetString()
}

func (section *IPAddressSection) ToCompressedWildcardString() string {
	if section == nil {
		return nilString()
	}
	return section.toCompressedWildcardString()
}

func (section *IPAddressSection) ToCustomString(stringOptions IPStringOptions) string {
	if section == nil {
		return nilString()
	}
	return section.toCustomString(stringOptions)
}

func (section *IPAddressSection) GetSegmentStrings() []string {
	if section == nil {
		return nil
	}
	return section.getSegmentStrings()
}

var (
	rangeWildcard                 = new(WildcardsBuilder).ToWildcards()
	allWildcards                  = new(WildcardOptionsBuilder).SetWildcardOptions(WildcardsAll).ToOptions()
	wildcardsRangeOnlyNetworkOnly = new(WildcardOptionsBuilder).SetWildcards(rangeWildcard).ToOptions()
	allSQLWildcards               = new(WildcardOptionsBuilder).SetWildcardOptions(WildcardsAll).SetWildcards(
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
		if isPrefixSubnetSegs(segments, prefLen) {
			applyPrefixToSegments(
				prefLen,
				segments,
				res.GetBitsPerSegment(),
				res.GetBytesPerSegment(),
				(*AddressDivision).toPrefixedNetworkDivision)
			if !res.isMult {
				res.isMult = res.GetSegment(segLen - 1).isMultiple()
			}
		}
	}
	return
}

// handles prefix blocks subnets, and ensures segment prefixes match the section prefix
func assignPrefix(prefixLength PrefixLen, segments []*AddressDivision, res *IPAddressSection, singleOnly bool, boundaryBits BitCount) {
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
		applyPrefixSubnet := !singleOnly && isPrefixSubnetSegs(segments, prefLen)
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
		if applyPrefixSubnet && !res.isMult {
			res.isMult = res.GetSegment(segLen - 1).isMultiple()
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
func isPrefixSubnetSegs(sectionSegments []*AddressDivision, networkPrefixLength BitCount) bool {
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
		zerosOnly)
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

func createSegmentsUint64(
	//segments []*AddressDivision,
	segLen int,
	highBytes,
	lowBytes uint64,
	bytesPerSegment int,
	bitsPerSegment BitCount,
	creator addressSegmentCreator,
	prefixLength PrefixLen) []*AddressDivision {
	segmentMask := ^(^SegInt(0) << uint(bitsPerSegment))
	lowSegCount := getHostSegmentIndex(64, bytesPerSegment, bitsPerSegment)
	newSegs := make([]*AddressDivision, segLen)
	//segLen := len(segments)
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
			newSegs[segmentIndex] = seg
			segmentIndex--
			if segmentIndex < lowIndex {
				break
			}
			bytes >>= uint(bitsPerSegment)
		}
		if lowIndex == 0 {
			break
		}
		lowIndex = 0
		bytes = highBytes
	}
	return newSegs
}

func createSegments(
	lowerValueProvider,
	upperValueProvider SegmentValueProvider,
	segmentCount int,
	bitsPerSegment BitCount,
	creator addressSegmentCreator,
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
