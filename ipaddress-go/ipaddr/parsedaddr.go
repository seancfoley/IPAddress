package ipaddr

import (
	"strconv"
	"sync"
	"sync/atomic"
	"unsafe"
)

// How address sections and addresses and ranges can be created here:
// section (with no error) -> address -> sequential range
// non-nil hostSection -> hostAddress
// nil hostSection -> section (with no error) -> address -> hostAddress
// lower/upper boundary -> sequential range
// lower boundary -> mask (ie address used as mask)

type translatedResult struct {
	sections *sectionResult

	rng *IPAddressSeqRange

	mask *IPAddress

	//series IPAddressDivisionSeries // TODO LATER division grouping creation

}

type boundaryResult struct {
	lowerSection, upperSection *IPAddressSection
}

func (res *boundaryResult) createRange(zone Zone) *IPAddressSeqRange {
	//we need to add zone in order to reuse the lower and upper
	lowerSection := res.lowerSection
	creator := lowerSection.getAddrType().getIPNetwork().getIPAddressCreator()
	rangeLower := creator.createAddressInternalFromSection(lowerSection, zone, nil)
	var rangeUpper *IPAddress
	if res.upperSection == nil {
		rangeUpper = rangeLower
	} else {
		rangeUpper = creator.createAddressInternalFromSection(res.upperSection, zone, nil)
	}
	result, _ := rangeLower.SpanWithRange(rangeUpper)
	return result
}

func (res *boundaryResult) createMask() *IPAddress {
	lowerSection := res.lowerSection
	creator := lowerSection.getAddrType().getIPNetwork().getIPAddressCreator()
	return creator.createAddressInternalFromSection(res.lowerSection, noZone, nil)
}

type sectionResult struct {
	section, hostSection *IPAddressSection

	address, hostAddress *IPAddress

	joinHostError, joinAddressError /* inet_aton, single seg */, mixedError, maskError IncompatibleAddressError
}

func (res *sectionResult) withoutAddressException() bool {
	return res.joinAddressError == nil && res.mixedError == nil && res.maskError == nil
}

type parsedIPAddress struct {
	ipAddressParseData

	ipAddrProvider

	options    IPAddressStringParameters
	originator HostIdentifierString
	valuesx    translatedResult
	//skipContains *bool //TODO additional containment options in IPAddressString
	maskers, mixedMaskers []Masker

	creationLock sync.Mutex
}

func (parseData *parsedIPAddress) values() *translatedResult {
	return &parseData.valuesx
}

func (parseData *parsedIPAddress) providerCompare(other IPAddressProvider) (int, IncompatibleAddressError) {
	return providerCompare(parseData, other)
}

func (parseData *parsedIPAddress) providerEquals(other IPAddressProvider) (bool, IncompatibleAddressError) {
	return providerEquals(parseData, other)
}

func (parseData *parsedIPAddress) isProvidingIPAddress() bool {
	return true
}

func (parseData *parsedIPAddress) getType() IPType {
	return fromVersion(parseData.getProviderIPVersion())
}

func (parseData *parsedIPAddress) getParameters() IPAddressStringParameters {
	return parseData.options
}

// Note: the following are needed because we have two anonymous fields and there are name clashes
// Instead of defaulting to the default methods in IPAddressProvider, we need to defer to our parsed data for these methods
//

func (parseData *parsedIPAddress) isProvidingMixedIPv6() bool {
	return parseData.ipAddressParseData.isProvidingMixedIPv6()
}

func (parseData *parsedIPAddress) isProvidingIPv6() bool {
	return parseData.ipAddressParseData.isProvidingIPv6()
}

func (parseData *parsedIPAddress) isProvidingIPv4() bool {
	return parseData.ipAddressParseData.isProvidingIPv4()
}

func (parseData *parsedIPAddress) isProvidingBase85IPv6() bool {
	return parseData.ipAddressParseData.isProvidingBase85IPv6()
}

func (parseData *parsedIPAddress) getProviderIPVersion() IPVersion {
	return parseData.ipAddressParseData.getProviderIPVersion()
}

func (parseData *parsedIPAddress) getIPAddressParseData() *ipAddressParseData {
	return &parseData.ipAddressParseData
}

// creation methods start here

func (parseData *parsedIPAddress) createSections(doSections, doRangeBoundaries, withUpper bool) (sections sectionResult, boundaries boundaryResult) {
	version := parseData.getProviderIPVersion()
	if version.isIPv4() {
		return parseData.createIPv4Sections(doSections, doRangeBoundaries, withUpper)
	} else if version.isIPv6() {
		return parseData.createIPv6Sections(doSections, doRangeBoundaries, withUpper)
	}
	return
}

func (parseData *parsedIPAddress) getProviderSeqRange() *IPAddressSeqRange {
	val := parseData.values()
	result := val.rng
	if result == nil {
		parseData.creationLock.Lock()
		result = val.rng
		if result == nil {
			sections := val.sections
			if sections == nil {
				_, boundaries := parseData.createSections(false, true, true)
				// creates lower, upper, then range from the two
				result = boundaries.createRange(parseData.getQualifier().getZone())
			} else {
				if sections.withoutAddressException() {
					result = sections.address.ToSequentialRange()
				} else {
					_, boundaries := parseData.createSections(false, true, true)
					result = boundaries.createRange(parseData.getQualifier().getZone())
				}
			}
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&val.rng))
			atomic.StorePointer(dataLoc, unsafe.Pointer(result))
		}
		parseData.creationLock.Unlock()
	}
	return result
}

// this is for parsed addresses which are masks in and of themselves
// with masks, only the lower value matters
func (parseData *parsedIPAddress) getValForMask() *IPAddress {
	val := parseData.values()
	mask := val.mask
	if mask == nil {
		parseData.creationLock.Lock()
		if mask == nil {
			_, boundaries := parseData.createSections(false, true, false)
			mask = boundaries.createMask()
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&val.mask))
			atomic.StorePointer(dataLoc, unsafe.Pointer(mask))
		}
		parseData.creationLock.Unlock()
	}
	return mask
}

func (parseData *parsedIPAddress) getCachedAddresses(forHostAddr bool) *sectionResult {
	val := parseData.values()
	sections := val.sections
	if sections == nil {
		parseData.creationLock.Lock()
		sections = val.sections
		if sections == nil {
			sects, _ := parseData.createSections(true, false, false)
			sections = &sects
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&val.sections))
			atomic.StorePointer(dataLoc, unsafe.Pointer(sections))
		}
		parseData.creationLock.Unlock()
	}
	if sections.withoutAddressException() {
		var addr *IPAddress
		if forHostAddr {
			addr = sections.hostAddress
		} else {
			addr = sections.address
		}
		if addr == nil {
			parseData.creationLock.Lock()
			if forHostAddr {
				addr = sections.hostAddress
			} else {
				addr = sections.address
			}
			if addr == nil {
				var section *IPAddressSection
				var originator HostIdentifierString
				if forHostAddr {
					section = sections.hostSection
					if section == nil {
						section = sections.section
					}
				} else {
					section = sections.section
					originator = parseData.originator
				}
				creator := section.getAddrType().getIPNetwork().getIPAddressCreator()
				addr = creator.createAddressInternalFromSection(section, parseData.getQualifier().getZone(), originator)
				var dataLoc *unsafe.Pointer
				if forHostAddr {
					dataLoc = (*unsafe.Pointer)(unsafe.Pointer(&sections.hostAddress))
				} else {
					// if range created first, stick the lower and upper into the address cache
					if rng := val.rng; rng != nil {
						addr.cache.addrsCache = &addrsCache{
							lower: rng.lower.ToAddress(),
							upper: rng.upper.ToAddress(),
						}
					}
					dataLoc = (*unsafe.Pointer)(unsafe.Pointer(&sections.address))
				}
				atomic.StorePointer(dataLoc, unsafe.Pointer(addr))
			}
			parseData.creationLock.Unlock()
		}
	}
	return sections
}

// this is for parsed addresses which have associated masks
func (parseData *parsedIPAddress) getProviderMask() *IPAddress {
	return parseData.getQualifier().getMaskLower()
}

func (parseData *parsedIPAddress) getProviderHostAddress() (*IPAddress, IncompatibleAddressError) {
	addrs := parseData.getCachedAddresses(true)
	if addrs.mixedError != nil {
		return nil, addrs.mixedError
	} else if addrs.joinHostError != nil {
		return nil, addrs.joinHostError
	}
	return addrs.hostAddress, nil
}

func (parseData *parsedIPAddress) getProviderAddress() (*IPAddress, IncompatibleAddressError) {
	addrs := parseData.getCachedAddresses(false)
	if addrs.mixedError != nil {
		return nil, addrs.mixedError
	} else if addrs.maskError != nil {
		return nil, addrs.maskError
	} else if addrs.joinAddressError != nil {
		return nil, addrs.joinAddressError
	}
	return addrs.address, nil
}

func (parseData *parsedIPAddress) getVersionedAddress(version IPVersion) (*IPAddress, IncompatibleAddressError) {
	thisVersion := parseData.getProviderIPVersion()
	if version != thisVersion {
		return nil, nil
	}
	return parseData.getProviderAddress()
}

func (parseData *parsedIPAddress) getProviderNetworkPrefixLength() PrefixLen {
	return parseData.getQualifier().getEquivalentPrefixLength()
}

func allocateSegments(
	segments,
	originalSegments []*AddressDivision,
	segmentCount,
	originalCount int) []*AddressDivision {
	if segments == nil {
		segments = createSegmentArray(segmentCount)
		if originalCount > 0 {
			copy(segments, originalSegments[:originalCount])
		}
	}
	return segments
}

func (parseData *parsedIPAddress) createIPv4Sections(doSections, doRangeBoundaries, withUpper bool) (sections sectionResult, boundaries boundaryResult) {
	qualifier := parseData.getQualifier()
	mask := parseData.getProviderMask()
	if mask != nil && mask.GetBlockMaskPrefixLength(true) != nil {
		mask = nil //we don't do any masking if the mask is a subnet mask, instead we just map it to the corresponding prefix length
	}
	hasMask := mask != nil
	addrParseData := parseData.getAddressParseData()
	segmentCount := addrParseData.getSegmentCount()
	if hasMask && parseData.maskers == nil {
		parseData.maskers = make([]Masker, segmentCount)
	}
	creator := ipv4Type.getIPNetwork().getIPAddressCreator()
	missingCount := IPv4SegmentCount - segmentCount

	var hostSegments, segments, lowerSegments, upperSegments []*AddressDivision
	if doSections {
		segments = createSegmentArray(IPv4SegmentCount)
	} else if doRangeBoundaries {
		lowerSegments = createSegmentArray(IPv4SegmentCount)
	} else {
		return
	}
	expandedSegments := missingCount <= 0
	var expandedStart, expandedEnd int = -1, -1
	addressString := parseData.str
	maskedIsDifferent := false
	for i, normalizedSegmentIndex := 0, 0; i < segmentCount; i++ {
		lower := addrParseData.getValue(i, keyLower)
		upper := addrParseData.getValue(i, keyUpper)
		if !expandedSegments {
			//check for any missing segments that we should account for here
			isLastSegment := i == segmentCount-1
			isWildcard := addrParseData.isWildcard(i)
			expandedSegments = isLastSegment
			if !expandedSegments {
				// if we are inet_aton, we must wait for last segment
				// otherwise, we check if we are wildcard and no other wildcard further down
				expandedSegments = !parseData.is_inet_aton_joined() && isWildcard
				if expandedSegments {
					for j := i + 1; j < segmentCount; j++ {
						if addrParseData.isWildcard(j) { //another wildcard further down
							expandedSegments = false
							break
						}
					}
				}
			}
			if expandedSegments {
				if isWildcard {
					upper = 0xffffffff >> ((3 - missingCount) << 3)
				} else {
					expandedStart = i
					expandedEnd = i + missingCount
				}
				bits := BitCount(missingCount+1) << 3 // BitCount(missingCount+1) * IPv4BitsPerSegment
				var maskedLower, maskedUpper uint64
				if hasMask {
					var divMask uint64
					for k := 0; k <= missingCount; k++ {
						divMask = (divMask << IPv4BitsPerSegment) | uint64(mask.GetSegment(normalizedSegmentIndex+k).GetSegmentValue())
					}
					masker := parseData.maskers[i]
					if masker == nil {
						var maxValue uint64 = ^(^uint64(0) << bits)
						masker = maskRange(lower, upper, divMask, maxValue)
						if !masker.IsSequential() {
							if sections.maskError == nil {
								sections.maskError = &incompatibleAddressError{
									addressError: addressError{
										str: maskString(lower, upper, divMask),
										key: "ipaddress.error.maskMismatch",
									},
								}
							}
						}
						parseData.maskers[i] = masker
					}
					maskedLower = masker.GetMaskedLower(lower, divMask)
					maskedUpper = masker.GetMaskedUpper(upper, divMask)
					maskedIsDifferent = maskedIsDifferent || maskedLower != lower || maskedUpper != upper
				} else {
					maskedLower = lower
					maskedUpper = upper
				}
				shift := bits
				count := missingCount
				for count >= 0 { //add the missing segments
					shift -= IPv4BitsPerSegment
					currentPrefix := getQualifierSegmentPrefixLength(normalizedSegmentIndex, IPv4BitsPerSegment, qualifier)
					hostSegLower := SegInt((lower >> shift) & IPv4MaxValuePerSegment)
					var hostSegUpper SegInt
					if lower == upper {
						hostSegUpper = hostSegLower
					} else {
						hostSegUpper = SegInt((upper >> shift) & IPv4MaxValuePerSegment)
					}
					var maskedSegLower, maskedSegUpper SegInt
					if hasMask {
						maskedSegLower = SegInt((maskedLower >> shift) & IPv4MaxValuePerSegment)
						if maskedLower == maskedUpper {
							maskedSegUpper = maskedSegLower
						} else {
							maskedSegUpper = SegInt((maskedUpper >> shift) & IPv4MaxValuePerSegment)
						}
					} else {
						maskedSegLower = hostSegLower
						maskedSegUpper = hostSegUpper
					}
					if doSections {
						if maskedIsDifferent || currentPrefix != nil {
							hostSegments = allocateSegments(hostSegments, segments, IPv4SegmentCount, normalizedSegmentIndex)
							hostSegments[normalizedSegmentIndex] = parseData.createSegment(
								addressString,
								IPv4,
								hostSegLower,
								hostSegUpper,
								false,
								i,
								nil,
								creator)
						}
						segments[normalizedSegmentIndex] = parseData.createSegment(
							addressString,
							IPv4,
							maskedSegLower,
							maskedSegUpper,
							false,
							i,
							currentPrefix,
							creator)
					}
					if doRangeBoundaries {
						isRange := maskedSegLower != maskedSegUpper
						if !doSections || isRange {
							if doSections {
								lowerSegments = allocateSegments(lowerSegments, segments, IPv4SegmentCount, normalizedSegmentIndex)
							} // else segments already allocated
							lowerSegments[normalizedSegmentIndex] = parseData.createSegment(
								addressString,
								IPv4,
								maskedSegLower,
								maskedSegLower,
								false,
								i,
								currentPrefix,
								creator)
						} else if lowerSegments != nil {
							lowerSegments[normalizedSegmentIndex] = segments[normalizedSegmentIndex]
						}
						if withUpper {
							if isRange {
								upperSegments = allocateSegments(upperSegments, lowerSegments, IPv4SegmentCount, normalizedSegmentIndex)
								upperSegments[normalizedSegmentIndex] = parseData.createSegment(
									addressString,
									IPv4,
									maskedSegUpper,
									maskedSegUpper,
									false,
									i,
									currentPrefix,
									creator)
							} else if upperSegments != nil {
								upperSegments[normalizedSegmentIndex] = lowerSegments[normalizedSegmentIndex]
							}
						}
					}
					normalizedSegmentIndex++
					count--
				}
				addrParseData.setBitLength(i, bits)
				continue
			} //end handle inet_aton joined segments
		}
		var hostLower, hostUpper uint64 = lower, upper
		var masker Masker
		unmasked := true
		if hasMask {
			masker = parseData.maskers[i]
			maskInt := uint64(mask.GetSegment(normalizedSegmentIndex).GetSegmentValue())
			if masker == nil {
				masker = maskRange(lower, upper, maskInt, uint64(creator.getMaxValuePerSegment()))
				parseData.maskers[i] = masker
				if !masker.IsSequential() && sections.maskError == nil {
					sections.maskError = &incompatibleAddressError{
						addressError: addressError{
							str: maskString(lower, upper, maskInt),
							key: "ipaddress.error.maskMismatch",
						},
					}
				}
			}
			lower = masker.GetMaskedLower(lower, maskInt)
			upper = masker.GetMaskedUpper(upper, maskInt)
			unmasked = hostLower == lower && hostUpper == upper
			maskedIsDifferent = maskedIsDifferent || !unmasked
		}
		segmentPrefixLength := getQualifierSegmentPrefixLength(normalizedSegmentIndex, IPv4BitsPerSegment, qualifier)
		if doSections {
			if maskedIsDifferent || segmentPrefixLength != nil {
				hostSegments = allocateSegments(hostSegments, segments, IPv4SegmentCount, normalizedSegmentIndex)
				hostSegments[normalizedSegmentIndex] = parseData.createSegment(
					addressString,
					IPv4,
					SegInt(hostLower),
					SegInt(hostUpper),
					true,
					i,
					nil,
					creator)
			}
			segments[normalizedSegmentIndex] = parseData.createSegment(
				addressString,
				IPv4,
				SegInt(lower),
				SegInt(upper),
				unmasked,
				i,
				segmentPrefixLength,
				creator)
		}
		if doRangeBoundaries {
			isRange := lower != upper
			if !doSections || isRange {
				if doSections {
					lowerSegments = allocateSegments(lowerSegments, segments, IPv4SegmentCount, normalizedSegmentIndex)
				} // else segments already allocated
				lowerSegments[normalizedSegmentIndex] = parseData.createSegment(
					addressString,
					IPv4,
					SegInt(lower),
					SegInt(lower),
					false,
					i,
					segmentPrefixLength,
					creator)
			} else if lowerSegments != nil {
				lowerSegments[normalizedSegmentIndex] = segments[normalizedSegmentIndex]
			}
			if withUpper {
				if isRange {
					upperSegments = allocateSegments(upperSegments, lowerSegments, IPv4SegmentCount, normalizedSegmentIndex)
					upperSegments[normalizedSegmentIndex] = parseData.createSegment(
						addressString,
						IPv4,
						SegInt(upper),
						SegInt(upper),
						false,
						i,
						segmentPrefixLength,
						creator)
				} else if upperSegments != nil {
					upperSegments[normalizedSegmentIndex] = lowerSegments[normalizedSegmentIndex]
				}
			}
		}
		normalizedSegmentIndex++
		addrParseData.setBitLength(i, IPv4BitsPerSegment)
	}
	prefLength := getPrefixLength(qualifier)
	var result, hostResult *IPAddressSection
	if doSections {
		result = creator.createPrefixedSectionInternal(segments, prefLength)
		sections.section = result
		if hostSegments != nil {
			hostResult = creator.createSectionInternal(hostSegments).ToIPAddressSection()
			sections.hostSection = hostResult
			if checkExpandedValues(hostResult, expandedStart, expandedEnd) {
				sections.joinHostError = &incompatibleAddressError{
					addressError{
						str: addressString,
						key: "ipaddress.error.invalid.joined.ranges",
					},
				}
			}
		}
		if checkExpandedValues(result, expandedStart, expandedEnd) {
			sections.joinAddressError = &incompatibleAddressError{addressError{str: addressString, key: "ipaddress.error.invalid.joined.ranges"}}
			if hostResult == nil {
				sections.joinHostError = sections.joinAddressError
			}
		}
	}
	if doRangeBoundaries {
		// if we have a prefix subnet, it is possible our lower and upper boundaries exceed what appears in the parsed address
		prefixLength := getPrefixLength(qualifier)
		isPrefixSub := false
		if prefixLength != nil {
			var lowerSegs, upperSegs []*AddressDivision
			if doSections {
				upperSegs = segments
				lowerSegs = upperSegs
			} else {
				lowerSegs = lowerSegments
				if upperSegments == nil {
					upperSegs = lowerSegments
				} else {
					upperSegs = upperSegments
				}
			}
			isPrefixSub = isPrefixSubnet(
				func(index int) SegInt { return lowerSegs[index].ToAddressSegment().GetSegmentValue() },
				func(index int) SegInt { return upperSegs[index].ToAddressSegment().GetUpperSegmentValue() },
				len(lowerSegs),
				IPv4BytesPerSegment,
				IPv4BitsPerSegment,
				IPv4MaxValuePerSegment,
				*prefixLength,
				false)
			if isPrefixSub {
				if lowerSegments == nil {
					//allocate lower segments from address segments
					lowerSegments = allocateSegments(lowerSegments, segments, IPv4SegmentCount, IPv4SegmentCount)
				}
				if upperSegments == nil {
					//allocate upper segments from lower segments
					upperSegments = allocateSegments(upperSegments, lowerSegments, IPv4SegmentCount, IPv4SegmentCount)
				}
			}
		}
		if lowerSegments != nil {
			boundaries.lowerSection = creator.createPrefixedSectionInternalSingle(lowerSegments, prefLength)
		}
		if upperSegments != nil {
			section := creator.createPrefixedSectionInternal(upperSegments, prefLength)
			if isPrefixSub {
				section = section.ToPrefixBlock()
			}
			boundaries.upperSection = section.GetUpper()
		}
	}
	return
}

func (parseData *parsedIPAddress) createIPv6Sections(doSections, doRangeBoundaries, withUpper bool) (sections sectionResult, boundaries boundaryResult) {
	qualifier := parseData.getQualifier()
	mask := parseData.getProviderMask()
	if mask != nil && mask.GetBlockMaskPrefixLength(true) != nil {
		mask = nil //we don't do any masking if the mask is a subnet mask, instead we just map it to the corresponding prefix length
	}
	hasMask := mask != nil

	addressParseData := parseData.getAddressParseData()
	segmentCount := addressParseData.getSegmentCount()
	if hasMask && parseData.maskers == nil {
		parseData.maskers = make([]Masker, segmentCount)
	}
	//creator := parseData.getIPv6AddressCreator()
	creator := ipv6Type.getIPNetwork().getIPAddressCreator()
	ipv6SegmentCount := IPv6SegmentCount
	var hostSegments, segments, lowerSegments, upperSegments []*AddressDivision
	if doSections {
		segments = createSegmentArray(IPv6SegmentCount)
	} else if doRangeBoundaries {
		lowerSegments = createSegmentArray(IPv6SegmentCount)
	} else {
		return
	}
	//finalResult := &parseData.valuesx
	//finalResult.creator = creator
	mixed := parseData.isProvidingMixedIPv6()

	normalizedSegmentIndex := 0
	var missingSegmentCount int
	if mixed {
		missingSegmentCount = IPv6MixedOriginalSegmentCount
	} else {
		missingSegmentCount = IPv6SegmentCount
	}
	missingSegmentCount -= segmentCount

	expandedSegments := missingSegmentCount <= 0
	var expandedStart, expandedEnd int = -1, -1
	addressString := parseData.str
	maskedIsDifferent := false

	//get the segments for IPv6
	for i := 0; i < segmentCount; i++ {
		lower := addressParseData.getValue(i, keyLower)
		upper := addressParseData.getValue(i, keyUpper)

		if !expandedSegments {
			isLastSegment := i == segmentCount-1
			isWildcard := addressParseData.isWildcard(i)
			isCompressed := parseData.segmentIsCompressed(i)

			// figure out if this segment should be expanded
			expandedSegments = isLastSegment || isCompressed
			if !expandedSegments {
				// we check if we are wildcard and no other wildcard or compressed segment further down
				expandedSegments = isWildcard
				if expandedSegments {
					for j := i + 1; j < segmentCount; j++ {
						if addressParseData.isWildcard(j) || parseData.segmentIsCompressed(j) {
							expandedSegments = false
							break
						}
					}
				}
			}
			if expandedSegments {
				var lowerHighBytes, upperHighBytes uint64
				hostIsRange := false
				if !isCompressed {
					if isWildcard {
						if missingSegmentCount > 3 {
							upperHighBytes = 0xffffffffffffffff >> ((7 - missingSegmentCount) << 4)
							upper = 0xffffffffffffffff
						} else {
							upperHighBytes = 0
							upper = 0xffffffffffffffff >> ((3 - missingSegmentCount) << 4)
						}
						lower = 0
						hostIsRange = true
					} else {
						if missingSegmentCount > 3 {
							lowerHighBytes = addressParseData.getValue(i, keyExtendedLower) //the high half of the lower value
							upperHighBytes = addressParseData.getValue(i, keyExtendedUpper) //the high half of the upper value
							hostIsRange = (lower != upper) || (lowerHighBytes != upperHighBytes)
						} else {
							//lowerHighBytes = upperHighBytes = 0;
							hostIsRange = (lower != upper)
						}
						expandedStart = i
						expandedEnd = i + missingSegmentCount
					}
				}
				bits := BitCount(missingSegmentCount+1) << 4 // BitCount(missingSegmentCount+1) * IPv6BitsPerSegment
				var maskedLower, maskedUpper, maskedLowerHighBytes, maskedUpperHighBytes uint64
				maskedIsRange := false
				if hasMask {
					// line up the mask segments into two longs
					if isCompressed {
						parseData.maskers[i] = defaultMasker
					} else {
						bitsPerSegment := IPv6BitsPerSegment
						var maskVal uint64 = 0
						if missingSegmentCount >= 4 {
							cachedMasker := parseData.maskers[i]
							var extendedMaskVal uint64
							extendedCount := missingSegmentCount - 3
							for k := 0; k < extendedCount; k++ {
								extendedMaskVal = (extendedMaskVal << bitsPerSegment) | mask.GetSegment(normalizedSegmentIndex+k).getDivisionValue()
							}
							for k := extendedCount; k <= missingSegmentCount; k++ {
								maskVal = (maskVal << bitsPerSegment) | mask.GetSegment(normalizedSegmentIndex+k).getDivisionValue()
							}
							if cachedMasker == nil {
								// shift must be 6 bits at most for this shift to work per the java spec (so it must be less than 2^6 = 64)
								extendedMaxValue := ^(^DivInt(0) << (bits - DivIntSize))
								//long extendedMaxValue = bits == Long.SIZE ? 0xffffffffffffffffL : ~(~DivInt(0) << (bits - Long.SIZE));
								cachedMasker = maskExtendedRange(
									lower, lowerHighBytes,
									upper, upperHighBytes,
									maskVal, extendedMaskVal,
									0xffffffffffffffff, extendedMaxValue)
								if !cachedMasker.IsSequential() {
									if sections.maskError == nil {

										//byteCount := (missingSegmentCount + 1) * IPv6BytesPerSegment;
										sections.maskError = &incompatibleAddressError{
											addressError: addressError{
												str: addressString,
												//new BigInteger(1, toBytesSizeAdjusted(lower, lowerHighBytes, byteCount)).toString(),
												//new BigInteger(1, toBytesSizeAdjusted(upper, upperHighBytes, byteCount)).toString(),
												//new BigInteger(1, toBytesSizeAdjusted(maskVal, extendedMaskVal, byteCount)).toString(),
												key: "ipaddress.error.maskMismatch",
											},
										}
									}
								}
								parseData.maskers[i] = cachedMasker
							}
							masker := cachedMasker.(ExtendedMasker)
							maskedLowerHighBytes = masker.GetExtendedMaskedLower(lowerHighBytes, extendedMaskVal)
							maskedUpperHighBytes = masker.GetExtendedMaskedUpper(upperHighBytes, extendedMaskVal)
							maskedLower = masker.GetMaskedLower(lower, maskVal)
							maskedUpper = masker.GetMaskedUpper(upper, maskVal)
							maskedIsRange = (maskedLower != maskedUpper) || (maskedLowerHighBytes != maskedUpperHighBytes)
							maskedIsDifferent = maskedIsDifferent || maskedLower != lower || maskedUpper != upper || maskedLowerHighBytes != lowerHighBytes || maskedUpperHighBytes != upperHighBytes
						} else {
							masker := parseData.maskers[i]
							for k := 0; k <= missingSegmentCount; k++ {
								maskVal = (maskVal << bitsPerSegment) | mask.GetSegment(normalizedSegmentIndex+k).getDivisionValue()
							}
							if masker == nil {
								// shift must be 6 bits at most for this shift to work per the java spec (so it must be less than 2^6 = 64)
								maxValue := ^(^DivInt(0) << bits)
								//long maxValue = bits == Long.SIZE ? 0xffffffffffffffffL : ~(~0L << bits);
								masker = maskRange(lower, upper, maskVal, maxValue)
								if !masker.IsSequential() {
									if sections.maskError == nil {
										sections.maskError = &incompatibleAddressError{
											addressError: addressError{
												str: maskString(lower, upper, maskVal),
												key: "ipaddress.error.maskMismatch",
											},
										}
									}
								}
								parseData.maskers[i] = masker
							}
							//maskedLowerHighBytes = maskedUpperHighBytes = 0;
							maskedLower = masker.GetMaskedLower(lower, maskVal)
							maskedUpper = masker.GetMaskedUpper(upper, maskVal)
							maskedIsRange = maskedLower != maskedUpper
							maskedIsDifferent = maskedIsDifferent || maskedLower != lower || maskedUpper != upper
						}
					}
				} else {
					maskedLowerHighBytes = lowerHighBytes
					maskedUpperHighBytes = upperHighBytes
					maskedLower = lower
					maskedUpper = upper
					maskedIsRange = hostIsRange
				}
				shift := bits
				count := missingSegmentCount
				for count >= 0 { // add the missing segments
					// func getSegmentPrefixLength(bitsPerSegment BitCount, prefixLength PrefixLen, segmentIndex int)
					currentPrefix := getQualifierSegmentPrefixLength(normalizedSegmentIndex, IPv6BitsPerSegment, qualifier)
					var hostSegLower, hostSegUpper, maskedSegLower, maskedSegUpper uint64
					if !isCompressed {
						shift -= IPv6BitsPerSegment
						//segmentBitsMask := IPv6MaxValuePerSegment
						if count >= 4 {
							shorterShift := shift - (IPv6BitsPerSegment << 2)
							hostSegLower = (lowerHighBytes >> shorterShift) & IPv6MaxValuePerSegment
							if hostIsRange {
								hostSegUpper = (upperHighBytes >> shorterShift) & IPv6MaxValuePerSegment
							} else {
								hostSegUpper = hostSegLower
							}
							if hasMask {
								maskedSegLower = (maskedLowerHighBytes >> shorterShift) & IPv6MaxValuePerSegment
								if maskedIsRange {
									maskedSegUpper = (maskedUpperHighBytes >> shorterShift) & IPv6MaxValuePerSegment
								} else {
									maskedSegUpper = maskedSegLower
								}
							} else {
								maskedSegLower = hostSegLower
								maskedSegUpper = hostSegUpper
							}
						} else {
							hostSegLower = (lower >> shift) & IPv6MaxValuePerSegment
							if hostIsRange {
								hostSegUpper = (upper >> shift) & IPv6MaxValuePerSegment
							} else {
								hostSegUpper = hostSegLower
							}
							if hasMask {
								maskedSegLower = (maskedLower >> shift) & IPv6MaxValuePerSegment
								if maskedIsRange {
									maskedSegUpper = (maskedUpper >> shift) & IPv6MaxValuePerSegment
								} else {
									maskedSegUpper = maskedSegLower
								}
							} else {
								maskedSegLower = hostSegLower
								maskedSegUpper = hostSegUpper
							}
						}
					}
					if doSections {
						if maskedIsDifferent || currentPrefix != nil {
							hostSegments = allocateSegments(hostSegments, segments, ipv6SegmentCount, normalizedSegmentIndex)
							hostSegments[normalizedSegmentIndex] = parseData.createSegment(
								addressString,
								IPv6,
								SegInt(hostSegLower),
								SegInt(hostSegUpper),
								false,
								i,
								nil,
								creator)
						}
						segments[normalizedSegmentIndex] = parseData.createSegment(
							addressString,
							IPv6,
							SegInt(maskedSegLower),
							SegInt(maskedSegUpper),
							false,
							i,
							currentPrefix,
							creator)
					}
					if doRangeBoundaries {
						isSegRange := maskedSegLower != maskedSegUpper
						if !doSections || isSegRange {
							if doSections {
								lowerSegments = allocateSegments(lowerSegments, segments, ipv6SegmentCount, normalizedSegmentIndex)
							} // else segments already allocated
							lowerSegments[normalizedSegmentIndex] = parseData.createSegment(
								addressString,
								IPv6,
								SegInt(maskedSegLower),
								SegInt(maskedSegLower),
								false,
								i,
								currentPrefix,
								creator)

						} else if lowerSegments != nil {
							lowerSegments[normalizedSegmentIndex] = segments[normalizedSegmentIndex]
						}
						if withUpper {
							if isSegRange {
								upperSegments = allocateSegments(upperSegments, lowerSegments, ipv6SegmentCount, normalizedSegmentIndex)
								upperSegments[normalizedSegmentIndex] = parseData.createSegment(
									addressString,
									IPv6,
									SegInt(maskedSegUpper),
									SegInt(maskedSegUpper),
									false,
									i,
									currentPrefix,
									creator)
							} else if upperSegments != nil {
								upperSegments[normalizedSegmentIndex] = lowerSegments[normalizedSegmentIndex]
							}
						}
					}
					normalizedSegmentIndex++
					count--
				}
				addressParseData.setBitLength(i, bits)
				continue
			} //end handle joined segments
		}

		var hostLower, hostUpper uint64 = lower, upper
		var masker Masker
		unmasked := true
		if hasMask {
			masker = parseData.maskers[i]
			maskInt := uint64(mask.GetSegment(normalizedSegmentIndex).GetSegmentValue())
			if masker == nil {
				masker = maskRange(lower, upper, maskInt, uint64(creator.getMaxValuePerSegment()))
				parseData.maskers[i] = masker
				if !masker.IsSequential() && sections.maskError == nil {
					sections.maskError = &incompatibleAddressError{
						addressError: addressError{
							str: maskString(lower, upper, maskInt),
							key: "ipaddress.error.maskMismatch",
						},
					}
				}
			}
			lower = masker.GetMaskedLower(lower, maskInt)
			upper = masker.GetMaskedUpper(upper, maskInt)
			unmasked = hostLower == lower && hostUpper == upper
			maskedIsDifferent = maskedIsDifferent || !unmasked
		}
		segmentPrefixLength := getQualifierSegmentPrefixLength(normalizedSegmentIndex, IPv6BitsPerSegment, qualifier)
		if doSections {
			if maskedIsDifferent || segmentPrefixLength != nil {
				hostSegments = allocateSegments(hostSegments, segments, ipv6SegmentCount, normalizedSegmentIndex)
				hostSegments[normalizedSegmentIndex] = parseData.createSegment(
					addressString,
					IPv6,
					SegInt(hostLower),
					SegInt(hostUpper),
					true,
					i,
					nil,
					creator)
			}
			segments[normalizedSegmentIndex] = parseData.createSegment(
				addressString,
				IPv6,
				SegInt(lower),
				SegInt(upper),
				unmasked,
				i,
				segmentPrefixLength,
				creator)
		}
		if doRangeBoundaries {
			isRange := lower != upper
			if !doSections || isRange {
				if doSections {
					lowerSegments = allocateSegments(lowerSegments, segments, ipv6SegmentCount, normalizedSegmentIndex)
				} // else segments already allocated
				lowerSegments[normalizedSegmentIndex] = parseData.createSegment(
					addressString,
					IPv6,
					SegInt(lower),
					SegInt(lower),
					false,
					i,
					segmentPrefixLength,
					creator)
			} else if lowerSegments != nil {
				lowerSegments[normalizedSegmentIndex] = segments[normalizedSegmentIndex]
			}
			if withUpper {
				if isRange {
					upperSegments = allocateSegments(upperSegments, lowerSegments, ipv6SegmentCount, normalizedSegmentIndex)
					upperSegments[normalizedSegmentIndex] = parseData.createSegment(
						addressString,
						IPv6,
						SegInt(upper),
						SegInt(upper),
						false,
						i,
						segmentPrefixLength,
						creator)
				} else if upperSegments != nil {
					upperSegments[normalizedSegmentIndex] = lowerSegments[normalizedSegmentIndex]
				}
			}
		}
		normalizedSegmentIndex++
		addressParseData.setBitLength(i, IPv6BitsPerSegment)
	}
	prefLength := getPrefixLength(qualifier)
	if mixed {
		ipv4Range := parseData.mixedParsedAddress.getProviderSeqRange().ToIPv4SequentialRange()
		if hasMask && parseData.mixedMaskers == nil {
			parseData.mixedMaskers = make([]Masker, IPv4SegmentCount)
		}
		for n := 0; n < 2; n++ {
			m := n << 1
			segmentPrefixLength := getQualifierSegmentPrefixLength(normalizedSegmentIndex, IPv6BitsPerSegment, qualifier)
			o := m + 1
			oneLow := ipv4Range.GetLower().GetSegment(m)
			twoLow := ipv4Range.GetLower().GetSegment(o)
			oneUp := ipv4Range.GetUpper().GetSegment(m)
			twoUp := ipv4Range.GetUpper().GetSegment(o)
			oneLower := oneLow.GetSegmentValue()
			twoLower := twoLow.GetSegmentValue()
			oneUpper := oneUp.GetSegmentValue()
			twoUpper := twoUp.GetSegmentValue()

			originalOneLower := oneLower
			originalTwoLower := twoLower
			originalOneUpper := oneUpper
			originalTwoUpper := twoUpper

			if hasMask {
				maskInt := uint64(mask.GetSegment(normalizedSegmentIndex).GetSegmentValue())
				shift := IPv4BitsPerSegment
				shiftedMask := maskInt >> shift
				masker := parseData.mixedMaskers[m]
				lstringLower := uint64(oneLower)
				lstringUpper := uint64(oneUpper)
				if masker == nil {
					masker = maskRange(lstringLower, lstringUpper, shiftedMask, IPv4MaxValuePerSegment)
					parseData.mixedMaskers[m] = masker
					if !masker.IsSequential() && sections.maskError == nil {
						sections.maskError = &incompatibleAddressError{
							addressError: addressError{
								str: maskString(lstringLower, lstringUpper, shiftedMask),
								key: "ipaddress.error.maskMismatch",
							},
						}
					}
				}
				oneLower = SegInt(masker.GetMaskedLower(lstringLower, shiftedMask))
				oneUpper = SegInt(masker.GetMaskedUpper(lstringUpper, shiftedMask))
				lstringLower = uint64(twoLower)
				lstringUpper = uint64(twoUpper)
				masker = parseData.mixedMaskers[m+1]
				if masker == nil {
					masker = maskRange(lstringLower, lstringUpper, maskInt, IPv4MaxValuePerSegment)
					parseData.mixedMaskers[m+1] = masker
					if !masker.IsSequential() && sections.maskError == nil {
						sections.maskError = &incompatibleAddressError{
							addressError: addressError{
								str: maskString(lstringLower, lstringUpper, maskInt),
								key: "ipaddress.error.maskMismatch",
							},
						}
					}
				}
				twoLower = SegInt(masker.GetMaskedLower(lstringLower, maskInt))
				twoUpper = SegInt(masker.GetMaskedUpper(lstringUpper, maskInt))
				maskedIsDifferent = maskedIsDifferent || oneLower != originalOneLower || oneUpper != originalOneUpper ||
					twoLower != originalTwoLower || twoUpper != originalTwoUpper
			}
			isRange := oneLower != oneUpper || twoLower != twoUpper
			if doSections {
				doHostSegment := maskedIsDifferent || segmentPrefixLength != nil
				if doHostSegment {
					hostSegments = allocateSegments(hostSegments, segments, ipv6SegmentCount, normalizedSegmentIndex)
				}
				if !isRange {
					if doHostSegment {
						hostSegments[normalizedSegmentIndex] = createIPv6Segment(originalOneLower, originalTwoLower, nil, creator)
					}
					segments[normalizedSegmentIndex] = createIPv6Segment(
						oneLower,
						twoLower,
						segmentPrefixLength,
						creator)
				} else {
					if doHostSegment {
						hostSegments[normalizedSegmentIndex] = createIPv6RangeSegment(
							&sections,
							ipv4Range,
							originalOneLower,
							originalOneUpper,
							originalTwoLower,
							originalTwoUpper,
							nil,
							creator)
					}
					segments[normalizedSegmentIndex] = createIPv6RangeSegment(
						&sections,
						ipv4Range,
						oneLower,
						oneUpper,
						twoLower,
						twoUpper,
						segmentPrefixLength,
						creator)
				}
			}
			if doRangeBoundaries {
				if !doSections || isRange {
					if doSections {
						lowerSegments = allocateSegments(lowerSegments, segments, ipv6SegmentCount, normalizedSegmentIndex)
					} // else segments already allocated
					lowerSegments[normalizedSegmentIndex] = createIPv6Segment(
						oneLower,
						twoLower,
						segmentPrefixLength,
						creator)
				} else if lowerSegments != nil {
					lowerSegments[normalizedSegmentIndex] = segments[normalizedSegmentIndex]
				}
				if withUpper {
					if isRange {
						upperSegments = allocateSegments(upperSegments, lowerSegments, ipv6SegmentCount, normalizedSegmentIndex)
						upperSegments[normalizedSegmentIndex] = createIPv6Segment(
							oneUpper,
							twoUpper,
							segmentPrefixLength, // we must keep prefix length for upper to get prefix subnet creation
							creator)
					} else if upperSegments != nil {
						upperSegments[normalizedSegmentIndex] = lowerSegments[normalizedSegmentIndex]
					}
				}
			}
			normalizedSegmentIndex++
		}
	}
	var result, hostResult *IPAddressSection
	if doSections {
		if hostSegments != nil {
			hostResult = creator.createSectionInternal(hostSegments).ToIPAddressSection()
			sections.hostSection = hostResult
			if checkExpandedValues(hostResult, expandedStart, expandedEnd) {
				sections.joinHostError = &incompatibleAddressError{addressError{str: addressString, key: "ipaddress.error.invalid.joined.ranges"}}
			}
		}
		result = creator.createPrefixedSectionInternal(segments, prefLength)
		sections.section = result
		if checkExpandedValues(result, expandedStart, expandedEnd) {
			sections.joinAddressError = &incompatibleAddressError{addressError{str: addressString, key: "ipaddress.error.invalid.joined.ranges"}}
			if hostResult == nil {
				sections.joinHostError = sections.joinAddressError
			}
		}
	}
	if doRangeBoundaries {
		prefixLength := getPrefixLength(qualifier)
		isPrefixSub := false
		if prefixLength != nil {
			//IPAddressNetwork<?, ?, ?, ?, ?> network = getParameters().getIPv6Parameters().getNetwork();
			var lowerSegs, upperSegs []*AddressDivision
			if doSections {
				lowerSegs = segments
				upperSegs = segments
			} else {
				lowerSegs = lowerSegments
				if upperSegments == nil {
					upperSegs = lowerSegments
				} else {
					upperSegs = upperSegments
				}
			}
			isPrefixSub = isPrefixSubnet(
				func(index int) SegInt { return lowerSegs[index].ToAddressSegment().GetSegmentValue() },
				func(index int) SegInt { return upperSegs[index].ToAddressSegment().GetUpperSegmentValue() },
				len(lowerSegs),
				IPv6BytesPerSegment,
				IPv6BitsPerSegment,
				IPv6MaxValuePerSegment,
				*prefixLength,
				//network.getPrefixConfiguration(),
				false)
			if isPrefixSub {
				if lowerSegments == nil {
					//allocate lower segments from address segments
					lowerSegments = allocateSegments(lowerSegments, segments, ipv6SegmentCount, ipv6SegmentCount)
				}
				if upperSegments == nil {
					//allocate upper segments from lower segments
					upperSegments = allocateSegments(upperSegments, lowerSegments, ipv6SegmentCount, ipv6SegmentCount)
				}
			}
		}
		if lowerSegments != nil {
			boundaries.lowerSection = creator.createPrefixedSectionInternalSingle(lowerSegments, prefLength)
		}
		if upperSegments != nil {
			section := creator.createPrefixedSectionInternal(upperSegments, prefLength)
			if isPrefixSub {
				section = section.ToPrefixBlock()
			}
			boundaries.upperSection = section.GetUpper()
		}
	}
	return
}

func maskString(lower, upper, maskInt uint64) string {
	return strconv.FormatUint(lower, 10) + "-" + strconv.FormatUint(upper, 10) + " /" + strconv.FormatUint(maskInt, 10)
}

/*
 * When expanding a set of segments into multiple, it is possible that the new segments do not accurately
 * cover the same ranges of values.  This occurs when there is a range in the upper segments and the lower
 * segments do not cover the full range (as is the case in the original unexpanded segment).
 *
 * This does not include compressed 0 segments or compressed '*' segments, as neither can have the issue.
 *
 * Returns true if the expansion was invalid.
 *
 */
func checkExpandedValues(section *IPAddressSection, start, end int) bool {
	if section != nil && start < end {
		seg := section.GetSegment(start)
		lastWasRange := seg.IsMultiple()
		for {
			start++
			seg = section.GetSegment(start)
			if lastWasRange {
				if !seg.IsFullRange() {
					return true
				}
			} else {
				lastWasRange = seg.IsMultiple()
			}
			if start >= end {
				break
			}
		}
	}
	return false
}

func (parseData *parsedIPAddress) createSegment(
	addressString string,
	version IPVersion,
	val,
	upperVal SegInt,
	useFlags bool,
	parsedSegIndex int,
	segmentPrefixLength PrefixLen,
	creator parsedAddressCreator) *AddressDivision {
	parsed := parseData.getAddressParseData()
	if val != upperVal {
		return createRangeSeg(addressString, version, val, upperVal,
			useFlags, parsed, parsedSegIndex,
			segmentPrefixLength, creator)
	}
	var result *AddressDivision
	if !useFlags {
		result = creator.createSegment(val, val, segmentPrefixLength)
	} else {
		result = creator.createSegmentInternal(
			val,
			segmentPrefixLength,
			addressString,
			val,
			parsed.getFlag(parsedSegIndex, keyStandardStr),
			parsed.getIndex(parsedSegIndex, keyLowerStrStartIndex),
			parsed.getIndex(parsedSegIndex, keyLowerStrEndIndex))
	}
	return result
}

// create an IPv6 segment by joining two IPv4 segments
func createIPv6Segment(value1, value2 SegInt, segmentPrefixLength PrefixLen, creator parsedAddressCreator) *AddressDivision {
	value := (value1 << IPv4BitsPerSegment) | value2
	result := creator.createPrefixSegment(value, segmentPrefixLength)
	return result
}

// create an IPv6 segment by joining two IPv4 segments
func createIPv6RangeSegment(
	//finalResult *translatedResult,
	sections *sectionResult,
	item *IPv4AddressSeqRange, // this was only used to be put into any exceptions
	upperRangeLower,
	upperRangeUpper,
	lowerRangeLower,
	lowerRangeUpper SegInt,
	segmentPrefixLength PrefixLen,
	creator ipAddressCreator) *AddressDivision {
	shift := IPv4BitsPerSegment
	if upperRangeLower != upperRangeUpper {
		//if the high segment has a range, the low segment must match the full range,
		//otherwise it is not possible to create an equivalent IPv6 range when joining two IPv4 ranges
		if sections.mixedError == nil && lowerRangeLower != 0 || lowerRangeUpper != IPv4MaxValuePerSegment {
			sections.mixedError = &incompatibleAddressError{
				addressError: addressError{
					key: "ipaddress.error.invalidMixedRange",
				},
			}
		}
	}
	return creator.createSegment(
		(upperRangeLower<<shift)|lowerRangeLower,
		(upperRangeUpper<<shift)|lowerRangeUpper,
		segmentPrefixLength)
}

func createRangeSeg(
	addressString string,
	version IPVersion,
	stringLower,
	stringUpper SegInt,
	useFlags bool,
	parseData *addressParseData,
	parsedSegIndex int,
	segmentPrefixLength PrefixLen,
	creator parsedAddressCreator) *AddressDivision {
	var lower, upper = stringLower, stringUpper
	var result *AddressDivision
	if !useFlags {
		result = creator.createSegment(lower, upper, segmentPrefixLength)
	} else {
		result = creator.createRangeSegmentInternal(
			lower,
			upper,
			segmentPrefixLength,
			addressString,
			stringLower,
			stringUpper,
			parseData.getFlag(parsedSegIndex, keyStandardStr),
			parseData.getFlag(parsedSegIndex, keyStandardRangeStr),
			parseData.getIndex(parsedSegIndex, keyLowerStrStartIndex),
			parseData.getIndex(parsedSegIndex, keyLowerStrEndIndex),
			parseData.getIndex(parsedSegIndex, keyUpperStrEndIndex))
	}
	return result
}

func createFullRangeSegment(
	version IPVersion,
	stringLower,
	stringUpper SegInt,
	parsedSegIndex int,
	segmentPrefixLength PrefixLen,
	mask *SegInt,
	creator parsedAddressCreator) (result, hostResult, lower, upper *AddressDivision, err IncompatibleAddressError) {
	var maskedLower, maskedUpper SegInt
	hasMask := (mask != nil)
	maskedIsDifferent := false
	if hasMask {
		maskInt := DivInt(*mask)
		lstringLower := uint64(stringLower)
		lstringUpper := uint64(stringUpper)
		masker := maskRange(lstringLower, lstringUpper, maskInt, uint64(creator.getMaxValuePerSegment()))
		if !masker.IsSequential() {
			err = &incompatibleAddressError{
				addressError{
					str: maskString(lstringLower, lstringUpper, maskInt),
					key: "ipaddress.error.maskMismatch",
				},
			}
		}
		maskedLower = SegInt(masker.GetMaskedLower(lstringLower, maskInt))
		maskedUpper = SegInt(masker.GetMaskedUpper(lstringUpper, maskInt))
		maskedIsDifferent = maskedLower != stringLower || maskedUpper != stringUpper
	}
	result = createRangeSeg("", version, maskedLower, maskedUpper,
		false, nil, parsedSegIndex, segmentPrefixLength, creator)
	if maskedIsDifferent || segmentPrefixLength != nil {
		hostResult = createRangeSeg("", version, stringLower, stringUpper,
			false, nil, parsedSegIndex, nil, creator)
	} else {
		hostResult = result
	}
	if maskedLower == maskedUpper {
		lower = result
		upper = result
	} else {
		lower = createRangeSeg("", version, maskedLower, maskedLower,
			false, nil, parsedSegIndex, segmentPrefixLength, creator)
		upper = createRangeSeg("", version, maskedUpper, maskedUpper,
			false, nil, parsedSegIndex, segmentPrefixLength, creator)
	}
	return
}

func createAllAddress(
	version IPVersion,
	qualifier *ParsedHostIdentifierStringQualifier,
	originator HostIdentifierString) (res, hostAddr, lower, upper *IPAddress, err IncompatibleAddressError) {

	creator := version.toType().getIPNetwork().getIPAddressCreator()
	//prefixLength := qualifier.getEquivalentPrefixLength()
	mask := qualifier.getMaskLower()
	//TODO mask version must match version
	// Sometimes this function is called for a specific version, in fact that version might even be etermined by the mask, but it is not always dettermined by the mask
	if mask != nil && mask.GetBlockMaskPrefixLength(true) != nil {
		mask = nil //we don't do any masking if the mask is a subnet mask, instead we just map it to the corresponding prefix length
	}
	segmentCount := GetSegmentCount(version)
	segments := make([]*AddressDivision, segmentCount)
	hostSegments := make([]*AddressDivision, segmentCount)
	lowerSegments := make([]*AddressDivision, segmentCount)
	upperSegments := make([]*AddressDivision, segmentCount)
	segMaxVal := creator.getMaxValuePerSegment()
	//if prefixLength == nil { xxxx this looks wrong - what about mask, we can still have a mask when pref len is nil xxx
	//	allRangeSegment := creator.createSegment(0, segMaxVal, nil)
	//	for i := range segments {
	//		segments[i] = allRangeSegment
	//	}
	//} else {
	hasMask := mask != nil
	for i := 0; i < segmentCount; i++ {
		var segmentMask *SegInt
		if hasMask {
			maskVal := mask.getSegment(i).getSegmentValue()
			segmentMask = &maskVal
		}
		newSeg, hostSeg, lowSeg, upperSeg, rngErr := createFullRangeSegment(
			version,
			0,
			segMaxVal,
			i,
			getSegmentVersionedPrefixLength(i, version, qualifier),
			segmentMask,
			creator)
		if rngErr != nil && err == nil {
			err = rngErr
		}
		segments[i] = newSeg
		hostSegments[i] = hostSeg
		lowerSegments[i] = lowSeg
		upperSegments[i] = upperSeg
	}
	//}
	if err == nil {
		section := creator.createSectionInternal(segments)
		res = creator.createAddressInternalFromSection(section.ToIPAddressSection(), qualifier.getZone(), originator).ToIPAddress()
	}
	hostSection := creator.createSectionInternal(hostSegments)
	hostAddr = creator.createAddressInternal(hostSection.ToAddressSection(), nil).ToIPAddress()
	lowerSection := creator.createSectionInternal(lowerSegments)
	lower = creator.createAddressInternal(lowerSection.ToAddressSection(), nil).ToIPAddress()
	upperSection := creator.createSectionInternal(upperSegments)
	upper = creator.createAddressInternal(upperSection.ToAddressSection(), nil).ToIPAddress()
	return
	/*
		int segmentCount = IPAddress.getSegmentCount(version);
				IPAddress mask = qualifier.getMaskLower();
				if(mask != null && mask.getBlockMaskPrefixLength(true) != null) {
					mask = null;//we don't do any masking if the mask is a subnet mask, instead we just map it to the corresponding prefix length
				}
				boolean hasMask = mask != null;
				Integer prefLength = getPrefixLength(qualifier);
				if(version.isIPv4()) {
					parsedAddressCreator<IPv4Address, IPv4AddressSection, ?, IPv4AddressSegment> creator = options.getIPv4Parameters().getNetwork().getIPAddressCreator();
					IPv4AddressSegment segments[] = creator.createSegmentArray(segmentCount);
					for(int i = 0; i < segmentCount; i++) {
						Integer segmentMask = hasMask ? cacheSegmentMask(mask.getSegment(i).getSegmentValue()) : null;
						segments[i] = createFullRangeSegment(
								version,
								0,
								IPv4Address.MAX_VALUE_PER_SEGMENT,
								i,
								getSegmentPrefixLength(i, version, qualifier),
								segmentMask,
								creator);
					}
					return creator.createAddressInternal(segments, originator, prefLength);
				} else {
					parsedAddressCreator<IPv6Address, IPv6AddressSection, ?, IPv6AddressSegment> creator = options.getIPv6Parameters().getNetwork().getIPAddressCreator();
					IPv6AddressSegment segments[] = creator.createSegmentArray(segmentCount);
					for(int i = 0; i < segmentCount; i++) {
						Integer segmentMask = hasMask ? cacheSegmentMask(mask.getSegment(i).getSegmentValue()) : null;
						segments[i] = createFullRangeSegment(
								version,
								0,
								IPv6Address.MAX_VALUE_PER_SEGMENT,
								i,
								getSegmentPrefixLength(i, version, qualifier),
								segmentMask,
								creator);
					}
					return creator.createAddressInternal(segments, qualifier.getZone(), originator, prefLength);
				}
	*/
	//xxxxxx
	//return nil

	/*
		func (provider *macAddressAllProvider) getAddress() (*MACAddress, IncompatibleAddressError) {
			addr := provider.address
			if addr == nil {
				provider.creationLock.Lock()
				addr = provider.address
				if addr == nil {
					validationOptions := provider.validationOptions
					creator := provider.validationOptions.GetNetwork().GetMACAddressCreator()
					size := validationOptions.MACAddressSize()
					var segCount int
					if size == EUI64 {
						segCount = ExtendedUniqueIdentifier64SegmentCount
					} else {
						segCount = MediaAccessControlSegmentCount
					}
					allRangeSegment := creator.createMACRangeSegment(0, MACMaxValuePerSegment)
					segments := make([]*AddressDivision, segCount)
					for i := range segments {
						segments[i] = allRangeSegment
					}
					section := creator.createSectionInternal(segments)
					addr = creator.createAddressInternal(section.ToAddressSection(), nil).ToMACAddress()
				}
				provider.creationLock.Unlock()
			}
			return addr, nil
		}
	*/
}

func getPrefixLength(qualifier *ParsedHostIdentifierStringQualifier) PrefixLen {
	return qualifier.getEquivalentPrefixLength()
}

/**
 * Across the address prefixes are:
 * IPv6: (null):...:(null):(1 to 16):(0):...:(0)
 * or IPv4: ...(null).(1 to 8).(0)...
 *
 * @param segmentIndex
 * @return
 */
func getQualifierSegmentPrefixLength(segmentIndex int, bitsPerSegment BitCount, qualifier *ParsedHostIdentifierStringQualifier) PrefixLen {
	bits := getPrefixLength(qualifier)
	return getSegmentPrefixLength(bitsPerSegment, bits, segmentIndex)
}

/**
 * Across the address prefixes are:
 * IPv6: (null):...:(null):(1 to 16):(0):...:(0)
 * or IPv4: ...(null).(1 to 8).(0)...
 *
 * @param segmentIndex
 * @param version
 * @return
 */
func getSegmentVersionedPrefixLength(segmentIndex int, version IPVersion, qualifier *ParsedHostIdentifierStringQualifier) PrefixLen {
	return getQualifierSegmentPrefixLength(segmentIndex, BitsPerSegment(version), qualifier)
}
