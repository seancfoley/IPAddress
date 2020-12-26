package ipaddr

import (
	"strconv"
	"sync"
)

// TODO note that the way that you save substrings for segments in Java is perfect for go and slices, so your address creator interfaces will keep it

type TranslatedResult struct {
	CachedIPAddresses

	qualifier  *ParsedHostIdentifierStringQualifier
	originator HostIdentifierString

	//TODO later consider if perhaps the address and section should be embedded here - PROBABLY NOT, because TranslatedResult is likely embedded already in ParsedIPAddress and we want to throw away the parsing stuff

	//TODO range parsing not so hard to add, because it is in the same parsing function as sections.
	// BUT the code for managing the various parsed values in here is copied frmo Java and includes the groupings
	// so maybe it's better to do ranges and groupings at the same time

	rangeLower, rangeUpper *IPAddress

	section, hostSection,
	lowerSection, upperSection *IPAddressSection

	joinHostException, joinAddressException /* inet_aton, single seg */, mixedException, maskException IncompatibleAddressException

	rng *IPAddressSeqRange

	//series IPAddressDivisionSeries // TODO division grouping creation

	creator ParsedIPAddressCreator
}

func (res *TranslatedResult) getAddress() *IPAddress {
	if res.address == nil {
		// If an address is present we use it to construct the range.
		// So we need only share the boundaries when they were constructed first.
		//if(range == null) {
		res.address = res.creator.createAddressInternalFromSection(res.section, res.getZone(), res.originator)
		//} else {
		// TODO this just caches the lower and upper since we know them already, which we can do by just inserting them instead of another creator func
		//	address = getCreator().createAddressInternal(section, getZone(), originator, rangeLower, rangeUpper);
		//}
	}
	return res.address
}

func (res *TranslatedResult) getZone() Zone {
	return res.qualifier.getZone()
}

func (res *TranslatedResult) hasLowerSection() bool {
	return res.lowerSection != nil
}

func (res *TranslatedResult) hasHostAddress() bool {
	return res.hostAddress != nil
}

func (res *TranslatedResult) hasAddress() bool {
	return res.address != nil
}

func (res *TranslatedResult) getHostAddress() *IPAddress {
	if res.hostSection == nil {
		return res.getAddress()
	}
	if res.hostAddress == nil {
		res.hostAddress = res.creator.createAddressInternalFromSection(res.hostSection, res.getZone(), nil)
	}
	return res.hostAddress
}

func (res *TranslatedResult) getSection() *IPAddressSection {
	return res.section
}

func (res *TranslatedResult) withoutSections() bool {
	return res.section == nil
}

func (res *TranslatedResult) withoutAddressException() bool {
	return res.joinAddressException == nil && res.mixedException == nil && res.maskException == nil
}

func (res *TranslatedResult) withoutRange() bool {
	return res.rng == nil
}

func (res *TranslatedResult) withoutGrouping() bool {
	return false
	//TODO grouping parsing
	//return res.series == nil
}

func (res *TranslatedResult) createRange() *IPAddressSeqRange {
	//we need to add zone in order to reuse the lower and upper
	res.rangeLower = res.creator.createAddressInternalFromSection(res.lowerSection, res.getZone(), nil)
	if res.upperSection == nil {
		res.rangeUpper = res.rangeLower
	} else {
		res.rangeUpper = res.creator.createAddressInternalFromSection(res.upperSection, res.getZone(), nil)
	}
	res.rng = res.rangeLower.SpanWithRange(res.rangeUpper)
	return res.rng
}

// when this is used, the host address, regular address, and range boundaries are not used
func (res *TranslatedResult) getValForMask() *IPAddress {
	return res.creator.createAddressInternalFromSection(res.lowerSection, noZone, nil)
}

type ParsedIPAddress struct {
	IPAddressParseData

	ipAddrProvider

	options    IPAddressStringParameters
	originator HostIdentifierString
	valuesx    TranslatedResult
	//skipContains *bool //TODO additional containment options in IPAddressString
	maskers, mixedMaskers []Masker //TODO masking (not as bad as it looks)

	creationLock sync.RWMutex
}

func (parseData *ParsedIPAddress) values() *TranslatedResult {
	return &parseData.valuesx
}

func (parseData *ParsedIPAddress) providerCompare(other IPAddressProvider) (int, IncompatibleAddressException) {
	return providerCompare(parseData, other)
}

func (parseData *ParsedIPAddress) providerEquals(other IPAddressProvider) (bool, IncompatibleAddressException) {
	return providerEquals(parseData, other)
}

func (parseData *ParsedIPAddress) getIPv6AddressCreator() *IPv6AddressCreator {
	return parseData.getParameters().GetIPv6Parameters().GetNetwork().GetIPv6AddressCreator()
}

func (parseData *ParsedIPAddress) getIPv4AddressCreator() *IPv4AddressCreator {
	return parseData.getParameters().GetIPv4Parameters().GetNetwork().GetIPv4AddressCreator()
}

func (parseData *ParsedIPAddress) isProvidingIPAddress() bool {
	return true
}

func (parseData *ParsedIPAddress) getType() IPType {
	return fromVersion(parseData.getProviderIPVersion())
}

func (parseData *ParsedIPAddress) getParameters() IPAddressStringParameters {
	return parseData.options
}

// Note: the following are needed because we have two anonymous fields and there are name clashes
// Instead of defaulting to the default methods in IPAddressProvider, we need to defer to our parsed data for these methods
//

func (parseData *ParsedIPAddress) isProvidingMixedIPv6() bool {
	return parseData.IPAddressParseData.isProvidingMixedIPv6()
}

func (parseData *ParsedIPAddress) isProvidingIPv6() bool {
	return parseData.IPAddressParseData.isProvidingIPv6()
}

func (parseData *ParsedIPAddress) isProvidingIPv4() bool {
	return parseData.IPAddressParseData.isProvidingIPv4()
}

func (parseData *ParsedIPAddress) isProvidingBase85IPv6() bool {
	return parseData.IPAddressParseData.isProvidingBase85IPv6()
}

func (parseData *ParsedIPAddress) getProviderIPVersion() IPVersion {
	return parseData.IPAddressParseData.getProviderIPVersion()
}

func (parseData *ParsedIPAddress) getIPAddressParseData() *IPAddressParseData {
	return &parseData.IPAddressParseData
}

// creation methods start here

func (parseData *ParsedIPAddress) createSections(doAddress, doRangeBoundaries, withUpper bool) {
	version := parseData.getProviderIPVersion()
	if version.isIPv4() {
		parseData.createIPv4Sections(doAddress, doRangeBoundaries, withUpper)
	} else if version.isIPv6() {
		parseData.createIPv6Sections(doAddress, doRangeBoundaries, withUpper)
	}
	// assign other elements needed for address creation
	parseData.valuesx.originator, parseData.valuesx.qualifier = parseData.originator, parseData.getQualifier()
}

func (parseData *ParsedIPAddress) getProviderSeqRange() *IPAddressSeqRange {
	val := parseData.values()
	parseData.creationLock.RLock()
	result := val.rng
	parseData.creationLock.RUnlock()
	if result == nil {
		parseData.creationLock.Lock()
		result = val.rng
		if result == nil {
			if !val.withoutSections() && val.withoutAddressException() {
				val.rng = val.getAddress().ToSequentialRange()
			} else {
				parseData.createSections(false, true, true)
				// creates lower, upper, then range from the two
				val.createRange()
				if parseData.isDoneTranslating() {
					parseData.releaseSegmentData()
				}
			}
			result = val.rng
		}
		parseData.creationLock.Unlock()
	}
	return result
}

// this is for parsed addresses which are masks in and of themselves
// with masks, only the lower value matters
func (parseData *ParsedIPAddress) getValForMask() *IPAddress {
	val := parseData.values()
	parseData.creationLock.RLock()
	hasLower := val.hasLowerSection()
	parseData.creationLock.RUnlock()
	if !hasLower {
		parseData.creationLock.Lock()
		hasLower = val.hasLowerSection()
		if !hasLower {
			parseData.createSections(false, true, false)
			parseData.releaseSegmentData() // As a mask value, we can release our data sooner, there will be no request for address or division grouping
		}
		parseData.creationLock.Unlock()
	}
	// requests for masks are single-threaded, so locking no longer required
	return val.getValForMask()
}

// this is for parsed addresses which have associated masks
func (parseData *ParsedIPAddress) getProviderMask() *IPAddress {
	return parseData.getQualifier().getMaskLower()
}

func (parseData *ParsedIPAddress) isDoneTranslating() bool {
	val := parseData.values()
	return !val.withoutSections() /* address sections created */ &&
		(val.withoutAddressException() /* range can be created from sections */ ||
			!val.withoutRange() /* range already created (from sections or boundaries) */) &&
		!val.withoutGrouping()
}

func (parseData *ParsedIPAddress) getCachedAddresses(forHostAddr bool) *TranslatedResult {
	val := parseData.values()
	parseData.creationLock.RLock()
	hasSections := !val.withoutSections()
	var hasAddr bool
	if hasSections {
		if forHostAddr {
			hasAddr = val.hasHostAddress()
		} else {
			hasAddr = val.hasAddress()
		}
	}
	parseData.creationLock.RUnlock()
	if !hasAddr {
		parseData.creationLock.Lock()
		hasSections = !val.withoutSections()
		if !hasSections {
			parseData.createSections(true, false, false)
			if parseData.isDoneTranslating() {
				parseData.releaseSegmentData()
			}
		}
		if forHostAddr {
			val.getHostAddress()
		} else {
			val.getAddress()
		}
		parseData.creationLock.Unlock()
	}
	return val
}

func (parseData *ParsedIPAddress) getProviderHostAddress() (*IPAddress, IncompatibleAddressException) {
	addrs := parseData.getCachedAddresses(true)
	if addrs.mixedException != nil {
		return nil, addrs.mixedException
	} else if addrs.joinHostException != nil {
		return nil, addrs.joinHostException
	}
	return addrs.getHostAddress(), nil
}

func (parseData *ParsedIPAddress) getProviderAddress() (*IPAddress, IncompatibleAddressException) {
	addrs := parseData.getCachedAddresses(false)
	if addrs.mixedException != nil {
		return nil, addrs.mixedException
	} else if addrs.maskException != nil {
		return nil, addrs.maskException
	} else if addrs.joinHostException != nil {
		return nil, addrs.joinHostException
	}
	return addrs.getAddress(), nil
}

func (parseData *ParsedIPAddress) getVersionedAddress(version IPVersion) (*IPAddress, IncompatibleAddressException) {
	thisVersion := parseData.getProviderIPVersion()
	if version != thisVersion {
		return nil, nil
	}
	return parseData.getProviderAddress()
}

func (parseData *ParsedIPAddress) getProviderNetworkPrefixLength() PrefixLen {
	return parseData.getQualifier().getEquivalentPrefixLength()
}

func allocateSegments(
	segments,
	originalSegments []*AddressDivision,
	creator AddressSegmentCreator,
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

func (parseData *ParsedIPAddress) createIPv4Sections(doAddress, doRangeBoundaries, withUpper bool) {
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
	creator := parseData.getIPv4AddressCreator()
	missingCount := IPv4SegmentCount - segmentCount

	var hostSegments, segments, lowerSegments, upperSegments []*AddressDivision
	if doAddress {
		segments = createSegmentArray(IPv4SegmentCount)
	} else if doRangeBoundaries {
		lowerSegments = createSegmentArray(IPv4SegmentCount)
	} else {
		return
	}
	finalResult := &parseData.valuesx
	finalResult.creator = parseData.getIPv4AddressCreator()

	expandedSegments := (missingCount <= 0)
	var expandedStart, expandedEnd int = -1, -1
	addressString := parseData.str
	maskedIsDifferent := false
	for i, normalizedSegmentIndex := 0, 0; i < segmentCount; i++ {
		lower := addrParseData.getValue(i, KEY_LOWER)
		upper := addrParseData.getValue(i, KEY_UPPER)
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
				bits := IPv4BitsPerSegment * BitCount(missingCount+1)
				var maskedLower, maskedUpper uint64
				if hasMask {
					var divMask uint64
					for k := 0; k <= missingCount; k++ {
						divMask = (divMask << IPv4BitsPerSegment) | uint64(mask.GetSegment(normalizedSegmentIndex+k).GetSegmentValue())
					}
					masker := parseData.maskers[i]
					if masker == nil {
						var maxValue uint64 = ^(^uint64(0) << bits)
						masker = maskRangeWithMax(lower, upper, divMask, maxValue)
						if !masker.IsSequential() {
							if finalResult.maskException == nil {
								finalResult.maskException = &incompatibleAddressException{
									str: maskString(lower, upper, divMask),
									key: "ipaddress.error.maskMismatch"}
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
					if doAddress {
						if maskedIsDifferent || currentPrefix != nil {
							hostSegments = allocateSegments(hostSegments, segments, creator, IPv4SegmentCount, normalizedSegmentIndex)
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
						if !doAddress || isRange {
							if doAddress {
								lowerSegments = allocateSegments(lowerSegments, segments, creator, IPv4SegmentCount, normalizedSegmentIndex)
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
								upperSegments = allocateSegments(upperSegments, lowerSegments, creator, IPv4SegmentCount, normalizedSegmentIndex)
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
				masker = maskRangeWithMax(lower, upper, maskInt, uint64(creator.getMaxValuePerSegment()))
				parseData.maskers[i] = masker
				if !masker.IsSequential() && finalResult.maskException == nil {
					finalResult.maskException = &incompatibleAddressException{
						str: maskString(lower, upper, maskInt),
						key: "ipaddress.error.maskMismatch"}
				}
			}
			lower = masker.GetMaskedLower(lower, maskInt)
			upper = masker.GetMaskedUpper(upper, maskInt)
			unmasked = hostLower == lower && hostUpper == upper
			maskedIsDifferent = maskedIsDifferent || !unmasked
		}
		segmentPrefixLength := getQualifierSegmentPrefixLength(normalizedSegmentIndex, IPv4BitsPerSegment, qualifier)
		if doAddress {
			if maskedIsDifferent || segmentPrefixLength != nil {
				hostSegments = allocateSegments(hostSegments, segments, creator, IPv4SegmentCount, normalizedSegmentIndex)
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
			if !doAddress || isRange {
				if doAddress {
					lowerSegments = allocateSegments(lowerSegments, segments, creator, IPv4SegmentCount, normalizedSegmentIndex)
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
					upperSegments = allocateSegments(upperSegments, lowerSegments, creator, IPv4SegmentCount, normalizedSegmentIndex)
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
	if doAddress {
		result = creator.createPrefixedSectionInternal(segments, prefLength)
		finalResult.section = result
		if hostSegments != nil {
			hostResult = creator.createSectionInternal(hostSegments)
			finalResult.hostSection = hostResult
			if checkExpandedValues(hostResult, expandedStart, expandedEnd) {
				finalResult.joinHostException = &incompatibleAddressException{str: addressString, key: "ipaddress.error.invalid.joined.ranges"}
			}
		}

		if checkExpandedValues(result, expandedStart, expandedEnd) {
			finalResult.joinAddressException = &incompatibleAddressException{str: addressString, key: "ipaddress.error.invalid.joined.ranges"}
			if hostResult == nil {
				finalResult.joinHostException = finalResult.joinAddressException
			}
		}
	}
	if doRangeBoundaries {
		// if we have a prefix subnet, it is possible our lower and upper boundaries exceed what appears in the parsed address
		prefixLength := getPrefixLength(qualifier)
		isPrefixSub := false
		if prefixLength != nil {
			var lowerSegs, upperSegs []*AddressDivision
			if doAddress {
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
				//network.getPrefixConfiguration(),
				false)
			if isPrefixSub {
				if lowerSegments == nil {
					//allocate lower segments from address segments
					lowerSegments = allocateSegments(lowerSegments, segments, creator, IPv4SegmentCount, IPv4SegmentCount)
				}
				if upperSegments == nil {
					//allocate upper segments from lower segments
					upperSegments = allocateSegments(upperSegments, lowerSegments, creator, IPv4SegmentCount, IPv4SegmentCount)
				}
			}
		}
		if lowerSegments != nil {
			finalResult.lowerSection = creator.createPrefixedSectionInternalSingle(lowerSegments, prefLength).GetLower()
		}
		if upperSegments != nil {
			section := creator.createPrefixedSectionInternal(upperSegments, prefLength)
			if isPrefixSub {
				section = section.ToPrefixBlock()
			}
			finalResult.upperSection = section.GetUpper()
		}
	}
	return
}

func (parseData *ParsedIPAddress) createIPv6Sections(doAddress, doRangeBoundaries, withUpper bool) {
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
	creator := parseData.getIPv6AddressCreator()
	ipv6SegmentCount := IPv6SegmentCount
	var hostSegments, segments, lowerSegments, upperSegments []*AddressDivision
	if doAddress {
		segments = createSegmentArray(IPv6SegmentCount)
	} else if doRangeBoundaries {
		lowerSegments = createSegmentArray(IPv6SegmentCount)
	} else {
		return
	}
	finalResult := &parseData.valuesx
	finalResult.creator = parseData.getIPv6AddressCreator()
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
		lower := addressParseData.getValue(i, KEY_LOWER)
		upper := addressParseData.getValue(i, KEY_UPPER)

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
				if isCompressed {
					lower = 0 //TODO probably unnecessary, probably already 0
					upper = 0
				} else if isWildcard {
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
						lowerHighBytes = addressParseData.getValue(i, KEY_EXTENDED_LOWER) //the high half of the lower value
						upperHighBytes = addressParseData.getValue(i, KEY_EXTENDED_UPPER) //the high half of the upper value
						hostIsRange = (lower != upper) || (lowerHighBytes != upperHighBytes)
					} else {
						//lowerHighBytes = upperHighBytes = 0;
						hostIsRange = (lower != upper)
					}
					expandedStart = i
					expandedEnd = i + missingSegmentCount
				}
				bits := IPv6BitsPerSegment * BitCount(missingSegmentCount+1)
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
								extendedMaskVal = (extendedMaskVal << bitsPerSegment) | mask.GetSegment(normalizedSegmentIndex+k).GetDivisionValue()
							}
							for k := extendedCount; k <= missingSegmentCount; k++ {
								maskVal = (maskVal << bitsPerSegment) | mask.GetSegment(normalizedSegmentIndex+k).GetDivisionValue()
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
									if finalResult.maskException == nil {
										//byteCount := (missingSegmentCount + 1) * IPv6BytesPerSegment;
										finalResult.maskException = &incompatibleAddressException{
											str: addressString,
											//new BigInteger(1, toBytesSizeAdjusted(lower, lowerHighBytes, byteCount)).toString(),
											//new BigInteger(1, toBytesSizeAdjusted(upper, upperHighBytes, byteCount)).toString(),
											//new BigInteger(1, toBytesSizeAdjusted(maskVal, extendedMaskVal, byteCount)).toString(),
											key: "ipaddress.error.maskMismatch"}
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
								maskVal = (maskVal << bitsPerSegment) | mask.GetSegment(normalizedSegmentIndex+k).GetDivisionValue()
							}
							if masker == nil {
								// shift must be 6 bits at most for this shift to work per the java spec (so it must be less than 2^6 = 64)
								maxValue := ^(^DivInt(0) << bits)
								//long maxValue = bits == Long.SIZE ? 0xffffffffffffffffL : ~(~0L << bits);
								masker = maskRangeWithMax(lower, upper, maskVal, maxValue)
								if !masker.IsSequential() {
									if finalResult.maskException == nil {
										finalResult.maskException = &incompatibleAddressException{
											str: maskString(lower, upper, maskVal),
											key: "ipaddress.error.maskMismatch",
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
					if doAddress {
						if maskedIsDifferent || currentPrefix != nil {
							hostSegments = allocateSegments(hostSegments, segments, creator, ipv6SegmentCount, normalizedSegmentIndex)
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
						if !doAddress || isSegRange {
							if doAddress {
								lowerSegments = allocateSegments(lowerSegments, segments, creator, ipv6SegmentCount, normalizedSegmentIndex)
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
								upperSegments = allocateSegments(upperSegments, lowerSegments, creator, ipv6SegmentCount, normalizedSegmentIndex)
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
				masker = maskRangeWithMax(lower, upper, maskInt, uint64(creator.getMaxValuePerSegment()))
				parseData.maskers[i] = masker
				if !masker.IsSequential() && finalResult.maskException == nil {
					finalResult.maskException = &incompatibleAddressException{
						str: maskString(lower, upper, maskInt),
						key: "ipaddress.error.maskMismatch",
					}
				}
			}
			lower = masker.GetMaskedLower(lower, maskInt)
			upper = masker.GetMaskedUpper(upper, maskInt)
			unmasked = hostLower == lower && hostUpper == upper
			maskedIsDifferent = maskedIsDifferent || !unmasked
		}
		segmentPrefixLength := getQualifierSegmentPrefixLength(normalizedSegmentIndex, IPv6BitsPerSegment, qualifier)
		if doAddress {
			if maskedIsDifferent || segmentPrefixLength != nil {
				hostSegments = allocateSegments(hostSegments, segments, creator, ipv6SegmentCount, normalizedSegmentIndex)
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
			if !doAddress || isRange {
				if doAddress {
					lowerSegments = allocateSegments(lowerSegments, segments, creator, ipv6SegmentCount, normalizedSegmentIndex)
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
					upperSegments = allocateSegments(upperSegments, lowerSegments, creator, ipv6SegmentCount, normalizedSegmentIndex)
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
					masker = maskRangeWithMax(lstringLower, lstringUpper, shiftedMask, IPv4MaxValuePerSegment)
					parseData.mixedMaskers[m] = masker
					if !masker.IsSequential() && finalResult.maskException == nil {
						finalResult.maskException = &incompatibleAddressException{
							str: maskString(lstringLower, lstringUpper, shiftedMask),
							key: "ipaddress.error.maskMismatch",
						}
					}
				}
				oneLower = SegInt(masker.GetMaskedLower(lstringLower, shiftedMask))
				oneUpper = SegInt(masker.GetMaskedUpper(lstringUpper, shiftedMask))
				lstringLower = uint64(twoLower)
				lstringUpper = uint64(twoUpper)
				masker = parseData.mixedMaskers[m+1]
				if masker == nil {
					masker = maskRangeWithMax(lstringLower, lstringUpper, maskInt, IPv4MaxValuePerSegment)
					parseData.mixedMaskers[m+1] = masker
					if !masker.IsSequential() && finalResult.maskException == nil {
						finalResult.maskException = &incompatibleAddressException{
							str: maskString(lstringLower, lstringUpper, maskInt),
							key: "ipaddress.error.maskMismatch",
						}
					}
				}
				twoLower = SegInt(masker.GetMaskedLower(lstringLower, maskInt))
				twoUpper = SegInt(masker.GetMaskedUpper(lstringUpper, maskInt))
				maskedIsDifferent = maskedIsDifferent || oneLower != originalOneLower || oneUpper != originalOneUpper ||
					twoLower != originalTwoLower || twoUpper != originalTwoUpper
			}
			isRange := oneLower != oneUpper || twoLower != twoUpper
			if doAddress {
				doHostSegment := maskedIsDifferent || segmentPrefixLength != nil
				if doHostSegment {
					hostSegments = allocateSegments(hostSegments, segments, creator, ipv6SegmentCount, normalizedSegmentIndex)
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
							finalResult,
							ipv4Range,
							originalOneLower,
							originalOneUpper,
							originalTwoLower,
							originalTwoUpper,
							nil,
							creator)
					}
					segments[normalizedSegmentIndex] = createIPv6RangeSegment(
						finalResult,
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
				if !doAddress || isRange {
					if doAddress {
						lowerSegments = allocateSegments(lowerSegments, segments, creator, ipv6SegmentCount, normalizedSegmentIndex)
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
						upperSegments = allocateSegments(upperSegments, lowerSegments, creator, ipv6SegmentCount, normalizedSegmentIndex)
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
	if doAddress {
		if hostSegments != nil {
			hostResult = creator.createSectionInternal(hostSegments)
			finalResult.hostSection = hostResult
			if checkExpandedValues(hostResult, expandedStart, expandedEnd) {
				finalResult.joinHostException = &incompatibleAddressException{str: addressString, key: "ipaddress.error.invalid.joined.ranges"}
			}
		}
		result = creator.createPrefixedSectionInternal(segments, prefLength)
		finalResult.section = result
		if checkExpandedValues(result, expandedStart, expandedEnd) {
			finalResult.joinAddressException = &incompatibleAddressException{str: addressString, key: "ipaddress.error.invalid.joined.ranges"}
			if hostResult == nil {
				finalResult.joinHostException = finalResult.joinAddressException
			}
		}
	}
	if doRangeBoundaries {
		prefixLength := getPrefixLength(qualifier)
		isPrefixSub := false
		if prefixLength != nil {
			//IPAddressNetwork<?, ?, ?, ?, ?> network = getParameters().getIPv6Parameters().getNetwork();
			var lowerSegs, upperSegs []*AddressDivision
			if doAddress {
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
					lowerSegments = allocateSegments(lowerSegments, segments, creator, ipv6SegmentCount, ipv6SegmentCount)
				}
				if upperSegments == nil {
					//allocate upper segments from lower segments
					upperSegments = allocateSegments(upperSegments, lowerSegments, creator, ipv6SegmentCount, ipv6SegmentCount)
				}
			}
		}
		if lowerSegments != nil {
			finalResult.lowerSection = creator.createPrefixedSectionInternalSingle(lowerSegments, prefLength).GetLower() // getLower needed for all prefix subnet config
		}
		if upperSegments != nil {
			section := creator.createPrefixedSectionInternal(upperSegments, prefLength)
			if isPrefixSub {
				section = section.ToPrefixBlock()
			}
			finalResult.upperSection = section.GetUpper()
		}
	}
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

func (parseData *ParsedIPAddress) createSegment(
	addressString string,
	version IPVersion,
	val,
	upperVal SegInt,
	useFlags bool,
	parsedSegIndex int,
	segmentPrefixLength PrefixLen,
	creator ParsedAddressCreator) *AddressDivision {
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
			parsed.getFlag(parsedSegIndex, KEY_STANDARD_STR),
			parsed.getIndex(parsedSegIndex, KEY_LOWER_STR_START_INDEX),
			parsed.getIndex(parsedSegIndex, KEY_LOWER_STR_END_INDEX))
	}
	return result
}

/*
 * create an IPv6 segment by joining two IPv4 segments
 */
func createIPv6Segment(value1, value2 SegInt, segmentPrefixLength PrefixLen, creator ParsedAddressCreator) *AddressDivision {
	value := (value1 << IPv4BitsPerSegment) | value2
	result := creator.createPrefixSegment(value, segmentPrefixLength)
	return result
}

/*
 * create an IPv6 segment by joining two IPv4 segments
 */
func createIPv6RangeSegment(
	finalResult *TranslatedResult,
	item *IPv4AddressSeqRange, // this was only used to be put into any exceptions
	upperRangeLower,
	upperRangeUpper,
	lowerRangeLower,
	lowerRangeUpper SegInt,
	segmentPrefixLength PrefixLen,
	creator *IPv6AddressCreator) *AddressDivision {
	shift := IPv4BitsPerSegment
	if upperRangeLower != upperRangeUpper {
		//if the high segment has a range, the low segment must match the full range,
		//otherwise it is not possible to create an equivalent IPv6 range when joining two IPv4 ranges
		if finalResult.mixedException == nil && lowerRangeLower != 0 || lowerRangeUpper != IPv4MaxValuePerSegment {
			finalResult.mixedException = &incompatibleAddressException{key: "ipaddress.error.invalidMixedRange"}
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
	parseData *AddressParseData,
	parsedSegIndex int,
	segmentPrefixLength PrefixLen,
	creator ParsedAddressCreator) *AddressDivision {
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
			parseData.getFlag(parsedSegIndex, KEY_STANDARD_STR),
			parseData.getFlag(parsedSegIndex, KEY_STANDARD_RANGE_STR),
			parseData.getIndex(parsedSegIndex, KEY_LOWER_STR_START_INDEX),
			parseData.getIndex(parsedSegIndex, KEY_LOWER_STR_END_INDEX),
			parseData.getIndex(parsedSegIndex, KEY_UPPER_STR_END_INDEX))
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
	creator ParsedAddressCreator) (result *AddressDivision, err error) {
	hasMask := (mask != nil)
	if hasMask {
		maskInt := DivInt(*mask)
		lstringLower := uint64(stringLower)
		lstringUpper := uint64(stringUpper)
		masker := maskRangeWithMax(lstringLower, lstringUpper, maskInt, uint64(creator.getMaxValuePerSegment()))
		if !masker.IsSequential() {
			err = &incompatibleAddressException{
				str: maskString(lstringLower, lstringUpper, maskInt),
				key: "ipaddress.error.maskMismatch",
			}
			return
		}
		stringLower = SegInt(masker.GetMaskedLower(lstringLower, maskInt))
		stringUpper = SegInt(masker.GetMaskedUpper(lstringUpper, maskInt))
	}
	result = createRangeSeg("", version, stringLower, stringUpper,
		false, nil, parsedSegIndex, segmentPrefixLength, creator)
	return
}

//TODO lots of mask stuff
//TODO lots of prefixEquals, prefixContains etc

func createAllAddress(
	version IPVersion,
	qualifier *ParsedHostIdentifierStringQualifier,
	originator HostIdentifierString,
	options IPAddressStringParameters) *IPAddress {
	//TODO
	return nil
}

func maskExtendedRange(
	value, extendedValue,
	upperValue, extendedUpperValue,
	maskValue, extendedMaskValue,
	maxValue, extendedMaxValue uint64) ExtendedMasker {

	//algorithm:
	//here we find the highest bit that is part of the range, highestDifferingBitInRange (ie changes from lower to upper)
	//then we find the highest bit in the mask that is 1 that is the same or below highestDifferingBitInRange (if such a bit exists)
	//
	//this gives us the highest bit that is part of the masked range (ie changes from lower to upper after applying the mask)
	//if this latter bit exists, then any bit below it in the mask must be 1 to include the entire range.

	//
	//long extendedDiffering = extendedValue ^ extendedUpperValue;
	//if(extendedDiffering == 0) {
	//	// the top is single-valued so just need to check the lower part
	//	Masker masker = maskRangeWithMax(value, upperValue, maskValue, maxValue);
	//	if(masker == DEFAULT_MASKER) {
	//		return DEFAULT_MASKER;
	//	}
	//	if(masker instanceof FullRangeMasker) {
	//		int fullRangeBit = ((FullRangeMasker) masker).fullRangeBit;
	//		WrappedMasker cache[] = masker.isSequential() ? WRAPPED_SEQUENTIAL_FULL_RANGE_MASKERS : WRAPPED_FULL_RANGE_MASKERS;
	//		WrappedMasker result = cache[fullRangeBit];
	//		if(result == null) {
	//			cache[fullRangeBit] = result = new WrappedMasker(masker);
	//		}
	//		return result;
	//	}
	//	return new WrappedMasker(masker);
	//}
	//if(extendedValue > extendedUpperValue) {
	//	throw new IllegalArgumentException("value > upper value");
	//}
	//if((maskValue == maxValue && extendedMaskValue == extendedMaxValue /* all ones mask */) ||
	//		(maskValue == 0 && extendedMaskValue == 0 /* all zeros mask */)) {
	//	return DEFAULT_MASKER;
	//}
	//int highestDifferingBitInRange = Long.numberOfLeadingZeros(extendedDiffering);
	//long extendedDifferingMasked = extendedMaskValue & (~0L >>> highestDifferingBitInRange);
	//int highestDifferingBitMasked;
	//if(extendedDifferingMasked != 0) {
	//	boolean differingIsLowestBit = (extendedDifferingMasked == 1);
	//	highestDifferingBitMasked = Long.numberOfLeadingZeros(extendedDifferingMasked);
	//	boolean maskedIsSequential;
	//	long hostMask = ~0L >>> (highestDifferingBitMasked + 1);
	//	if(!differingIsLowestBit) { // Anything below highestDifferingBitMasked in the mask must be ones.
	//		//for the first mask bit that is 1, all bits that follow must also be 1
	//		maskedIsSequential = (extendedMaskValue & hostMask) == hostMask && maskValue == maxValue; //check if all ones below
	//	} else {
	//		maskedIsSequential = maskValue == maxValue;
	//	}
	//	if(value == 0 && extendedValue == 0 &&
	//			upperValue == maxValue && extendedUpperValue == extendedMaxValue) {
	//		// full range
	//		if(maskedIsSequential) {
	//			return DEFAULT_MASKER;
	//		} else {
	//			return DEFAULT_NON_SEQUENTIAL_MASKER;
	//		}
	//	}
	//	if(highestDifferingBitMasked > highestDifferingBitInRange) {
	//		if(maskedIsSequential) {
	//			// We need to check that the range is larger enough that when chopping off the top it remains sequential
	//
	//			// Note: a count of 2 in the extended could equate to a count of 2 total!
	//			// upper: xxxxxxx1 00000000
	//			// lower: xxxxxxx0 11111111
	//			// Or, it could be everything:
	//			// upper: xxxxxxx1 11111111
	//			// lower: xxxxxxx0 00000000
	//			// So for that reason, we need to check the full count here and not just extended
	//
	//			int shift = Long.SIZE - highestDifferingBitMasked; // highestDifferingBitMasked > 0 so shift < 64 which is required for long left shift
	//			BigInteger countRequiredForSequential = ONE_SHIFTED_EXTENDED[shift];
	//			if(countRequiredForSequential == null) {
	//				countRequiredForSequential = ONE_SHIFTED_EXTENDED[shift] = BigInteger.valueOf(1L << shift).shiftLeft(Long.SIZE);
	//			}
	//			BigInteger upperBig = new BigInteger(1, toBytesSizeAdjusted(upperValue, extendedUpperValue, 16));
	//			BigInteger lowerBig = new BigInteger(1, toBytesSizeAdjusted(value, extendedValue, 16));
	//			BigInteger count = upperBig.subtract(lowerBig).add(BigInteger.ONE);
	//			maskedIsSequential = count.compareTo(countRequiredForSequential) >= 0;
	//		}
	//		ExtendedFullRangeMasker cache[] = maskedIsSequential ? EXTENDED_SEQUENTIAL_FULL_RANGE_MASKERS : EXTENDED_FULL_RANGE_MASKERS;
	//		ExtendedFullRangeMasker result = cache[highestDifferingBitMasked];
	//		if(result == null) {
	//			cache[highestDifferingBitMasked] = result = new ExtendedFullRangeMasker(highestDifferingBitMasked, maskedIsSequential);
	//		}
	//		return result;
	//	} else if(!maskedIsSequential) {
	//		BigInteger bigHostMask = HOST_MASK_EXTENDED[highestDifferingBitMasked];
	//		if(bigHostMask == null) {
	//			bigHostMask = BigInteger.valueOf(hostMask);
	//			bigHostMask = bigHostMask.shiftLeft(Long.SIZE);
	//			byte b = (byte) 0xff;
	//			bigHostMask = bigHostMask.or(new BigInteger(1, new byte[] {b, b, b, b, b, b, b, b}));
	//			HOST_MASK_EXTENDED[highestDifferingBitMasked] = bigHostMask;
	//		}
	//		BigInteger bigHostZeroed = NETWORK_MASK_EXTENDED[highestDifferingBitMasked];
	//		if(bigHostZeroed == null) {
	//			bigHostZeroed = NETWORK_MASK_EXTENDED[highestDifferingBitMasked] = bigHostMask.not();
	//		}
	//		BigInteger upperBig = new BigInteger(1, toBytesSizeAdjusted(upperValue, extendedUpperValue, 16));
	//		BigInteger lowerBig = new BigInteger(1, toBytesSizeAdjusted(value, extendedValue, 16));
	//		BigInteger upperToBeMaskedBig = upperBig.and(bigHostZeroed);
	//		BigInteger lowerToBeMaskedBig = lowerBig.or(bigHostMask);
	//		BigInteger maskBig = new BigInteger(1, toBytesSizeAdjusted(maskValue, extendedMaskValue, 16));
	//		for(int nextBit = 128 - (highestDifferingBitMasked + 1) - 1; nextBit >= 0; nextBit--) {
	//			if(maskBig.testBit(nextBit)) {
	//				BigInteger candidate = upperToBeMaskedBig.setBit(nextBit);
	//				if(candidate.compareTo(upperBig) <= 0) {
	//					upperToBeMaskedBig = candidate;
	//				}
	//				candidate = lowerToBeMaskedBig.clearBit(nextBit);
	//				if(candidate.compareTo(lowerBig) >= 0) {
	//					lowerToBeMaskedBig = candidate;
	//				}
	//			} //else
	//			// keep our upperToBeMaskedBig bit as 0
	//			// keep our lowerToBeMaskedBig bit as 1
	//		}
	//		return new ExtendedSpecificValueMasker(
	//				lowerToBeMaskedBig.shiftRight(Long.SIZE).longValue(),
	//				lowerToBeMaskedBig.longValue(),
	//				upperToBeMaskedBig.shiftRight(Long.SIZE).longValue(),
	//				upperToBeMaskedBig.longValue());
	//	}
	//	return DEFAULT_MASKER;
	//
	//}
	//// When masking, the top becomes single-valued.
	//
	//// We go to the lower values to find highestDifferingBitMasked.
	//
	//// At this point, the highest differing bit in the lower range is 0
	//// and the highestDifferingBitMasked is the first 1 bit in the lower mask
	//
	//if(maskValue == 0) {
	//	// the mask zeroes out everything,
	//	return DEFAULT_MASKER;
	//}
	//boolean maskedIsSequential = true;
	//int highestDifferingBitMaskedLow = Long.numberOfLeadingZeros(maskValue);
	//if(maskValue != maxValue && highestDifferingBitMaskedLow < Long.SIZE - 1) {
	//	//for the first mask bit that is 1, all bits that follow must also be 1
	//	long hostMask = ~0L >>> (highestDifferingBitMaskedLow + 1); // this shift of since case of highestDifferingBitMaskedLow of 64 and 63 taken care of, so the shift is < 64
	//	maskedIsSequential = (maskValue & hostMask) == hostMask; //check if all ones below
	//}
	//if(maskedIsSequential) {
	//	// Note: a count of 2 in the lower values could equate to a count of everything in the full range:
	//	// upper: xxxxxx10 00000000
	//	// lower: xxxxxxx0 11111111
	//	// Another example:
	//	// upper: xxxxxxx1 00000001
	//	// lower: xxxxxxx0 00000000
	//	// So for that reason, we need to check the full count here and not just lower values
	//
	//	// We need to check that the range is larger enough that when chopping off the top it remains sequential
	//	BigInteger countRequiredForSequential;
	//	if(highestDifferingBitMaskedLow == 0) {
	//		countRequiredForSequential = ONE_EXTENDED;
	//	} else if(highestDifferingBitMaskedLow == 1) { // need this case because 1 << 63 is a negative number
	//		countRequiredForSequential = HIGH_BIT;
	//	} else {
	//		int shift = Long.SIZE - highestDifferingBitMaskedLow;
	//		countRequiredForSequential = ONE_SHIFTED[shift];
	//		if(countRequiredForSequential == null) {
	//			countRequiredForSequential = ONE_SHIFTED[shift] = BigInteger.valueOf(1L << shift);
	//		}
	//	}
	//	BigInteger upperBig = new BigInteger(1, toBytesSizeAdjusted(upperValue, extendedUpperValue, 16));
	//	BigInteger lowerBig = new BigInteger(1, toBytesSizeAdjusted(value, extendedValue, 16));
	//	BigInteger count = upperBig.subtract(lowerBig).add(BigInteger.ONE);
	//	maskedIsSequential = count.compareTo(countRequiredForSequential) >= 0;
	//}
	//highestDifferingBitMasked = highestDifferingBitMaskedLow + Long.SIZE;
	//ExtendedFullRangeMasker cache[] = maskedIsSequential ? EXTENDED_SEQUENTIAL_FULL_RANGE_MASKERS : EXTENDED_FULL_RANGE_MASKERS;
	//ExtendedFullRangeMasker result = cache[highestDifferingBitMasked];
	//if(result == null) {
	//	cache[highestDifferingBitMasked] = result = new ExtendedFullRangeMasker(highestDifferingBitMasked, maskedIsSequential);
	//}
	//return result;

	return nil
}

//func maskRange(value, upperValue, maskValue uint64) Masker {
//	return maskRangeWithMax(value, upperValue, maskValue, 0xffffffffffffffff)
//}

func maskRangeWithMax(value, upperValue, maskValue, maxValue uint64) Masker {
	//if(value == upperValue) {
	//	return DEFAULT_MASKER;
	//}
	//if(value > upperValue) {
	//	throw new IllegalArgumentException("value > upper value");
	//}
	//if(maskValue == 0 || maskValue == maxValue) {
	//	return DEFAULT_MASKER;
	//}
	//
	////algorithm:
	////here we find the highest bit that is part of the range, highestDifferingBitInRange (ie changes from lower to upper)
	////then we find the highest bit in the mask that is 1 that is the same or below highestDifferingBitInRange (if such a bit exists)
	//
	////this gives us the highest bit that is part of the masked range (ie changes from lower to upper after applying the mask)
	////if this latter bit exists, then any bit below it in the mask must be 1 to remain sequential.
	//
	//long differing = value ^ upperValue;
	//if(differing != 1) {
	//	int highestDifferingBitInRange = Long.numberOfLeadingZeros(differing);
	//	long maskMask = ~0L >>> highestDifferingBitInRange;
	//	long differingMasked = maskValue & maskMask;
	//	boolean foundDiffering = (differingMasked != 0);
	//	if(foundDiffering) {
	//		// Anything below highestDifferingBitMasked in the mask must be ones.
	//		// Also, if we have masked out any 1 bit in the original, then anything that we do not mask out that follows must be all 1s
	//		int highestDifferingBitMasked = Long.numberOfLeadingZeros(differingMasked); // first one bit in the mask covering the range
	//		long hostMask = (highestDifferingBitMasked == Long.SIZE - 1) ? 0 : ~0L >>> (highestDifferingBitMasked + 1);//for the first mask bit that is 1, all bits that follow must also be 1
	//		boolean maskedIsSequential = (maskValue & hostMask) == hostMask;
	//		if(maxValue == -1 &&
	//				(!maskedIsSequential || highestDifferingBitMasked > highestDifferingBitInRange)) {
	//			int highestOneBit = Long.numberOfLeadingZeros(upperValue);
	//			// note we know highestOneBit < 64, otherwise differing would be 1 or 0
	//			maxValue = ~0L >>> highestOneBit;
	//		}
	//		if(value == 0 && upperValue == maxValue) {
	//			// full range
	//			if(maskedIsSequential) {
	//				return DEFAULT_MASKER;
	//			} else {
	//				return DEFAULT_NON_SEQUENTIAL_MASKER;
	//			}
	//		}
	//		if(highestDifferingBitMasked > highestDifferingBitInRange) {
	//			if(maskedIsSequential) {
	//				// the count will determine if the masked range is sequential
	//				if(highestDifferingBitMasked < Long.SIZE - 1) {
	//					long count = upperValue - value + 1;
	//
	//					// if original range is 0xxxx to 1xxxx and our mask starts with a single 0 so the mask is 01111,
	//					// then our new range covers 4 bits at most (could be less).
	//					// If the range covers 4 bits, we need to know if that range covers the same count of values as 0000 to 1111.
	//					// If so, the resulting range is not disjoint.
	//					// How do we know the range is disjoint otherwise?  We know because it has the values 1111 and 0000.
	//					// In order to go from 0xxxx to 1xxxx you must cross the consecutive values 01111 and 10000.
	//					// These values are consecutive in the original range (ie 01111 is followed by 10000) but in the new range
	//					// they are farthest apart and we need the entire range to fill the gap between them.
	//					// That count of values for the entire range is 1111 - 0000 + 1 = 10000
	//					// So in this example, the first bit in the original range is bit 0, highestDifferingBitMasked is 1,
	//					// and the range must cover 2 to the power of (5 - 1),
	//					// or 2 to the power of bit count - highestDifferingBitMasked, or 1 shifted by that much.
	//
	//					long countRequiredForSequential = 1L << (Long.SIZE - highestDifferingBitMasked);
	//					if(count < countRequiredForSequential) {
	//						// the resulting masked values are disjoint, not sequential
	//						maskedIsSequential = false;
	//					}
	//				} // else count of 2 is good enough, even if the masked range does not cover both values, then the result is a single value, which is also sequential
	//				// another way of looking at it: when the range is just two, we do not need to see if the masked range covers all values in between, as there is no values in between
	//			}
	//			// The range part of the values will go from 0 to the mask itself.
	//			// This is because we know that if the range is 0xxxx... to 1yyyy..., then 01111... and 10000... are also in the range,
	//			// since that is the only way to transition from 0xxxx... to 1yyyy...
	//			// Because the mask has no 1 bit at the top bit, then we know that when masking with those two values 01111... and 10000...
	//			// we get the mask itself and 00000 as the result.
	//			FullRangeMasker cache[] = maskedIsSequential ? SEQUENTIAL_FULL_RANGE_MASKERS : FULL_RANGE_MASKERS;
	//			FullRangeMasker result = cache[highestDifferingBitMasked];
	//			if(result == null) {
	//				cache[highestDifferingBitMasked] = result = new FullRangeMasker(highestDifferingBitMasked, maskedIsSequential);
	//			}
	//			return result;
	//		} else if(!maskedIsSequential) {
	//			long hostZeroed = ~hostMask;
	//			long upperToBeMasked = upperValue & hostZeroed;
	//			long lowerToBeMasked = value | hostMask;
	//			// we find a value in the range that will produce the highest and lowest values when masked
	//			for(long nextBit = (1 << (Long.SIZE - (highestDifferingBitMasked + 1) - 1)); nextBit != 0; nextBit >>>= 1) {
	//				// check if the bit in the mask is 1
	//				if((maskValue & nextBit) != 0) {
	//					long candidate = upperToBeMasked | nextBit;
	//					if(candidate <= upperValue) {
	//						upperToBeMasked = candidate;
	//					}
	//					candidate = lowerToBeMasked & ~nextBit;
	//					if(candidate >= value) {
	//						lowerToBeMasked = candidate;
	//					}
	//				} //else
	//					// keep our upperToBeMasked bit as 0
	//					// keep our lowerToBeMasked bit as 1
	//			}
	//			return new SpecificValueMasker(lowerToBeMasked, upperToBeMasked);
	//		} // else fall through to default masker
	//	}
	//}
	//return DEFAULT_MASKER;
	return defaultMasker
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

type Masker interface {
	// GetMaskedLower provides the lowest masked value, which is not necessarily the lowest value masked
	GetMaskedLower(value, maskValue DivInt) DivInt

	// GetMaskedUpper provides the highest masked value, which is not necessarily the highest value masked
	GetMaskedUpper(upperValue, maskValue DivInt) DivInt

	// IsSequential returns whether masking all values in the range results in a sequential set of values
	IsSequential() bool
}

type ExtendedMasker interface {
	Masker

	GetExtendedMaskedLower(extendedValue, extendedMaskValue DivInt) DivInt

	GetExtendedMaskedUpper(extendedUpperValue, extendedMaskValue DivInt) DivInt
}

var (
	defaultMasker              ExtendedMasker = extendedMaskerBase{maskerBase{true}}
	defaultNonSequentialMasker ExtendedMasker = extendedMaskerBase{}
)

type maskerBase struct {
	isSequentialVal bool
}

func (masker maskerBase) GetMaskedLower(value, maskValue DivInt) DivInt {
	return value & maskValue
}

func (masker maskerBase) GetMaskedUpper(upperValue, maskValue DivInt) DivInt {
	return upperValue & maskValue
}

func (masker maskerBase) IsSequential() bool {
	return masker.isSequentialVal
}

var _ Masker = maskerBase{}

type extendedMaskerBase struct {
	maskerBase
}

func (masker maskerBase) GetExtendedMaskedLower(extendedValue, extendedMaskValue DivInt) DivInt {
	return extendedValue & extendedMaskValue
}

func (masker maskerBase) GetExtendedMaskedUpper(extendedUpperValue, extendedMaskValue DivInt) DivInt {
	return extendedUpperValue & extendedMaskValue
}

var _ ExtendedMasker = extendedMaskerBase{}
var _ Masker = extendedMaskerBase{}

//TODO the remaining maskers, which is not so hard.  All of them have a nested maskerBase.  They can also all have pointer receivers if you want.

var _ Masker = maskerBase{}
