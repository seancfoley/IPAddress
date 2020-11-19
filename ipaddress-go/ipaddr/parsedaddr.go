package ipaddr

import "sync"

// TODO note that the way that you save substrings for segments in Java is perfect for go and slices, so your address creator interfaces will keep it

type TranslatedResult struct {
	CachedIPAddresses

	//TODO later consider if perhaps the address and section should be embedded here - PROBABLY NOT, because TranslatedResult is likely embedded already in ParsedIPAddress and we want to throw away the parsing stuff

	//TODO range parsing not so hard to add, because it is in the same parsing function as sections.
	// BUT the code for managing the various parsed values in here is copied frmo Java and includes the groupings
	// so maybe it's better to do ranges and groupings at the same time

	//rangeLower, rangeUpper *IPAddress //TODO range parsing

	section, hostSection,
	lowerSection/*, upperSection TODO range parsing */ *IPAddressSection

	joinHostException, joinAddressException /* inet_aton, single seg */, mixedException, maskException IncompatibleAddressException

	//TODO the other parsing options
	//range *IPAddressSeqRange
	//series IPAddressDivisionSeries

	creator ParsedIPAddressCreator

	parsed *ParsedIPAddress // In java this is the outer instance of the nested TranslatedResult
}

func (res *TranslatedResult) getAddress() *IPAddress {
	if res.address == nil {
		// If an address is present we use it to construct the range.
		// So we need only share the boundaries when they were constructed first.
		//if(range == null) { TODO range parsing
		res.address = res.creator.createAddressInternalFromSection(res.section, res.getZone(), res.parsed.originator)
		//} else {
		//	address = getCreator().createAddressInternal(section, getZone(), originator, rangeLower, rangeUpper);
		//}
	}
	return res.address
}

func (res *TranslatedResult) getZone() Zone {
	return res.parsed.getQualifier().getZone()
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
	return false
	//TODO range parsing
	//return res.range == nil
}

func (res *TranslatedResult) withoutGrouping() bool {
	return false
	//TODO grouping parsing
	//return res.series == nil
}

//func (res *TranslatedResult)  createRange() *IPAddressSeqRange { //TODO range parsing
//			//we need to add zone in order to reuse the lower and upper
//	res.rangeLower = res.creator.createAddressInternal(res.lowerSection, res.getZone(), nil)
//	if res.upperSection == nil {
//		res.rangeUpper = res.rangeLower
//	} else {
//		res.rangeUpper = res.creator.createAddressInternal(res.upperSection, res.getZone(), nil);
//	}
//	res.range = res.rangeLower.toSequentialRange(res.rangeUpper);
//	return res.range
//}

// when this is used, the host address, regular address, and range boundaries are not used
func (res *TranslatedResult) getValForMask() *IPAddress {
	return res.creator.createAddressInternalFromSection(res.lowerSection, noZone, nil)
}

type ParsedIPAddress struct {
	IPAddressParseData

	ipAddrProvider

	//TODO ParsedIPAddress

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

func (parseData *ParsedIPAddress) createSections(doAddress, doRangeBoundaries, withUpper bool) IncompatibleAddressException {
	version := parseData.getProviderIPVersion()
	if version.isIPv4() {
		return parseData.createIPv4Sections(doAddress, doRangeBoundaries, withUpper)
	} else if version.isIPv6() {
		return parseData.createIPv6Sections(doAddress, doRangeBoundaries, withUpper)
	}
	return nil
}

//func (parseData *ParsedIPAddress)   getProviderSeqRange() *IPAddressSeqRange {
//		 val := parseData.values()
//		parseData.creationLock.RLock()
//		result := val.range
//		parseData.creationLock.RUnlock()
//		if result == nil {
//			parseData.creationLock.Lock()
//			result = val.range
//			if(result == nil) {
//				if(!val.withoutSections() && val.withoutAddressException()) {
//					val.range = val.getAddress().toSequentialRange();
//				} else {
//					parseData.createSections(false, true, true);
//					// creates lower, upper, then range from the two
//					val.createRange();
//					if(parseData.isDoneTranslating()) {
//						parseData.releaseSegmentData();
//					}
//				}
//				result = val.range
//			}
//			parseData.creationLock.Unlock()
//		}
//		return result
//	}

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
		segments = creator.createSegmentArray(segmentCount)
		if originalCount > 0 {
			copy(segments, originalSegments[:originalCount])
		}
	}
	return segments
}

//func (parseData *ParsedIPAddress) createIPv4Sections( doAddress,  doRangeBoundaries,  withUpper bool)  (err IncompatibleAddressException) {
//		 qualifier := parseData.getQualifier();
//		 mask := parseData.getProviderMask();
//		if(mask != nil && mask.GetBlockMaskPrefixLength(true) != nil) {
//			mask = nil; //we don't do any masking if the mask is a subnet mask, instead we just map it to the corresponding prefix length
//		}
//		 hasMask := mask != nil;
//		 addrParseData := parseData.getAddressParseData();
//		segmentCount := addrParseData.getSegmentCount();
//		if(hasMask && parseData.maskers == nil) {
//			parseData.maskers = make([]Masker, segmentCount);
//		}
//		creator := parseData.getIPv4AddressCreator();
//		 ipv4SegmentCount := IPv4SegmentCount
//		missingCount := ipv4SegmentCount - segmentCount;
//
//		var hostSegments, segments, lowerSegments, upperSegments []*AddressDivision
//		if(doAddress) {
//			segments = creator.createSegmentArray(ipv4SegmentCount);
//		} else if(doRangeBoundaries) {
//			lowerSegments = creator.createSegmentArray(ipv4SegmentCount);
//		} else {
//			return;
//		}
//		finalResult := &parseData.valuesx
//		finalResult.creator = parseData.getIPv4AddressCreator()
//
//		 expandedSegments := (missingCount <= 0);
//		var expandedStart, expandedEnd int = -1,-1
//		 addressString := parseData.str;
//		 maskedIsDifferent := false;
//		for i, normalizedSegmentIndex := 0, 0; i < segmentCount; i++ {
//			 lower := addrParseData.getValue(i, KEY_LOWER);
//			 upper := addrParseData.getValue(i, KEY_UPPER);
//			if(!expandedSegments) {
//				//check for any missing segments that we should account for here
//				 isLastSegment := i == segmentCount - 1;
//				 isWildcard := addrParseData.isWildcard(i);
//				expandedSegments = isLastSegment;
//				if(!expandedSegments) {
//					// if we are inet_aton, we must wait for last segment
//					// otherwise, we check if we are wildcard and no other wildcard further down
//					expandedSegments = !parseData.is_inet_aton_joined() && isWildcard;
//					if(expandedSegments) {
//						for  j := i + 1; j < segmentCount; j++ {
//							if(addrParseData.isWildcard(j)) {//another wildcard further down
//								expandedSegments = false;
//								break;
//							}
//						}
//					}
//				}
//				if(expandedSegments) {
//					if(isWildcard) {
//						upper = 0xffffffff >> ((3 - missingCount) << 3);
//					} else {
//						expandedStart = i;
//						expandedEnd = i + missingCount;
//					}
//					 bits := IPv4BitsPerSegment * (missingCount + 1);
//					var maskedLower, maskedUpper uint64
//					if(hasMask) {
//						var divMask uint64
//						for k := 0; k <= missingCount; k++ {
//							divMask = (divMask << IPv4BitsPerSegment) | uint64(mask.GetSegment(normalizedSegmentIndex + k).GetSegmentValue())
//						}
//						 masker := parseData.maskers[i];
//						if(masker == nil) {
//							var maxValue uint64 = (bits == 32) ? 0xffffffffL : ~(~0 << bits); //TODO check if the golang shift has the same limitations as Java
//							masker = parseData.maskRange(lower, upper, divMask, maxValue);
//							if(!masker.IsSequential()) {
//								if(finalResult.maskException == nil) {
//									finalResult.maskException = new IncompatibleAddressException(lower, upper, divMask, "ipaddress.error.maskMismatch");
//								}
//							}
//							parseData.maskers[i] = masker;
//						}
//						maskedLower = masker.GetMaskedLower(lower, divMask);
//						maskedUpper = masker.GetMaskedUpper(upper, divMask);
//						maskedIsDifferent = maskedIsDifferent || maskedLower != lower || maskedUpper != upper;
//					} else {
//						maskedLower = lower;
//						maskedUpper = upper;
//					}
//					int shift = bits;
//					int count = missingCount;
//					while(count >= 0) { //add the missing segments
//						shift -= IPv4Address.BITS_PER_SEGMENT;
//						Integer currentPrefix = getSegmentPrefixLength(normalizedSegmentIndex, IPv4Address.BITS_PER_SEGMENT, qualifier);
//						int segmentBitsMask = IPv4Address.MAX_VALUE_PER_SEGMENT;
//						int hostSegLower = (int) (lower >>> shift) & segmentBitsMask;
//						int hostSegUpper = (lower == upper) ? hostSegLower : (int) (upper >>> shift) & segmentBitsMask;
//						int maskedSegLower, maskedSegUpper;
//						if(hasMask) {
//							maskedSegLower = (int) (maskedLower >>> shift) & segmentBitsMask;
//							maskedSegUpper = (maskedLower == maskedUpper) ? maskedSegLower : (int) (maskedUpper >>> shift) & segmentBitsMask;
//						} else {
//							maskedSegLower = hostSegLower;
//							maskedSegUpper = hostSegUpper;
//						}
//						if(doAddress) {
//							if(maskedIsDifferent || currentPrefix != null) {
//								hostSegments = allocateSegments(hostSegments, segments, creator, ipv4SegmentCount, normalizedSegmentIndex);
//								hostSegments[normalizedSegmentIndex] = createSegment(
//										addressString,
//										IPVersion.IPV4,
//										hostSegLower,
//										hostSegUpper,
//										false,
//										i,
//										null,
//										creator);
//							}
//							segments[normalizedSegmentIndex] = createSegment(
//								addressString,
//								IPVersion.IPV4,
//								maskedSegLower,
//								maskedSegUpper,
//								false,
//								i,
//								currentPrefix,
//								creator);
//						}
//						if(doRangeBoundaries) {
//							boolean isRange = maskedSegLower != maskedSegUpper;
//							if(!doAddress || isRange) {
//								if(doAddress) {
//									lowerSegments = allocateSegments(lowerSegments, segments, creator, ipv4SegmentCount, normalizedSegmentIndex);
//								} // else segments already allocated
//								lowerSegments[normalizedSegmentIndex] = createSegment(
//										addressString,
//										IPVersion.IPV4,
//										maskedSegLower,
//										maskedSegLower,
//										false,
//										i,
//										currentPrefix,
//										creator);
//							} else if(lowerSegments != null) {
//								lowerSegments[normalizedSegmentIndex] = segments[normalizedSegmentIndex];
//							}
//							if(withUpper) {
//								if(isRange) {
//									upperSegments = allocateSegments(upperSegments, lowerSegments, creator, ipv4SegmentCount, normalizedSegmentIndex);
//									upperSegments[normalizedSegmentIndex] = createSegment(
//											addressString,
//											IPVersion.IPV4,
//											maskedSegUpper,
//											maskedSegUpper,
//											false,
//											i,
//											currentPrefix,
//											creator);
//								} else if(upperSegments != null) {
//									upperSegments[normalizedSegmentIndex] = lowerSegments[normalizedSegmentIndex];
//								}
//							}
//						}
//						++normalizedSegmentIndex;
//						count--;
//					}
//					addrParseData.setBitLength(i, bits);
//					continue;
//				} //end handle inet_aton joined segments
//			}
//			long hostLower = lower, hostUpper = upper;
//			Masker masker = null;
//			boolean unmasked = true;
//			if(hasMask) {
//				masker = maskers[i];
//				Integer segmentMask = cacheSegmentMask(mask.getSegment(normalizedSegmentIndex).getSegmentValue());
//				int maskInt = segmentMask.intValue();
//				if(masker == null) {
//					maskers[i] = masker = maskRange(lower, upper, maskInt, creator.getMaxValuePerSegment());
//					if(!masker.isSequential() && finalResult.maskException == null) {
//						finalResult.maskException = new IncompatibleAddressException(lower, upper, maskInt, "ipaddress.error.maskMismatch");
//					}
//				}
//				lower = (int) masker.getMaskedLower(lower, maskInt);
//				upper = (int) masker.getMaskedUpper(upper, maskInt);
//				unmasked = hostLower == lower && hostUpper == upper;
//				maskedIsDifferent = maskedIsDifferent || !unmasked;
//			}
//			Integer segmentPrefixLength = getSegmentPrefixLength(normalizedSegmentIndex, IPv4Address.BITS_PER_SEGMENT, qualifier);
//			if(doAddress) {
//				if(maskedIsDifferent || segmentPrefixLength != null) {
//					hostSegments = allocateSegments(hostSegments, segments, creator, ipv4SegmentCount, normalizedSegmentIndex);
//					hostSegments[normalizedSegmentIndex] = createSegment(
//							addressString,
//							IPVersion.IPV4,
//							(int) hostLower,
//							(int) hostUpper,
//							true,
//							i,
//							null,
//							creator);
//				}
//				segments[normalizedSegmentIndex] = createSegment(
//						addressString,
//						IPVersion.IPV4,
//						(int) lower,
//						(int) upper,
//						unmasked,
//						i,
//						segmentPrefixLength,
//						creator);
//			}
//			if(doRangeBoundaries) {
//				boolean isRange = lower != upper;
//				if(!doAddress || isRange) {
//					if(doAddress) {
//						lowerSegments = allocateSegments(lowerSegments, segments, creator, ipv4SegmentCount, normalizedSegmentIndex);
//					} // else segments already allocated
//					lowerSegments[normalizedSegmentIndex] = createSegment(
//							addressString,
//							IPVersion.IPV4,
//							(int) lower,
//							(int) lower,
//							false,
//							i,
//							segmentPrefixLength,
//							creator);
//				} else if(lowerSegments != null) {
//					lowerSegments[normalizedSegmentIndex] = segments[normalizedSegmentIndex];
//				}
//				if(withUpper) {
//					if(isRange) {
//						upperSegments = allocateSegments(upperSegments, lowerSegments, creator, ipv4SegmentCount, normalizedSegmentIndex);
//						upperSegments[normalizedSegmentIndex] = createSegment(
//								addressString,
//								IPVersion.IPV4,
//								(int) upper,
//								(int) upper,
//								false,
//								i,
//								segmentPrefixLength,
//								creator);
//					} else if(upperSegments != null) {
//						upperSegments[normalizedSegmentIndex] = lowerSegments[normalizedSegmentIndex];
//					}
//				}
//			}
//			normalizedSegmentIndex++;
//			addrParseData.setBitLength(i, IPv4Address.BITS_PER_SEGMENT);
//		}
//		ParsedAddressCreator<IPv4Address, IPv4AddressSection, ?, IPv4AddressSegment> addressCreator = creator;
//		Integer prefLength = getPrefixLength(qualifier);
//		IPv4AddressSection result, hostResult = null;
//		if(doAddress) {
//			finalResult.section = result = addressCreator.createPrefixedSectionInternal(segments, prefLength);
//			if(hostSegments != null) {
//				finalResult.hostSection = hostResult = addressCreator.createSectionInternal(hostSegments);
//				if(checkExpandedValues(hostResult, expandedStart, expandedEnd)) {
//					finalResult.joinHostException = new IncompatibleAddressException(addressString, "ipaddress.error.invalid.joined.ranges");
//				}
//			}
//
//			if(checkExpandedValues(result, expandedStart, expandedEnd)) {
//				finalResult.joinAddressException = new IncompatibleAddressException(addressString, "ipaddress.error.invalid.joined.ranges");
//				if(hostResult == null) {
//					finalResult.joinHostException = finalResult.joinAddressException;
//				}
//			}
//		}
//		if(doRangeBoundaries) {
//			// if we have a prefix subnet, it is possible our lower and upper boundaries exceed what appears in the parsed address
//			Integer prefixLength = getPrefixLength(qualifier);
//			boolean isPrefixSubnet;
//			if(prefixLength != null) {
//				IPAddressNetwork<?, ?, ?, ?, ?> network = getParameters().getIPv4Parameters().getNetwork();
//				IPv4AddressSegment[] lowerSegs, upperSegs;
//				if(doAddress) {
//					lowerSegs = upperSegs = segments;
//				} else {
//					lowerSegs = lowerSegments;
//					upperSegs = (upperSegments == null) ? lowerSegments : upperSegments;
//				}
//				isPrefixSubnet = ParsedAddressGrouping.isPrefixSubnet(
//						segmentIndex -> lowerSegs[segmentIndex].getSegmentValue(),
//						segmentIndex -> upperSegs[segmentIndex].getUpperSegmentValue(),
//						lowerSegs.length,
//						IPv4Address.BYTES_PER_SEGMENT,
//						IPv4Address.BITS_PER_SEGMENT,
//						IPv4Address.MAX_VALUE_PER_SEGMENT,
//						prefixLength,
//						network.getPrefixConfiguration(),
//						false);
//				if(isPrefixSubnet) {
//					if(lowerSegments == null) {
//						//allocate lower segments from address segments
//						lowerSegments = allocateSegments(lowerSegments, segments, creator, ipv4SegmentCount, ipv4SegmentCount);
//					}
//					if(upperSegments == null) {
//						//allocate upper segments from lower segments
//						upperSegments = allocateSegments(upperSegments, lowerSegments, creator, ipv4SegmentCount, ipv4SegmentCount);
//					}
//				}
//			} else {
//				isPrefixSubnet = false;
//			}
//			if(lowerSegments != null) {
//				finalResult.lowerSection = addressCreator.createPrefixedSectionInternal(lowerSegments, prefLength, true).getLower();
//			}
//			if(upperSegments != null) {
//				IPv4AddressSection section = addressCreator.createPrefixedSectionInternal(upperSegments, prefLength);
//				if(isPrefixSubnet) {
//					section = section.toPrefixBlock();
//				}
//				finalResult.upperSection = section.getUpper();
//			}
//		}
//	}

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
			useFlags, parseData.getAddressParseData(), parsedSegIndex,
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
	item IPv4AddressSeqRange,
	upperRangeLower,
	upperRangeUpper,
	lowerRangeLower,
	lowerRangeUpper SegInt,
	segmentPrefixLength PrefixLen,
	creator IPv6AddressCreator) *AddressDivision {
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
	creator ParsedAddressCreator) *AddressDivision {
	hasMask := (mask != nil)
	if hasMask {
		//maskInt := *mask
		// TODO masking
		//Masker masker = maskRange(stringLower, stringUpper, maskInt, creator.getMaxValuePerSegment());
		//if(!masker.isSequential()) {
		//	throw new IncompatibleAddressException(stringLower, stringUpper, maskInt, "ipaddress.error.maskMismatch");
		//}
		//stringLower = (int) masker.getMaskedLower(stringLower, maskInt);
		//stringUpper = (int) masker.getMaskedUpper(stringUpper, maskInt);
	}
	result := createRangeSeg("", version, stringLower, stringUpper,
		false, nil, parsedSegIndex, segmentPrefixLength, creator)
	return result
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

type Masker interface {
	// GetMaskedLower provides the lowest masked value, which is not necessarily the lowest value masked
	GetMaskedLower(value, maskValue DivInt) DivInt

	// GetMaskedUpper provides the highest masked value, which is not necessarily the highest value masked
	GetMaskedUpper(upperValue, maskValue DivInt) DivInt

	// IsSequential returns whether masking all values in the range results in a sequential set of values
	IsSequential() bool
}

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

//TODO the remaining maskers, which is not so hard.  All of them have a nested maskerBase.  They can also all have pointer receivers if you want.

var _ Masker = maskerBase{}
