package ipaddr

import (
	"sync"
	"sync/atomic"
	"unsafe"
)

type ParsedMACAddress struct {
	macAddressParseData

	originator   *MACAddressString
	address      *MACAddress
	creationLock sync.Mutex
}

//func (parseData *ParsedMACAddress) getMACAddressCreator() parsedAddressCreator {
//	return parseData.originator.GetValidationOptions().GetNetwork().GetMACAddressCreator()
//}

func (parseData *ParsedMACAddress) getMACAddressParseData() *macAddressParseData {
	return &parseData.macAddressParseData
}

func (parseData *ParsedMACAddress) getAddress() (*MACAddress, IncompatibleAddressError) {
	addr := parseData.address
	if addr == nil {
		parseData.creationLock.Lock()
		addr = parseData.address
		if addr == nil {
			var err IncompatibleAddressError
			addr, err = parseData.createAddress()
			if err != nil {
				return nil, err
			}
			parseData.segmentData = nil // no longer needed
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&parseData.address))
			atomic.StorePointer(dataLoc, unsafe.Pointer(addr))
		}
		parseData.creationLock.Unlock()
	}
	return addr, nil
}

func (parseData *ParsedMACAddress) createAddress() (*MACAddress, IncompatibleAddressError) {
	creator := macType.getNetwork().getAddressCreator()
	sect, err := parseData.createSection()
	if err != nil {
		return nil, err
	}
	return creator.createAddressInternal(sect.ToAddressSection(), parseData.originator).ToMACAddress(), nil
	//return NewMACAddressInternal(parseData.createSection(), parseData.originator)
	//parsedAddressCreator<? extends MACAddress, MACAddressSection, ?, ?> creator = getMACAddressCreator();
	//return creator.createAddressInternal(createSection(), originator);
}

func (parseData *ParsedMACAddress) createSection() (*MACAddressSection, IncompatibleAddressError) {
	addressString := parseData.str
	addressParseData := parseData.getAddressParseData()
	actualInitialSegmentCount := addressParseData.getSegmentCount()
	creator := macType.getNetwork().getAddressCreator()
	//creator := parseData.getMACAddressCreator()
	format := parseData.getFormat()
	var finalSegmentCount, initialSegmentCount int
	if format == nil {
		if parseData.isExtended() {
			initialSegmentCount = ExtendedUniqueIdentifier64SegmentCount
		} else {
			initialSegmentCount = MediaAccessControlSegmentCount
		}
		finalSegmentCount = initialSegmentCount
	} else if format == dotted {
		if parseData.isExtended() {
			initialSegmentCount = MediaAccessControlDotted64SegmentCount
		} else {
			initialSegmentCount = MediaAccessControlDottedSegmentCount
		}
		if actualInitialSegmentCount <= MediaAccessControlDottedSegmentCount && !parseData.isExtended() {
			finalSegmentCount = MediaAccessControlSegmentCount
		} else {
			finalSegmentCount = ExtendedUniqueIdentifier64SegmentCount
		}
	} else {
		if addressParseData.isSingleSegment() || parseData.isDoubleSegment() {
			if parseData.isExtended() {
				finalSegmentCount = ExtendedUniqueIdentifier64SegmentCount
			} else {
				finalSegmentCount = MediaAccessControlSegmentCount
			}
		} else if actualInitialSegmentCount <= MediaAccessControlSegmentCount && !parseData.isExtended() {
			finalSegmentCount = MediaAccessControlSegmentCount
		} else {
			finalSegmentCount = ExtendedUniqueIdentifier64SegmentCount
		}
		initialSegmentCount = finalSegmentCount
	}
	missingCount := initialSegmentCount - actualInitialSegmentCount
	expandedSegments := (missingCount <= 0)
	segments := make([]*AddressDivision, finalSegmentCount)
	for i, normalizedSegmentIndex := 0, 0; i < actualInitialSegmentCount; i++ {
		lower := addressParseData.getValue(i, keyLower)
		upper := addressParseData.getValue(i, keyUpper)
		if format == dotted { //aaa.bbb.ccc.ddd
			//aabb is becoming aa.bb
			segLower := SegInt(lower)
			segUpper := SegInt(upper)
			lowerHalfLower := segLower >> 8
			lowerHalfUpper := segUpper >> 8
			adjustedLower2 := segLower & 0xff
			adjustedUpper2 := segUpper & 0xff
			if lowerHalfLower != lowerHalfUpper && adjustedUpper2-adjustedLower2 != 0xff {
				return nil, &incompatibleAddressError{addressError{str: addressString, key: "ipaddress.error.invalid.joined.ranges"}}
			}
			segments[normalizedSegmentIndex] = createSegment(
				addressString,
				lowerHalfLower,
				lowerHalfUpper,
				false,
				addressParseData,
				i,
				creator)
			normalizedSegmentIndex++
			segments[normalizedSegmentIndex] = createSegment(
				addressString,
				adjustedLower2,
				adjustedUpper2,
				false,
				addressParseData,
				i,
				creator)
		} else {
			if addressParseData.isSingleSegment() || parseData.isDoubleSegment() {
				useStringIndicators := true
				var count int
				if i == actualInitialSegmentCount-1 {
					count = missingCount
				} else {
					count = MACOrganizationalUniqueIdentifierSegmentCount - 1
				}
				missingCount -= count
				isRange := lower != upper
				previousAdjustedWasRange := false
				for count >= 0 { //add the missing segments
					var newLower, newUpper uint64
					if isRange {
						segmentMask := uint64(MACMaxValuePerSegment)
						shift := uint64(count) << macBitsToSegmentBitshift
						newLower = (lower >> shift) & segmentMask
						newUpper = (upper >> shift) & segmentMask
						if previousAdjustedWasRange && newUpper-newLower != MACMaxValuePerSegment {
							//any range extending into upper segments must have full range in lower segments
							//otherwise there is no way for us to represent the address
							//so we need to check whether the lower parts cover the full range
							//eg cannot represent 0.0.0x100-0x10f or 0.0.1-1ff, but can do 0.0.0x100-0x1ff or 0.0.0-1ff
							return nil, &incompatibleAddressError{addressError{str: addressString, key: "ipaddress.error.invalid.joined.ranges"}}
						}
						previousAdjustedWasRange = newLower != newUpper

						//we may be able to reuse our strings on the final segment
						//for previous segments, strings can be reused only when the value is 0, which we do not need to cacheBitCountx.  Any other value changes when shifted.
						if count == 0 && newLower == lower {
							if newUpper != upper {
								addressParseData.unsetFlag(i, keyStandardRangeStr)
								//segFlags[addressParseData.STANDARD_RANGE_STR_INDEX] = false;
							}
						} else {
							useStringIndicators = false
						}
					} else {
						newLower = (lower >> uint(count<<3)) & MACMaxValuePerSegment
						newUpper = newLower
						if count != 0 || newLower != lower {
							useStringIndicators = false
						}
					}
					segments[normalizedSegmentIndex] = createSegment(
						addressString,
						SegInt(newLower),
						SegInt(newUpper),
						useStringIndicators,
						addressParseData,
						i,
						creator)
					normalizedSegmentIndex++
					count--
				}
				continue
			} //end joined segments
			segments[normalizedSegmentIndex] = createSegment(
				addressString,
				SegInt(lower),
				SegInt(upper),
				true,
				addressParseData,
				i,
				creator)
		}
		if !expandedSegments {
			//check for any missing segments that we should account for here
			if addressParseData.isWildcard(i) {
				expandSegments := true
				for j := i + 1; j < actualInitialSegmentCount; j++ {
					if addressParseData.isWildcard(j) { //another wildcard further down
						expandSegments = false
						break
					}
				}
				if expandSegments {
					expandedSegments = true
					count := missingCount
					for ; count > 0; count-- { //add the missing segments
						if format == dotted {
							seg := createSegment(
								addressString,
								0,
								MACMaxValuePerSegment,
								false,
								addressParseData,
								i,
								creator)
							normalizedSegmentIndex++
							segments[normalizedSegmentIndex] = seg
							normalizedSegmentIndex++
							segments[normalizedSegmentIndex] = seg
						} else {
							normalizedSegmentIndex++
							segments[normalizedSegmentIndex] = createSegment(
								addressString,
								0,
								MACMaxValuePerSegment,
								false,
								addressParseData,
								i,
								creator)
						}
					}
				}
			}
		}
		normalizedSegmentIndex++
	}
	////		parsedAddressCreator<?, MACAddressSection, ?, MACAddressSegment> addressCreator = creator;
	return creator.createSectionInternal(segments).ToMACAddressSection(), nil
	//		MACAddressSection result = addressCreator.createSectionInternal(segments);
	//		return result;
}

func createSegment(
	addressString string,
	val,
	upperVal SegInt,
	useFlags bool,
	parseData *addressParseData,
	parsedSegIndex int,
	creator parsedAddressCreator) *AddressDivision {
	if val != upperVal {
		return createRangeSegment(addressString, val, upperVal, useFlags, parseData, parsedSegIndex, creator)
	}
	var result *AddressDivision
	if !useFlags {
		result = creator.createSegment(val, val, nil)
	} else {
		result = creator.createSegmentInternal(
			val,
			nil, //prefix length
			addressString,
			val,
			parseData.getFlag(parsedSegIndex, keyStandardStr),
			parseData.getIndex(parsedSegIndex, keyLowerStrStartIndex),
			parseData.getIndex(parsedSegIndex, keyLowerStrEndIndex))
	}
	return result
}

func createRangeSegment(
	addressString string,
	lower,
	upper SegInt,
	useFlags bool,
	parseData *addressParseData,
	parsedSegIndex int,
	creator parsedAddressCreator) *AddressDivision {
	var result *AddressDivision
	if !useFlags {
		result = creator.createSegment(lower, upper, nil)
	} else {
		result = creator.createRangeSegmentInternal(
			lower,
			upper,
			nil, //prefix length
			addressString,
			lower,
			upper,
			parseData.getFlag(parsedSegIndex, keyStandardStr),
			parseData.getFlag(parsedSegIndex, keyStandardRangeStr),
			parseData.getIndex(parsedSegIndex, keyLowerStrStartIndex),
			parseData.getIndex(parsedSegIndex, keyLowerStrEndIndex),
			parseData.getIndex(parsedSegIndex, keyUpperStrEndIndex))
	}
	return result
}
