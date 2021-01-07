package ipaddr

import (
	"fmt"
	"unsafe"
)

//
//
//
//
type ipAddressSectionInternal struct {
	addressSectionInternal
}

func (section *ipAddressSectionInternal) GetSegment(index int) *IPAddressSegment {
	return section.GetDivision(index).ToIPAddressSegment()
}

func (section *ipAddressSectionInternal) GetIPVersion() IPVersion {
	if section.matchesIPv4Section() {
		return IPv4
	}
	return IPv6
}

func (section *ipAddressSectionInternal) GetNetworkPrefixLength() PrefixLen {
	return section.prefixLength
}

func (section *ipAddressSectionInternal) GetBlockMaskPrefixLength(network bool) PrefixLen {
	// TODO GetBlockMaskPrefixLength is needed for address creation amongst other things
	return nil
}

func (section *ipAddressSectionInternal) ToAddressSection() *AddressSection {
	return (*AddressSection)(unsafe.Pointer(section))
}

// error returned for nil sements, or inconsistent prefixes
func (section *ipAddressSectionInternal) init(bitsPerSegment BitCount) error {
	var previousSegmentPrefix PrefixLen
	segCount := section.GetSegmentCount()
	isMultiple := false
	for i := 0; i < segCount; i++ {
		div := section.GetDivision(i)
		if div == nil {
			//TODO throw new NullPointerException(getMessage("ipaddress.error.null.segment"));
			return &addressException{"ipaddress.error.null.segment"}
		}
		//else if section.GetDivision(i).GetBitCount() != bitsPerSegment { // unnecessary since we can control the division type
		//	return &addressException{"ipaddress.error.mismatched.bit.size"}
		//}
		segment := section.GetSegment(i)

		//Across an address prefixes are:
		//IPv6: (null):...:(null):(1 to 16):(0):...:(0)
		//or IPv4: ...(null).(1 to 8).(0)...
		segPrefix := segment.GetSegmentPrefixLength()
		if !isMultiple && segment.isMultiple() {
			isMultiple = true
			section.isMultiple = true
		}
		if previousSegmentPrefix == nil {
			if segPrefix != nil {
				section.prefixLength = getNetworkPrefixLength(bitsPerSegment, *segPrefix, i)
				//break
			}
		} else if segPrefix == nil || *segPrefix != 0 {
			//return &inconsistentPrefixException(segments[i-1], segment, segPrefix)
			return &inconsistentPrefixException{str: fmt.Sprintf("%v %v %v", section.GetSegment(i-1), segment, segPrefix), key: "ipaddress.error.inconsistent.prefixes"}
		}
		previousSegmentPrefix = segPrefix
	}
	//if(previousSegmentPrefix == nil) { no need for this now since prefix length always set
	//	cachedPrefixLength = NO_PREFIX_LENGTH;
	//}
	return nil
}

//func createIPSection(segments []*AddressDivision, prefixLength PrefixLen, addrType addrType, startIndex uint8, isMultiple bool) *IPAddressSection {
//	return &IPAddressSection{
//		ipAddressSectionInternal{
//			addressSectionInternal{
//				addressDivisionGroupingInternal{
//					divisions:           segments,
//					prefixLength:        prefixLength,
//					addrType:            addrType,
//					addressSegmentIndex: startIndex,
//					isMultiple:          isMultiple,
//					cache:               &valueCache{},
//				},
//			},
//		},
//	}
//}

//
//
//
// An IPAddress section has segments, which are divisions of equal length and size
type IPAddressSection struct {
	ipAddressSectionInternal
}

func (section *IPAddressSection) IsIPv4() bool {
	return section != nil && section.matchesIPv4Section()
}

func (section *IPAddressSection) IsIPv6() bool {
	return section != nil && section.matchesIPv6Section()
}

func (section *IPAddressSection) GetLower() *IPAddressSection {
	return section.ToAddressSection().GetLower().ToIPAddressSection()
}

func (section *IPAddressSection) GetUpper() *IPAddressSection {
	return section.ToAddressSection().GetUpper().ToIPAddressSection()
}

func (section *IPAddressSection) ToPrefixBlock() *IPAddressSection {
	return section.ToAddressSection().ToPrefixBlock().ToIPAddressSection()
}

func (section *IPAddressSection) ToPrefixBlockLen(prefLen BitCount) *IPAddressSection {
	return section.ToAddressSection().toPrefixBlockLen(prefLen).ToIPAddressSection()
	//xxx
	//bitCount := section.GetBitCount()
	//if prefLen < 0 {
	//	prefLen = 0
	//} else {
	//	if prefLen > bitCount {
	//		prefLen = bitCount
	//	}
	//}
	//segCount := section.GetSegmentCount()
	//if segCount == 0 {
	//	return section
	//}
	//segmentByteCount := section.GetBytesPerSegment()
	//segmentBitCount := section.GetBitsPerSegment()
	//prefixedSegmentIndex := getHostSegmentIndex(prefLen, segmentByteCount, segmentBitCount)
	//if prefixedSegmentIndex >= segCount {
	//	if prefLen == bitCount {
	//		last := section.GetSegment(segCount - 1)
	//		segPrefLength := last.GetSegmentPrefixLength()
	//		if segPrefLength != nil && *segPrefLength == segmentBitCount {
	//			return section
	//		}
	//	} else { // prefLen > bitCount
	//		return section
	//	}
	//} else {
	//	segPrefLength := *getPrefixedSegmentPrefixLength(segmentBitCount, prefLen, prefixedSegmentIndex)
	//	seg := section.GetSegment(prefixedSegmentIndex)
	//	segPref := seg.GetSegmentPrefixLength()
	//	if segPref != nil && *segPref == segPrefLength && seg.ContainsPrefixBlock(segPrefLength) {
	//		i := prefixedSegmentIndex + 1
	//		for ; i < segCount; i++ {
	//			seg = section.GetSegment(i)
	//			if !seg.IsFullRange() {
	//				break
	//			}
	//		}
	//		if i == segCount {
	//			return section
	//		}
	//	}
	//}
	//newSegs := createSegmentArray(segCount)
	//if prefLen > 0 {
	//	prefixedSegmentIndex = getNetworkSegmentIndex(prefLen, segmentByteCount, segmentBitCount)
	//	copy(newSegs, section.divisions[:prefixedSegmentIndex])
	//} else {
	//	prefixedSegmentIndex = 0
	//}
	//for i := prefixedSegmentIndex; i < segCount; i++ {
	//	segPrefLength := getPrefixedSegmentPrefixLength(segmentBitCount, prefLen, i)
	//	oldSeg := section.divisions[i]
	//	newSegs[i] = oldSeg.ToIPAddressSegment().ToPrefixedNetworkSegment(segPrefLength).ToAddressDivision()
	//}
	//return createIPSection(newSegs, &prefLen, section.addrType, section.addressSegmentIndex, section.isMultiple || prefLen < bitCount)
}

func (section *IPAddressSection) ToIPv6AddressSection() *IPv6AddressSection {
	if section == nil {
		return nil
	} else if section.matchesIPv6Section() {
		return (*IPv6AddressSection)(unsafe.Pointer(section))
	}
	return nil
}

func (section *IPAddressSection) ToIPv4AddressSection() *IPv4AddressSection {
	if section == nil {
		return nil
	} else if section.matchesIPv4Section() {
		return (*IPv4AddressSection)(unsafe.Pointer(section))
	}
	return nil
}

func BitsPerSegment(version IPVersion) BitCount {
	if version == IPv4 {
		return IPv4BitsPerSegment
	}
	return IPv6BitsPerSegment
}

func assignPrefix(prefixLength PrefixLen, segments []*AddressDivision, res *IPAddressSection, singleOnly bool, boundaryBits, maxBits BitCount) {
	//if prefixLength != nil {
	prefLen := *prefixLength
	if prefLen < 0 {
		prefLen = 0
		//return &prefixLenException{prefixLen: prefLen, key: "ipaddress.error.prefixSize"}
		//throw new PrefixLenException(networkPrefixLength);
	} else if prefLen > boundaryBits {
		//if prefLen > maxBits {
		//	return &prefixLenException{prefixLen: prefLen, key: "ipaddress.error.prefixSize"}
		//	//throw new PrefixLenException(networkPrefixLength);
		//}
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
			res.divisions,
			res.GetBitsPerSegment(),
			res.GetBytesPerSegment(),
			segProducer)
		if applyPrefixSubnet && !res.isMultiple {
			res.isMultiple = res.GetSegment(segLen - 1).isMultiple()
		}
	}
	res.prefixLength = prefixLength
	//} // else prefixLength has already been set to the proper value
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
	//SegmentValueProvider func(segmentIndex int) SegInt
	return isPrefixSubnet(
		func(segmentIndex int) SegInt {
			return sectionSegments[segmentIndex].ToAddressSegment().GetSegmentValue()
		},
		func(segmentIndex int) SegInt {
			return sectionSegments[segmentIndex].ToAddressSegment().GetUpperSegmentValue()
		},
		//segmentIndex -> sectionSegments[segmentIndex].getSegmentValue(),
		//segmentIndex -> sectionSegments[segmentIndex].getUpperSegmentValue(),
		segmentCount,
		seg.GetByteCount(),
		seg.GetBitCount(),
		seg.ToAddressSegment().GetMaxSegmentValue(),
		//SegInt(seg.GetMaxValue()),
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
			segments[networkSegmentIndex] = segmentCreator(segment.GetSegmentValue(), segment.GetUpperSegmentValue(), cacheBitcount(segmentBitCount))
		}
	}
}

func toSegments(
	bytes []byte,
	segmentCount int,
	bytesPerSegment int,
	bitsPerSegment BitCount,
	creator AddressSegmentCreator,
	prefixLength PrefixLen) (segments []*AddressDivision, err AddressValueException) {
	//int segmentCount = segments.length;
	expectedByteCount := segmentCount * bytesPerSegment

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
		//endIndex := byteLen - 1
		expectedStartIndex := byteLen - expectedByteCount
		higherStartIndex := expectedStartIndex - 1
		expectedExtendedValue := bytes[higherStartIndex]
		if expectedExtendedValue != 0 {
			mostSignificantBit := bytes[expectedStartIndex] >> 7
			if mostSignificantBit != 0 {
				if expectedExtendedValue != 0xff { //0xff or -1
					err = &addressValueException{key: "ipaddress.error.exceeds.size", val: int(expectedExtendedValue)}
					return
				}
			} else {
				err = &addressValueException{key: "ipaddress.error.exceeds.size", val: int(expectedExtendedValue)}
				return
			}
		}
		for startIndex < higherStartIndex {
			higherStartIndex--
			if bytes[higherStartIndex] != expectedExtendedValue {
				err = &addressValueException{key: "ipaddress.error.exceeds.size", val: int(expectedExtendedValue)}
				return
			}
		}
		startIndex = expectedStartIndex
		missingBytes = 0
	}
	segments = createSegmentArray(segmentCount)
	//boolean allPrefixedAddressesAreSubnets = network.getPrefixConfiguration().allPrefixedAddressesAreSubnets();
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

func createSegments(
	//S segments[],
	lowerValueProvider,
	upperValueProvider SegmentValueProvider,
	segmentCount int,
	bytesPerSegment int,
	bitsPerSegment BitCount,
	creator AddressSegmentCreator,
	prefixLength PrefixLen) (segments []*AddressDivision, isMultiple bool) {
	//int bytesPerSegment,
	//int bitsPerSegment,
	////AddressNetwork<S> network,
	//Integer prefixLength) {
	//AddressSegmentCreator<S> creator = network.getAddressCreator();
	//int segmentCount = segments.length;
	segments = createSegmentArray(segmentCount)
	//isMultiple := false
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
