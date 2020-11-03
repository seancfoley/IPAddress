package ipaddr

import (
	"math"
	"strings"
)

var extendedDigits = []uint64{ //TODO soon change to bytes, it makes more sense to convert to a uint64 in the code than to retrieve more from memory
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B',
	'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
	'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
	'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
	'y', 'z', '!', '#', '$', '%', '&', '(', ')', '*', '+', '-',
	';', '<', '=', '>', '?', '@', '^', '_', '`', '{', '|', '}',
	'~'}

var chars [int('z') + 1]uint64         //TODO change to bytes, it makes more sense to convert to a uint64 in the code
var extendedChars [int('~') + 1]uint64 //TODO change to bytes

func init() {
	i := uint64(0)
	for c := '0'; i < 10; i, c = i+1, c+1 {
		chars[c] = i
	}
	for c, c2 := 'a', 'A'; i < 26; i, c, c2 = i+1, c+1, c2+1 {
		chars[c] = i
		chars[c2] = i
	}
	extLen := uint64(len(extendedDigits))
	for i = 0; i < extLen; i++ {
		c := extendedDigits[i]
		extendedChars[c] = i
	}
}

//var PREFIX_CACHE [IPv6BitCount + 1]*ParsedHostIdentifierStringQualifier //TODO rename

// Interface for validation and parsing of host identifier strings
type HostIdentifierStringValidator interface {

	//public static final int MAX_PREFIX = IPv6Address.BIT_COUNT;//the largest allowed value x for a /x prefix following an address or host name
	//public static final int MAX_PREFIX_CHARS = Integer.toString(MAX_PREFIX).length();
	//public static final String SMTP_IPV6_IDENTIFIER = "IPv6:";
	//public static final char IPvFUTURE= 'v';

	//validateHost(fromHost HostName ) ParsedHost, HostNameException;

	//validateIPAddress(fromString IPAddressString) (IPAddressProvider, AddressStringException)

	//validateMACAddress(fromString MACAddressString) (MACAddressProvider, AddressStringException)

	validatePrefix(fullAddr string, version IPVersion) (int, AddressStringException)
}

// TODO get parsing addresses working up to creating ParsedIPAddress nad ParsedHost.
// Then fix up the mask stuff that I may have skipped.  Then move to host parsing, which needs all the address stuff working.
// At that point you can move towards address creation

const ( //TODO rename not public
	LONG_SIZE                               = 64
	MAX_HOST_LENGTH                         = 253
	MAX_HOST_SEGMENTS                       = 127
	MAX_LABEL_LENGTH                        = 63
	MAC_DOUBLE_SEGMENT_DIGIT_COUNT          = 6
	MAC_EXTENDED_DOUBLE_SEGMENT_DIGIT_COUNT = 10
	MAC_SINGLE_SEGMENT_DIGIT_COUNT          = 12
	MAC_EXTENDED_SINGLE_SEGMENT_DIGIT_COUNT = 16
	IPV6_SINGLE_SEGMENT_DIGIT_COUNT         = 32
	IPV6_BINARY_SINGLE_SEGMENT_DIGIT_COUNT  = 128
	IPV4_BINARY_SINGLE_SEGMENT_DIGIT_COUNT  = 32
	IPV6_BASE85_SINGLE_SEGMENT_DIGIT_COUNT  = 20
	MAX_WILDCARDS                           = IPV6_BASE85_SINGLE_SEGMENT_DIGIT_COUNT - 1 // 20 wildcards is equivalent to a base 85 address
	IPV4_SINGLE_SEGMENT_OCTAL_DIGIT_COUNT   = 11
	LONG_HEX_DIGITS                         = LONG_SIZE >> 2
	LONG_BINARY_DIGITS                      = LONG_SIZE
)

var (
	macMaxTriple uint64 = (MACMaxValuePerSegment << (MACBitsPerSegment * 2)) |
		(MACMaxValuePerSegment << MACBitsPerSegment) | MACMaxValuePerSegment
	macMaxQuintuple uint64 = (macMaxTriple << (MACBitsPerSegment * 2)) | (macMaxTriple >> MACBitsPerSegment)
)

func isSingleSegmentIPv6(
	str string,
	totalDigits int,
	isRange bool,
	frontTotalDigits int,
	ipv6SpecificOptions IPv6AddressStringParameters) (isSingle bool, err AddressStringException) {
	backIsIpv6 := totalDigits == IPV6_SINGLE_SEGMENT_DIGIT_COUNT || // 32 hex chars with or without 0x
		(ipv6SpecificOptions.AllowsBinary() && totalDigits == IPV6_BINARY_SINGLE_SEGMENT_DIGIT_COUNT+2) || // 128 binary chars with 0b
		(isRange && totalDigits == 0 && (frontTotalDigits == IPV6_SINGLE_SEGMENT_DIGIT_COUNT ||
			(ipv6SpecificOptions.AllowsBinary() && frontTotalDigits == IPV6_BINARY_SINGLE_SEGMENT_DIGIT_COUNT+2)))
	if backIsIpv6 && isRange && totalDigits != 0 {
		frontIsIpv6 := frontTotalDigits == IPV6_SINGLE_SEGMENT_DIGIT_COUNT ||
			(ipv6SpecificOptions.AllowsBinary() && frontTotalDigits == IPV6_BINARY_SINGLE_SEGMENT_DIGIT_COUNT+2) ||
			frontTotalDigits == 0
		if !frontIsIpv6 {
			err = &addressStringException{str: str, key: "ipaddress.error.too.few.segments.digit.count"}
			return
		}
	}
	isSingle = backIsIpv6
	return
}

// When checking for binary single segment, we must check for the exact number of digits for IPv4.
// This is because of ambiguity between IPv6 hex 32 chars starting with 0b and 0b before 30 binary chars.
// So we must therefore avoid 0b before 30 binary chars for IPv4.  We must require 0b before 32 binary chars.
// This only applies to single-segment.
// For segmented IPv4, there is no ambiguity and we allow binary segments of varying lengths,
// just like we do for inet_aton.

func isSingleSegmentIPv4(
	str string,
	nonZeroDigits,
	totalDigits int,
	isRange bool,
	frontNonZeroDigits,
	frontTotalDigits int,
	ipv4SpecificOptions IPv4AddressStringParameters) (isSingle bool, err AddressStringException) {
	backIsIpv4 := nonZeroDigits <= IPV4_SINGLE_SEGMENT_OCTAL_DIGIT_COUNT ||
		(ipv4SpecificOptions.AllowsBinary() && totalDigits == IPV4_BINARY_SINGLE_SEGMENT_DIGIT_COUNT+2) ||
		(isRange && totalDigits == 0 && (frontTotalDigits <= IPV4_SINGLE_SEGMENT_OCTAL_DIGIT_COUNT ||
			(ipv4SpecificOptions.AllowsBinary() && frontTotalDigits == IPV4_BINARY_SINGLE_SEGMENT_DIGIT_COUNT+2)))
	if backIsIpv4 && isRange && totalDigits != 0 {
		frontIsIpv4 := frontNonZeroDigits <= IPV4_SINGLE_SEGMENT_OCTAL_DIGIT_COUNT ||
			(ipv4SpecificOptions.AllowsBinary() && frontTotalDigits == IPV4_BINARY_SINGLE_SEGMENT_DIGIT_COUNT+2) ||
			frontTotalDigits == 0
		if !frontIsIpv4 {
			err = &addressStringException{str: str, key: "ipaddress.error.too.few.segments.digit.count"}
			return
		}
	}
	isSingle = backIsIpv4
	return
}

func validateIPAddressString(fromString *IPAddressString) (prov IPAddressProvider, err AddressStringException) {
	str := fromString.str
	validationOptions := fromString.getParams()
	pa := ParsedIPAddress{
		originator:         fromString,
		options:            validationOptions,
		IPAddressParseData: IPAddressParseData{AddressParseData: AddressParseData{str: str}},
	}
	validateIPAddress(validationOptions, str, 0, len(str), pa.getIPAddressParseData(), false)
	err = parseAddressQualifier(str, validationOptions, nil, pa.getIPAddressParseData(), len(str))
	if err != nil {
		return
	}
	return chooseIPAddressProvider(fromString, str, validationOptions, &pa)
}

func validateMACAddressString(fromString *MACAddressString) (MACAddressProvider, AddressStringException) {
	str := fromString.str
	validationOptions := fromString.getParams()
	pa := ParsedMACAddress{
		originator:          fromString,
		MACAddressParseData: MACAddressParseData{AddressParseData: AddressParseData{str: str}},
	}
	addressParseData := pa.getAddressParseData()
	return chooseMACAddressProvider(fromString, validationOptions, &pa, addressParseData)
}

func validateIPAddress(
	validationOptions IPAddressStringParameters,
	str string,
	strStartIndex, strEndIndex int,
	parseData *IPAddressParseData,
	isEmbeddedIPv4 bool) AddressStringException {
	return validateAddress(validationOptions, nil, str, strStartIndex, strEndIndex, parseData, nil, isEmbeddedIPv4)
}

func validateMACAddress(
	validationOptions MACAddressStringParameters,
	str string,
	strStartIndex, strEndIndex int,
	parseData *MACAddressParseData) AddressStringException {
	return validateAddress(nil, validationOptions, str, strStartIndex, strEndIndex, nil, parseData, false)
}

/**
* This method is the mega-parser.
* It is designed to go through the characters one-by-one as a big if/else.
* You have basically several cases: digits, segment separators (. : -), end characters like zone or prefix length,
* range characters denoting a range a-b, wildcard char *, and the 'x' character used to denote hex like 0xf.
*
* Most of the processing occurs in the segment characters, where each segment is analyzed based on what chars came before.
*
* We can parse all possible imaginable variations of mac, ipv4, and ipv6.
*
* This is not the clearest way to write such a parser, because the code for each possible variation is interspersed amongst the various cases,
* so you cannot easily see the code for a given variation clearly, but written this way it may be the fastest parser since we basically account
* for all possibilities simultaneously as we move through the characters just once.
*
 */
func validateAddress(
	validationOptions IPAddressStringParameters,
	macOptions MACAddressStringParameters,
	str string,
	strStartIndex, strEndIndex int,
	ipAddressParseData *IPAddressParseData, //TODO we need the two parse data types
	macAddressParseData *MACAddressParseData,
	isEmbeddedIPv4 bool) AddressStringException {

	isMac := macAddressParseData != nil

	var parseData *AddressParseData
	var stringFormatParams AddressStringFormatParameters
	var ipv6SpecificOptions IPv6AddressStringParameters
	var ipv4SpecificOptions IPv4AddressStringParameters
	var macSpecificOptions MACAddressStringFormatParameters
	var baseOptions AddressStringParameters
	var macFormat MACFormat
	canBeBase85 := false
	if isMac {
		baseOptions = macOptions
		macSpecificOptions = macOptions.GetFormatParameters()
		stringFormatParams = macSpecificOptions
		macAddressParseData.init(str)
		parseData = macAddressParseData.getAddressParseData()
	} else {
		baseOptions = validationOptions
		// we set stringFormatParams when we know what ip version we have
		ipAddressParseData.init(str)
		parseData = ipAddressParseData.getAddressParseData()
		ipv6SpecificOptions = validationOptions.GetIPv6Parameters()
		canBeBase85 = ipv6SpecificOptions.AllowsBase85()
		ipv4SpecificOptions = validationOptions.GetIPv4Parameters()
	}

	index := strStartIndex

	// per segment variables
	var frontDigitCount, frontLeadingZeroCount, frontSingleWildcardCount, leadingZeroCount,
		singleWildcardCount, wildcardCount, frontWildcardCount int

	var extendedCharacterIndex, extendedRangeWildcardIndex, rangeWildcardIndex,
		hexDelimiterIndex, frontHexDelimiterIndex, segmentStartIndex,
		segmentValueStartIndex int = -1, -1, -1, -1, -1, index, index

	var isSegmented, leadingWithZero, hasDigits, frontIsStandardRangeChar, atEnd,
		firstSegmentDashedRange, frontUppercase, uppercase,
		isSingleIPv6, isSingleSegment, isDoubleSegment bool

	var err error

	checkCharCounts := true

	var version IPVersion
	var currentValueHex, currentFrontValueHex, extendedValue uint64

	charArray := chars

	var currentChar byte
	for {
		if index >= strEndIndex {
			atEnd = (index == strEndIndex)
			if atEnd {
				parseData.setAddressEndIndex(index)
				if isSegmented {
					if isMac {
						currentChar = byte(*macFormat)
						isDoubleSegment = parseData.getSegmentCount() == 1 && currentChar == RangeSeparator
						macAddressParseData.setDoubleSegment(isDoubleSegment)
						if isDoubleSegment {
							totalDigits := index - segmentValueStartIndex
							macAddressParseData.setExtended(totalDigits == MAC_EXTENDED_DOUBLE_SEGMENT_DIGIT_COUNT)
						}
					} else {
						// we are not base 85, so error if necessary
						if extendedCharacterIndex >= 0 {
							return &addressStringException{
								str:   str,
								index: extendedCharacterIndex,
								key:   "ipaddress.error.invalid.character.at.index",
							}
						}
						//current char is either . or : to handle last segment, unless we have double :: in which case we already handled last segment
						if version.isIPv4() {
							currentChar = IPv4SegmentSeparator
						} else { //ipv6
							if index == segmentStartIndex {
								if index == parseData.getConsecutiveSeparatorIndex()+2 {
									//ends with ::, we've already parsed the last segment
									break
								}
								return &addressStringException{str: str, key: "ipaddress.error.cannot.end.with.single.separator"}
							} else if ipAddressParseData.isProvidingMixedIPv6() {
								//no need to parse the last segment, since it is mixed we already have
								break
							} else {
								currentChar = IPv6SegmentSeparator
							}
						}
					}
				} else {
					// no segment separator so far and segmentCount is 0
					// it could be all addresses like "*", empty "", prefix-only ip address like /64, single segment like 12345, or single segment range like 12345-67890
					totalCharacterCount := index - strStartIndex
					if totalCharacterCount == 0 {
						//it is prefix-only or ""
						if !isMac && ipAddressParseData.hasPrefixSeparator() {
							if !validationOptions.AllowsPrefixOnly() {
								return &addressStringException{str: str, key: "ipaddress.error.prefix.only"}
							}
						} else if !baseOptions.AllowsEmpty() {
							return &addressStringException{str: str, key: "ipaddress.error.empty"}
						}
						parseData.setEmpty(true)
						break
					} else if wildcardCount == totalCharacterCount && wildcardCount <= MAX_WILDCARDS { //20 wildcards are base 85!
						if !baseOptions.AllowsAll() {
							return &addressStringException{str: str, key: "ipaddress.error.all"}
						}
						parseData.setHasWildcard()
						parseData.setAll()
						break
					}
					// At this point it is single segment like 12345 or single segment range like 12345-67890
					totalDigits := index - segmentValueStartIndex
					frontTotalDigits := frontLeadingZeroCount + frontDigitCount
					if isMac {
						// we handle the double segment format abcdef-abcdef here
						isDoubleSeg := (totalDigits == MAC_DOUBLE_SEGMENT_DIGIT_COUNT || totalDigits == MAC_EXTENDED_DOUBLE_SEGMENT_DIGIT_COUNT) &&
							(frontTotalDigits == MAC_DOUBLE_SEGMENT_DIGIT_COUNT || frontWildcardCount > 0)
						isDoubleSeg = isDoubleSeg || (frontTotalDigits == MAC_DOUBLE_SEGMENT_DIGIT_COUNT && wildcardCount > 0)
						isDoubleSeg = isDoubleSeg || (frontWildcardCount > 0 && wildcardCount > 0)
						if isDoubleSeg && !firstSegmentDashedRange { //checks for *-abcdef and abcdef-* and abcdef-abcdef and *-* two segment addresses
							// firstSegmentDashedRange means that the range character is '|'
							addressSize := macOptions.AddressSize()
							if addressSize == EUI64 && totalDigits == MAC_DOUBLE_SEGMENT_DIGIT_COUNT {
								return &addressStringException{str: str, key: "ipaddress.error.too.few.segments"}
							} else if addressSize == MAC && totalDigits == MAC_EXTENDED_DOUBLE_SEGMENT_DIGIT_COUNT {
								return &addressStringException{str: str, key: "ipaddress.error.too.many.segments"}
							}
							// we have aaaaaa-bbbbbb
							if !macOptions.AllowsSingleDashed() {
								return &addressStringException{str: str, key: "ipaddress.mac.error.format"}
							}
							isDoubleSegment = true
							macAddressParseData.setDoubleSegment(true)
							macAddressParseData.setExtended(totalDigits == MAC_EXTENDED_DOUBLE_SEGMENT_DIGIT_COUNT) //we have aaaaaa-bbbbbbbbbb
							currentChar = MACDashSegmentSeparator
							checkCharCounts = false //counted chars already
						} else if frontWildcardCount > 0 || wildcardCount > 0 {
							// either x-* or *-x, we treat these as if they can be expanded to x-*-*-*-*-* or *-*-*-*-*-x
							if !macOptions.AllowsSingleDashed() {
								return &addressStringException{str: str, key: "ipaddress.mac.error.format"}
							}
							currentChar = MACDashSegmentSeparator
						} else {
							// a string of digits with no segment separator
							// here we handle abcdefabcdef or abcdefabcdef|abcdefabcdef or abcdefabcdef-abcdefabcdef
							if !baseOptions.AllowsSingleSegment() {
								return &addressStringException{str: str, key: "ipaddress.error.single.segment"}
							}
							is12Digits := totalDigits == MAC_SINGLE_SEGMENT_DIGIT_COUNT
							is16Digits := totalDigits == MAC_EXTENDED_SINGLE_SEGMENT_DIGIT_COUNT
							isNoDigits := totalDigits == 0
							if is12Digits || is16Digits || isNoDigits {
								var frontIs12Digits, frontIs16Digits, frontIsNoDigits bool
								if rangeWildcardIndex >= 0 {
									frontIs12Digits = frontTotalDigits == MAC_SINGLE_SEGMENT_DIGIT_COUNT
									frontIs16Digits = frontTotalDigits == MAC_EXTENDED_SINGLE_SEGMENT_DIGIT_COUNT
									frontIsNoDigits = frontTotalDigits == 0
									if is12Digits {
										if !frontIs12Digits && !frontIsNoDigits {
											return &addressStringException{str: str, key: "ipaddress.error.front.digit.count"}
										}
									} else if is16Digits {
										if !frontIs16Digits && !frontIsNoDigits {
											return &addressStringException{str: str, key: "ipaddress.error.front.digit.count"}
										}
									} else if isNoDigits {
										if !frontIs12Digits && !frontIs16Digits {
											return &addressStringException{str: str, key: "ipaddress.error.front.digit.count"}
										}
									}
								} else if isNoDigits {
									return &addressStringException{str: str, key: "ipaddress.error.too.few.segments.digit.count"}
								}
								isSingleSegment = true
								parseData.setSingleSegment()
								macAddressParseData.setExtended(is16Digits || frontIs16Digits)
								currentChar = MACColonSegmentSeparator
								checkCharCounts = false //counted chars already
							} else {
								return &addressStringException{str: str, key: "ipaddress.error.too.few.segments.digit.count"}
							}
						}
					} else {
						//a string of digits with no segment separator
						if !baseOptions.AllowsSingleSegment() {
							return &addressStringException{str: str, key: "ipaddress.error.single.segment"}
						}

						isRange := rangeWildcardIndex >= 0
						isSingleSeg, serr := isSingleSegmentIPv6(str, totalDigits, isRange, frontTotalDigits, ipv6SpecificOptions)
						if serr != nil {
							return serr
						} else if isSingleSeg {
							// we are not base 85, so throw if necessary
							if extendedCharacterIndex >= 0 {
								return &addressStringException{
									str:   str,
									index: extendedCharacterIndex,
									key:   "ipaddress.error.invalid.character.at.index",
								}
							}
							isSingleIPv6 = true
							currentChar = IPv6SegmentSeparator
						} else {
							if canBeBase85 {
								if canBeBase85, serr = parseBase85(
									validationOptions, str, strStartIndex, strEndIndex, ipAddressParseData,
									extendedRangeWildcardIndex, totalCharacterCount, index); canBeBase85 {
									break
								}
								if serr != nil {
									return serr
								}
							}
							leadingZeros := leadingZeroCount
							if leadingWithZero {
								leadingZeros++
							}
							isSingleSeg, serr = isSingleSegmentIPv4(
								str,
								totalDigits-leadingZeros,
								totalDigits,
								isRange,
								frontDigitCount,
								frontTotalDigits,
								ipv4SpecificOptions)
							if serr != nil {
								return serr
							} else if isSingleSeg {
								// we are not base 85, so throw if necessary
								if extendedCharacterIndex >= 0 {
									return &addressStringException{
										str:   str,
										index: extendedCharacterIndex,
										key:   "ipaddress.error.invalid.character.at.index",
									}
								}
								currentChar = IPv4SegmentSeparator
							} else {
								return &addressStringException{str: str, key: "ipaddress.error.too.few.segments.digit.count"}
							}
						}
						isSingleSegment = true
						parseData.setSingleSegment()
						checkCharCounts = false // counted chars already
					}
				}
			} else {
				break
			}
		} else {
			currentChar = str[index]
		}

		// evaluate the character
		if currentChar <= '9' && currentChar >= '0' {
			if hasDigits {
				currentValueHex = currentValueHex<<4 | charArray[currentChar]
			} else {
				if currentChar == '0' {
					if leadingWithZero {
						leadingZeroCount++
					} else {
						leadingWithZero = true
					}
				} else {
					hasDigits = true
					currentValueHex = currentValueHex<<4 | charArray[currentChar]
				}
			}
			index++
		} else if currentChar >= 'a' && currentChar <= 'f' {
			currentValueHex = currentValueHex<<4 | charArray[currentChar]
			hasDigits = true
			index++
		} else if currentChar == IPv4SegmentSeparator {
			segCount := parseData.getSegmentCount()
			// could be mac or ipv4, we handle either one
			if isMac {
				if segCount == 0 {
					if !macOptions.AllowsDotted() {
						return &addressStringException{str: str, key: "ipaddress.mac.error.format"}
					}
					macFormat = DOTTED
					macAddressParseData.setFormat(macFormat)
					parseData.initSegmentData(MediaAccessControlDotted64SegmentCount)
					isSegmented = true
				} else {
					if macFormat != DOTTED {
						return &addressStringException{str: str, key: "ipaddress.mac.error.mix.format.characters.at.index", index: index}
					}
					var limit int
					if macOptions.AddressSize() == MAC {
						limit = MediaAccessControlDottedSegmentCount
					} else {
						limit = MediaAccessControlDotted64SegmentCount
					}
					if segCount >= limit {
						return &addressStringException{str: str, key: "ipaddress.error.too.many.segments"}
					}
				}
			} else {
				//end of an ipv4 segment
				if segCount == 0 {
					if !validationOptions.AllowsIPv4() {
						return &addressStringException{str: str, key: "ipaddress.error.ipv4"}
					}
					version = IPv4
					ipAddressParseData.setVersion(version)
					stringFormatParams = ipv4SpecificOptions
					canBeBase85 = false
					parseData.initSegmentData(IPv4SegmentCount)
					isSegmented = true
				} else if ipAddressParseData.getProviderIPVersion().isIPv6() {
					//mixed IPv6 address like 1:2:3:4:5:6:1.2.3.4
					if !ipv6SpecificOptions.AllowsMixed() {
						return &addressStringException{str: str, key: "ipaddress.error.no.mixed"}
					}
					totalSegmentCount := segCount + IPv6MixedReplacedSegmentCount
					if totalSegmentCount > IPv6SegmentCount {
						return &addressStringException{str: str, key: "ipaddress.error.too.many.segments"}
					}
					if wildcardCount > 0 {
						if parseData.getConsecutiveSeparatorIndex() < 0 &&
							totalSegmentCount < IPv6SegmentCount &&
							ipv6SpecificOptions.AllowsWildcardedSeparator() {
							// the '*' is covering an additional ipv6 segment (eg 1:2:3:4:5:*.2.3.4, the * covers both an ipv4 and ipv6 segment)
							// we flag this IPv6 segment with KEY_MERGED_MIXED
							parseData.setHasWildcard()
							assign6Attributes2Values1Flags(segmentStartIndex, index, segmentStartIndex, segmentStartIndex, index, segmentStartIndex,
								parseData, segCount, 0, IPv6MaxValuePerSegment, KEY_WILDCARD|KEY_MERGED_MIXED)
							parseData.incrementSegmentCount()
						}
					}
					mixedOptions := ipv6SpecificOptions.GetMixedParameters()
					pa := &ParsedIPAddress{
						IPAddressParseData: IPAddressParseData{AddressParseData: AddressParseData{str: str}},
						options:            mixedOptions,
					}
					err = validateIPAddress(mixedOptions, str, segmentStartIndex, strEndIndex, &pa.IPAddressParseData, true)
					if err != nil {
						return err
					}
					pa.clearQualifier()
					err = checkSegments(str, mixedOptions, pa.getIPAddressParseData())
					if err != nil {
						return err
					}
					ipAddressParseData.setMixedParsedAddress(pa)
					index = pa.getAddressParseData().getAddressEndIndex()
					continue
				} else if segCount >= IPv4SegmentCount {
					return &addressStringException{str: str, key: "ipaddress.error.ipv4.too.many.segments"}
				}
			}
			if wildcardCount > 0 {
				if !stringFormatParams.GetRangeParameters().AllowsWildcard() {
					return &addressStringException{str: str, key: "ipaddress.error.no.wildcard"}
				}
				//wildcards must appear alone
				totalDigits := index - segmentStartIndex
				if wildcardCount != totalDigits || hexDelimiterIndex >= 0 {
					return &addressStringException{str: str, index: index, key: "ipaddress.error.invalid.character.combination.at.index"}
				}
				parseData.setHasWildcard()
				startIndex := index - wildcardCount
				var max uint64
				if isMac {
					max = MACMaxValuePerDottedSegment
				} else {
					max = IPv4MaxValuePerSegment
				}
				assign6Attributes2Values1Flags(startIndex, index, startIndex, startIndex, index, startIndex,
					parseData, segCount, 0, max, KEY_WILDCARD)
				wildcardCount = 0
			} else {
				var flags, rangeFlags, radix uint32
				var value uint64
				digitStartIndex := segmentValueStartIndex + leadingZeroCount
				digitCount := index - digitStartIndex
				if leadingWithZero {
					if digitCount == 1 {
						if leadingZeroCount == 0 && rangeWildcardIndex < 0 && hexDelimiterIndex < 0 {
							// handles 0, but not 1-0 or 0x0
							assign4Attributes(digitStartIndex, index, parseData, segCount, 10, segmentValueStartIndex)
							parseData.incrementSegmentCount()
							index++
							segmentStartIndex = index
							segmentValueStartIndex = index
							leadingWithZero = false
							continue
						}
					} else {
						leadingZeroCount++
						digitStartIndex++
						digitCount--
					}
					leadingWithZero = false // reset this flag now that we've used it
				}
				noValuesToSet := false
				if digitCount == 0 {
					// we allow an empty range boundary to denote the max value
					if rangeWildcardIndex < 0 || hexDelimiterIndex >= 0 || !stringFormatParams.GetRangeParameters().AllowsInferredBoundary() {
						// starts with '.', or has two consecutive '.'
						return &addressStringException{str: str, key: "ipaddress.error.empty.segment.at.index", index: index}
					} else if isMac {
						value = MACMaxValuePerDottedSegment
						radix = MACDefaultTextualRadix
					} else {
						value = IPv4MaxValuePerSegment // for inet-aton multi-segment, this will be adjusted later
						radix = IPv4DefaultTextualRadix
					}
					rangeFlags = KEY_INFERRED_UPPER_BOUNDARY
				} else { // digitCount > 0
					// Note: we cannot do max value check on ipv4 until after all segments have been read due to inet_aton joined segments,
					// although we can do a preliminary check here that is in fact needed to prevent overflow when calculating values later
					isBinary := false
					hasLeadingZeros := leadingZeroCount > 0
					isSingleWildcard := singleWildcardCount > 0
					if isMac || hexDelimiterIndex >= 0 {
						if isMac { // mac dotted segments aabb.ccdd.eeff
							maxMacChars := 4
							if digitCount > maxMacChars { //
								return &addressStringException{str: str, key: "ipaddress.error.segment.too.long.at.index", index: segmentValueStartIndex}
							}
							totalDigits := digitCount + leadingZeroCount
							if hexDelimiterIndex >= 0 {
								return &addressStringException{str: str, key: "ipaddress.error.invalid.character.combination.at.index", index: hexDelimiterIndex}
							} else if leadingZeroCount > 0 && !stringFormatParams.AllowsLeadingZeros() {
								return &addressStringException{str: str, key: "ipaddress.error.segment.leading.zeros"}
							} else if !stringFormatParams.AllowsUnlimitedLeadingZeros() && totalDigits > maxMacChars {
								return &addressStringException{str: str, key: "ipaddress.error.segment.too.long.at.index", index: segmentValueStartIndex}
							} else if !macSpecificOptions.AllowsShortSegments() && totalDigits < maxMacChars {
								return &addressStringException{str: str, key: "ipaddress.error.segment.too.short.at.index", index: segmentValueStartIndex}
							}
						} else if !stringFormatParams.AllowsLeadingZeros() {
							// the '0' preceding the 'x' is not allowed
							return &addressStringException{str: str, key: "ipaddress.error.segment.leading.zeros"}
						} else if !ipv4SpecificOptions.Allows_inet_aton_hex() {
							return &addressStringException{str: str, key: "ipaddress.error.ipv4.segment.hex"}
						} else if hasLeadingZeros && !ipv4SpecificOptions.Allows_inet_aton_leading_zeros() {
							// the '0' following the 'x' is not allowed
							return &addressStringException{str: str, key: "ipaddress.error.segment.leading.zeros"}
						} else {
							if digitCount > 8 { // 0xffffffff
								return &addressStringException{str: str, key: "ipaddress.error.segment.too.long.at.index", index: segmentValueStartIndex}
							}
							ipAddressParseData.set_has_inet_aton_value(true)
						}
						radix = 16
						if isSingleWildcard {
							if rangeWildcardIndex >= 0 {
								return &addressStringException{str: str, key: "ipaddress.error.invalid.character.combination.at.index", index: index}
							}
							err = assignSingleWildcard16(currentValueHex, str, digitStartIndex, index, singleWildcardCount, parseData, segCount, segmentValueStartIndex, stringFormatParams)
							if err != nil {
								return err
							}
							value = 0
							noValuesToSet = true
							singleWildcardCount = 0
						} else {
							value = currentValueHex
						}
						hexDelimiterIndex = -1
					} else {
						isBinaryOrOctal := hasLeadingZeros
						if isBinaryOrOctal {
							isBinary = ipv4SpecificOptions.AllowsBinary() && isBinaryDelimiter(str, digitStartIndex)
							isBinaryOrOctal = isBinary || ipv4SpecificOptions.Allows_inet_aton_octal()
						}
						if isBinaryOrOctal {
							if !stringFormatParams.AllowsLeadingZeros() {
								return &addressStringException{str: str, key: "ipaddress.error.segment.leading.zeros"}
							}
							if isBinary {
								if digitCount > 33 {
									return &addressStringException{str: str, key: "ipaddress.error.segment.too.long.at.index", index: segmentValueStartIndex}
								}
								digitStartIndex++ // exclude the 'b' in 0b1100
								digitCount--      // exclude the 'b'
								radix = 2
								ipAddressParseData.setHasBinaryDigits(true)
								if isSingleWildcard {
									if rangeWildcardIndex >= 0 {
										return &addressStringException{str: str, index: index, key: "ipaddress.error.invalid.character.combination.at.index"}
									}
									if digitCount > 16 {
										parseSingleSegmentSingleWildcard2(str, digitStartIndex, index, singleWildcardCount, parseData, segCount, segmentValueStartIndex, stringFormatParams)
									} else {
										switchSingleWildcard2(currentValueHex, str, digitStartIndex, index, singleWildcardCount, parseData, segCount, segmentValueStartIndex, stringFormatParams)
									}
									value = 0
									noValuesToSet = true
									singleWildcardCount = 0
								} else {
									if digitCount > 16 {
										value = parseLong2(str, digitStartIndex, index)
									} else {
										value, err = switchValue2(currentValueHex, str, digitCount)
										if err != nil {
											return err
										}
									}
								}
							} else {
								if leadingZeroCount > 1 && !ipv4SpecificOptions.Allows_inet_aton_leading_zeros() {
									return &addressStringException{str: str, key: "ipaddress.error.segment.leading.zeros"}
								} else if digitCount > 11 { //octal 037777777777
									return &addressStringException{str: str, key: "ipaddress.error.segment.too.long.at.index", index: segmentValueStartIndex}
								}
								ipAddressParseData.set_has_inet_aton_value(true)
								radix = 8
								if isSingleWildcard {
									if rangeWildcardIndex >= 0 {
										return &addressStringException{str: str, key: "ipaddress.error.invalid.character.combination.at.index", index: index}
									}
									switchSingleWildcard8(currentValueHex, str, digitStartIndex, index, singleWildcardCount, parseData, segCount, segmentValueStartIndex, stringFormatParams)
									value = 0
									noValuesToSet = true
									singleWildcardCount = 0
								} else {
									value, err = switchValue8(currentValueHex, str, digitCount)
									if err != nil {
										return err
									}
								}
							}
						} else {
							if hasLeadingZeros {
								if !stringFormatParams.AllowsLeadingZeros() {
									return &addressStringException{str: str, key: "ipaddress.error.segment.leading.zeros"}
								}
								ipAddressParseData.setHasIPv4LeadingZeros(true)
							}
							if digitCount > 10 { // 4294967295
								return &addressStringException{str: str, key: "ipaddress.error.segment.too.long.at.index", index: segmentValueStartIndex}
							}
							radix = 10
							if isSingleWildcard {
								if rangeWildcardIndex >= 0 {
									return &addressStringException{str: str, key: "ipaddress.error.invalid.character.combination.at.index", index: index}
								}
								switchSingleWildcard10(currentValueHex, str, digitStartIndex, index, singleWildcardCount, parseData, segCount, segmentValueStartIndex, ipv4SpecificOptions)
								value = 0
								noValuesToSet = true
								singleWildcardCount = 0
							} else {
								value, err = switchValue10(currentValueHex, str, digitCount)
								if err != nil {
									return err
								}
								flags = KEY_STANDARD_STR
							}
						}
					}
					hasDigits = false
					currentValueHex = 0
				}
				if rangeWildcardIndex >= 0 {
					var frontRadix uint32
					var front uint64
					frontStartIndex := rangeWildcardIndex - frontDigitCount
					frontEndIndex := rangeWildcardIndex
					frontLeadingZeroStartIndex := frontStartIndex - frontLeadingZeroCount
					if !stringFormatParams.GetRangeParameters().AllowsRangeSeparator() {
						return &addressStringException{str: str, key: "ipaddress.error.no.range"}
					} else if frontSingleWildcardCount > 0 || frontWildcardCount > 0 { //no wildcards in ranges
						return &addressStringException{str: str, key: "ipaddress.error.invalid.character.combination.at.index", index: rangeWildcardIndex}
					}
					frontEmpty := frontStartIndex == frontEndIndex
					isReversed := false
					hasFrontLeadingZeros := frontLeadingZeroCount > 0
					if isMac || frontHexDelimiterIndex >= 0 {
						if isMac {
							totalFrontDigits := frontDigitCount + frontLeadingZeroCount
							maxMacChars := 4
							if frontHexDelimiterIndex >= 0 {
								return &addressStringException{str: str, key: "ipaddress.error.invalid.character.combination.at.index", index: frontHexDelimiterIndex}
							} else if hasFrontLeadingZeros && !stringFormatParams.AllowsLeadingZeros() {
								return &addressStringException{str: str, key: "ipaddress.error.segment.leading.zeros"}
							} else if !stringFormatParams.AllowsUnlimitedLeadingZeros() && totalFrontDigits > maxMacChars {
								return &addressStringException{str: str, key: "ipaddress.error.segment.too.long.at.index", index: frontLeadingZeroStartIndex}
							} else if !macSpecificOptions.AllowsShortSegments() && totalFrontDigits < maxMacChars {
								return &addressStringException{str: str, key: "ipaddress.error.segment.too.short.at.index", index: frontLeadingZeroStartIndex}
							} else if frontEmpty { //we allow the front of a range to be empty in which case it is 0
								if !stringFormatParams.GetRangeParameters().AllowsInferredBoundary() {
									return &addressStringException{str: str, key: "ipaddress.error.empty.segment.at.index", index: index}
								}
								rangeFlags |= KEY_INFERRED_LOWER_BOUNDARY
								front = 0
							} else if frontDigitCount > maxMacChars { // mac dotted segments aaa.bbb.ccc.ddd
								return &addressStringException{str: str, key: "ipaddress.error.segment.too.long.at.index", index: frontLeadingZeroStartIndex}
							} else {
								front = currentFrontValueHex
								isReversed = front > value && digitCount != 0
							}
						} else if !stringFormatParams.AllowsLeadingZeros() {
							// the '0' preceding the 'x' is not allowed
							return &addressStringException{str: str, key: "ipaddress.error.segment.leading.zeros"}
						} else if !ipv4SpecificOptions.Allows_inet_aton_hex() {
							return &addressStringException{str: str, key: "ipaddress.error.ipv4.segment.hex"}
						} else if hasFrontLeadingZeros && !ipv4SpecificOptions.Allows_inet_aton_leading_zeros() {
							// the '0' following the 'x' is not allowed
							return &addressStringException{str: str, key: "ipaddress.error.segment.leading.zeros"}
						} else if frontEmpty {
							return &addressStringException{str: str, key: "ipaddress.error.empty.segment.at.index", index: index}
						} else if frontDigitCount > 8 { // 0xffffffff
							return &addressStringException{str: str, key: "ipaddress.error.segment.too.long.at.index", index: frontLeadingZeroStartIndex}
						} else {
							ipAddressParseData.set_has_inet_aton_value(true)
							front = currentFrontValueHex
							isReversed = front > value && digitCount != 0
						}
						frontRadix = 16
					} else {
						if hasFrontLeadingZeros {
							if !stringFormatParams.AllowsLeadingZeros() {
								return &addressStringException{str: str, key: "ipaddress.error.segment.leading.zeros"}
							}
							if ipv4SpecificOptions.AllowsBinary() && isBinaryDelimiter(str, frontStartIndex) {
								if frontDigitCount > 33 {
									return &addressStringException{str: str, key: "ipaddress.error.segment.too.long.at.index", index: frontLeadingZeroStartIndex}
								}
								ipAddressParseData.setHasBinaryDigits(true)
								frontStartIndex++
								frontDigitCount--
								if frontDigitCount > 16 {
									front = parseLong2(str, frontStartIndex, frontEndIndex)
								} else {
									front, err = switchValue2(currentFrontValueHex, str, frontDigitCount)
									if err != nil {
										return err
									}
								}
								frontRadix = 2
								isReversed = digitCount != 0 && front > value
							} else if ipv4SpecificOptions.Allows_inet_aton_octal() {
								if frontLeadingZeroCount > 1 && !ipv4SpecificOptions.Allows_inet_aton_leading_zeros() {
									return &addressStringException{str: str, key: "ipaddress.error.segment.leading.zeros"}
								} else if frontDigitCount > 11 { // 037777777777
									return &addressStringException{str: str, key: "ipaddress.error.segment.too.long.at.index", index: frontLeadingZeroStartIndex}
								}
								ipAddressParseData.set_has_inet_aton_value(true)
								front, err = switchValue8(currentFrontValueHex, str, frontDigitCount)
								if err != nil {
									return err
								}
								frontRadix = 8
								isReversed = digitCount != 0 && front > value
							}
						}
						if frontRadix == 0 {
							frontRadix = 10
							if frontEmpty { //we allow the front of a range to be empty in which case it is 0
								if !stringFormatParams.GetRangeParameters().AllowsInferredBoundary() {
									return &addressStringException{str: str, key: "ipaddress.error.empty.segment.at.index", index: index}
								}
								rangeFlags |= KEY_INFERRED_LOWER_BOUNDARY
							} else if frontDigitCount > 10 { // 4294967295
								return &addressStringException{str: str, key: "ipaddress.error.segment.too.long.at.index", index: frontLeadingZeroStartIndex}
							} else {
								front, err = switchValue10(currentFrontValueHex, str, frontDigitCount)
								if err != nil {
									return err
								}
								if hasFrontLeadingZeros {
									if !stringFormatParams.AllowsLeadingZeros() {
										return &addressStringException{str: str, key: "ipaddress.error.segment.leading.zeros"}
									}
									ipAddressParseData.setHasIPv4LeadingZeros(true)
								}
								isReversed = digitCount != 0 && front > value
								if !isReversed {
									if leadingZeroCount == 0 && (flags&KEY_STANDARD_STR) != 0 {
										rangeFlags |= KEY_STANDARD_RANGE_STR | KEY_STANDARD_STR
									} else {
										rangeFlags |= KEY_STANDARD_STR
									}
								}
							}
						}
					}
					backEndIndex := index
					if isReversed {
						if !stringFormatParams.GetRangeParameters().AllowsReverseRange() {
							return &addressStringException{str: str, key: "ipaddress.error.invalidRange"}
						}
						// switcheroo
						frontStartIndex, digitStartIndex = digitStartIndex, frontStartIndex
						frontEndIndex, backEndIndex = backEndIndex, frontEndIndex
						frontLeadingZeroStartIndex, segmentValueStartIndex = segmentValueStartIndex, frontLeadingZeroStartIndex
						frontRadix, radix = radix, frontRadix
						front, value = value, front
					}
					assign6Attributes2Values2Flags(frontStartIndex, frontEndIndex, frontLeadingZeroStartIndex, digitStartIndex, backEndIndex, segmentValueStartIndex,
						parseData, segCount, front, value, rangeFlags|KEY_RANGE_WILDCARD|frontRadix, radix)
					rangeWildcardIndex = -1
				} else if !noValuesToSet {
					assign3Attributes1Values1Flags(digitStartIndex, index, segmentValueStartIndex, parseData, segCount, value, flags|radix)
				}
				leadingZeroCount = 0
			}
			parseData.incrementSegmentCount()
			index++
			segmentValueStartIndex = index
			segmentStartIndex = index
			// end of IPv4 segments and mac segments with '.' separators
		} else {
			//checking for all IPv6 and MAC segments, as well as the front range of all segments IPv4, IPv6, and MAC
			//the range character '-' is the same as one of the separators '-' for MAC,
			//so further work is required to distinguish between the front of IPv6/IPv4/MAC range and MAC segment
			//we also handle IPv6 segment and MAC segment in the same place to avoid code duplication
			var isSpace, isDashedRangeChar, isRangeChar bool
			if currentChar == IPv6SegmentSeparator {
				isRangeChar = false
				isSpace = false
			} else {
				isRangeChar = currentChar == RangeSeparator
				if isRangeChar || (isMac && (currentChar == MACDashSegmentSeparator)) {
					isSpace = false
					isDashedRangeChar = !isRangeChar
					/*
					 There are 3 cases here, A, B and C.
					 A - we have two MAC segments a-b-
					 B - we have the front of a range segment, either a-b which is MAC or IPV6,  or a|b or a<space>b which is MAC
					 C - we have a single segment, either a MAC segment a- or an IPv6 or MAC segment a:
					*/

					/*
					 Here we have either a '-' or '|' character or a space ' '

					 If we have a '-' character:
					 For MAC address, the cases are:
					 1. we did not previously set macFormat and we did not previously encounter '|'
					 		-if rangeWildcardIndex >= 0 we have dashed a-b- we treat as two segments, case A (we cannot have a|b because that would have set macFormat previously)
					 		-if rangeWildcardIndex < 0, we treat as front of range, case B, later we will know for sure if really front of range
					 2. we previously set macFormat or we previously encountered '|'
					 		if set to dashed we treat as one segment, may or may not be range segment, case C
					 		if we previously encountered '|' we treat as dashed range segment, case C
					 		if not we treat as front of range, case B

					 For IPv6, this is always front of range, case B

					 If we have a '|' character, we have front of range MAC, case B
					*/
					// we know either isRangeChar or isDashedRangeChar is true at this point
					endOfHexSegment := false
					if isMac {
						if macFormat == nil {
							if rangeWildcardIndex >= 0 && !firstSegmentDashedRange {

								//case A, we have two segments a-b- or a-b|

								//we handle the first segment here, we handle the second segment in the usual place below
								if frontHexDelimiterIndex >= 0 {
									return &addressStringException{str: str, key: "ipaddress.error.invalid.character.combination.at.index", index: frontHexDelimiterIndex}
								} else if hexDelimiterIndex >= 0 {
									return &addressStringException{str: str, key: "ipaddress.error.invalid.character.combination.at.index", index: hexDelimiterIndex}
								} else if !macOptions.AllowsDashed() {
									return &addressStringException{str: str, key: "ipaddress.mac.error.format"}
								}
								macFormat = DASHED
								macAddressParseData.setFormat(macFormat)
								checkCharCounts = false //counting chars later
								parseData.initSegmentData(ExtendedUniqueIdentifier64SegmentCount)
								isSegmented = true
								if frontWildcardCount > 0 {
									if !stringFormatParams.GetRangeParameters().AllowsWildcard() {
										return &addressStringException{str: str, key: "ipaddress.error.no.wildcard"}
									} else if frontSingleWildcardCount > 0 || frontLeadingZeroCount > 0 || frontDigitCount > 0 || frontHexDelimiterIndex >= 0 { //wildcards must appear alone
										return &addressStringException{str: str, key: "ipaddress.error.invalid.character.combination.at.index", index: rangeWildcardIndex}
									}
									parseData.setHasWildcard()
									backDigits := index - segmentValueStartIndex
									var upperValue uint64
									if isDoubleSegment || backDigits == MAC_DOUBLE_SEGMENT_DIGIT_COUNT {
										//even when not already identified as a double segment address, which is something we can see
										//only when we reach the end of the address, we may have a-b| where a is * and b is a 6 digit value.
										//Here we are considering the max value of a.
										//If b is 6 digits, we need to consider the max value of * as if we know already it will be double segment.
										//We can do this because the max values will be checked after the address has been parsed,
										//so even if a-b| ends up being a full address a-b|c-d-e-f-a and not a-b|c,
										//the fact that we have 6 digits here will invalidate the first address,
										//so we can safely assume that this address must be a double segment a-b|c even before we have seen that.
										upperValue = macMaxTriple
									} else {
										upperValue = MACMaxValuePerSegment
									}
									startIndex := rangeWildcardIndex - frontWildcardCount
									assign6Attributes2Values1Flags(startIndex, rangeWildcardIndex, startIndex, startIndex, rangeWildcardIndex, startIndex,
										parseData, 0, 0, upperValue, KEY_WILDCARD)
								} else {
									if !stringFormatParams.AllowsLeadingZeros() && frontLeadingZeroCount > 0 {
										return &addressStringException{str: str, key: "ipaddress.error.segment.leading.zeros"}
									}
									startIndex := rangeWildcardIndex - frontDigitCount
									leadingZeroStartIndex := startIndex - frontLeadingZeroCount
									if frontSingleWildcardCount > 0 {
										assignSingleWildcard16(currentFrontValueHex, str, startIndex, rangeWildcardIndex, singleWildcardCount, parseData, 0, leadingZeroStartIndex, stringFormatParams)
									} else {
										var flags uint32
										if !frontUppercase {
											if frontDigitCount == 0 {
												return &addressStringException{str: str, key: "ipaddress.error.empty.segment.at.index", index: startIndex}
											}
											flags = KEY_STANDARD_STR
										}
										assign3Attributes1Values1Flags(startIndex, rangeWildcardIndex, leadingZeroStartIndex, parseData, 0, currentFrontValueHex, flags)
									}
								}
								segmentValueStartIndex = rangeWildcardIndex + 1
								segmentStartIndex = segmentValueStartIndex
								rangeWildcardIndex = -1
								parseData.incrementSegmentCount()
								//end of handling the first segment a- in a-b-
								//below we handle b- by setting endOfSegment here
								endOfHexSegment = isRangeChar
							} else { //we will treat this as the front of a range
								if isDashedRangeChar {
									firstSegmentDashedRange = true
								} else {
									endOfHexSegment = firstSegmentDashedRange
								}
							}
						} else {
							if macFormat == DASHED {
								endOfHexSegment = isRangeChar
							} else if isDashedRangeChar {
								return &addressStringException{str: str, key: "ipaddress.error.invalid.character.combination.at.index", index: index}
							}
						}
					}
					if !endOfHexSegment {
						if extendedCharacterIndex < 0 {
							//case B
							if rangeWildcardIndex >= 0 {
								if canBeBase85 {
									index++
									extendedCharacterIndex = index
								} else {
									return &addressStringException{str: str, key: "ipaddress.error.invalid.character.combination.at.index", index: index}
								}
							} else {
								//here is where we handle the front 'a' of a range like 'a-b'
								rangeWildcardIndex = index

								frontIsStandardRangeChar = isRangeChar
								frontDigitCount = ((index - segmentValueStartIndex) - leadingZeroCount) - wildcardCount
								frontLeadingZeroCount = leadingZeroCount
								if leadingWithZero {
									if frontDigitCount != 1 {
										frontLeadingZeroCount++
										frontDigitCount--
									}
								}
								frontUppercase = uppercase
								frontHexDelimiterIndex = hexDelimiterIndex
								frontWildcardCount = wildcardCount
								frontSingleWildcardCount = singleWildcardCount
								currentFrontValueHex = currentValueHex

								index++
								segmentValueStartIndex = index
								hasDigits = false
								uppercase = false
								leadingWithZero = false
								hexDelimiterIndex = -1
								leadingZeroCount = 0
								wildcardCount = 0
								singleWildcardCount = 0
								currentValueHex = 0
							}
						} else {
							index++
						}
						continue
					}
				} else if isMac && currentChar == space {
					isSpace = true
				} else {
					// other characters handled here
					isZoneChar := false
					if currentChar == PrefixLenSeparator {
						if isMac {
							return &addressStringException{str: str, key: "ipaddress.error.invalid.character.at.index", index: index}
						}
						strEndIndex = index
						ipAddressParseData.setHasPrefixSeparator(true)
						ipAddressParseData.setQualifierIndex(index + 1)
					} else if currentChar >= 'A' && currentChar <= 'F' { // this is not paired with 'a' to 'f' because these are not canonical and hence not part of the fast path
						index++
						currentValueHex = (currentValueHex << 4) | charArray[currentChar]
						hasDigits = true
						uppercase = true
					} else {
						isSegWildcard := currentChar == SegmentWildcard
						if !isSegWildcard {
							isZoneChar = currentChar == SegmentSqlWildcard
							isSegWildcard = isZoneChar
						}
						if isSegWildcard {
							//the character * is always treated as wildcard (but later can be determined to be a base 85 character)

							//the character % denotes a zone and is also a character for the SQL wildcard,
							//and it is also a base 85 character,
							//so we treat it as zone only if the options allow it and it is in the zone position.
							//Either we have seen an ipv6 segment separator, or we are at the end of the correct number of digits for ipv6 single segment (which rules out base 85 or ipv4 single segment),
							//or we are the '*' all wildcard so far which can represent everything including ipv6
							//
							//In all other cases, the character is treated as wildcard,
							//but as is the case of other characters we may later discover we are base 85 ipv6
							//For base 85, we decided that having the same character mean two different thing depending on position in the string, that is not reasonable.
							//In fact, if the zone character were allowed, can you tell if there is a zone here or not: %%%%%%%%%%%%%%%%%%%%%%

							canBeZone := isZoneChar &&
								!isMac &&
								ipv6SpecificOptions.AllowsZone()
							if canBeZone {
								isIPv6 := (parseData.getSegmentCount() > 0 && (isEmbeddedIPv4 || ipAddressParseData.getProviderIPVersion() == IPv6) /* at end of IPv6 regular or mixed */)
								if !isIPv6 {
									isIPv6, _ = isSingleSegmentIPv6(str, index-segmentValueStartIndex, rangeWildcardIndex >= 0, frontLeadingZeroCount+frontDigitCount, ipv6SpecificOptions)
									if !isIPv6 {
										isIPv6 = wildcardCount == index && wildcardCount <= MAX_WILDCARDS /* all wildcards so far */
									}
								}
								canBeZone = isIPv6
							}
							if canBeZone {
								//we are not base 85
								canBeBase85 = false
								strEndIndex = index
								ipAddressParseData.setZoned(true)
								ipAddressParseData.setQualifierIndex(index + 1)
							} else {
								wildcardCount++
								index++
							}
						} else if currentChar == SegmentSqlSingleWildcard {
							hasDigits = true
							index++
							singleWildcardCount++
						} else if isHexDelimiter(currentChar) {
							if hasDigits || !leadingWithZero || leadingZeroCount > 0 || hexDelimiterIndex >= 0 || singleWildcardCount > 0 {
								if canBeBase85 {
									if extendedCharacterIndex < 0 {
										extendedCharacterIndex = index
									}
									index++
								} else {
									return &addressStringException{str: str, key: "ipaddress.error.invalid.character.combination.at.index", index: index}
								}
							} else {
								if isMac {
									if parseData.getSegmentCount() > 0 {
										return &addressStringException{str: str, key: "ipaddress.error.invalid.character.at.index", index: index}
									}
								} else if version.isIPv6() {
									return &addressStringException{str: str, key: "ipaddress.error.invalid.character.at.index", index: index}
								}
								hexDelimiterIndex = index
								leadingWithZero = false
								index++
								segmentValueStartIndex = index
							}
							//the remaining possibilities are base85 only
						} else if currentChar == AlternativeRangeSeparator {
							if canBeBase85 {
								if extendedCharacterIndex < 0 {
									extendedCharacterIndex = index
								} else if extendedRangeWildcardIndex >= 0 {
									return &addressStringException{str: str, key: "ipaddress.error.invalid.character.combination.at.index", index: index}
								}
								extendedRangeWildcardIndex = index
							} else {
								return &addressStringException{str: str, key: "ipaddress.error.invalid.character.at.index", index: index}
							}
							index++
						} else if currentChar == IPv6AlternativeZoneSeparator {
							if canBeBase85 && !isMac && ipv6SpecificOptions.AllowsZone() {
								strEndIndex = index
								ipAddressParseData.setZoned(true)
								ipAddressParseData.setBase85Zoned(true)
								ipAddressParseData.setQualifierIndex(index + 1)
							} else {
								return &addressStringException{str: str, key: "ipaddress.error.invalid.character.at.index", index: index}
							}
						} else {
							if canBeBase85 {
								if currentChar < 0 || int(currentChar) >= len(extendedChars) {
									return &addressStringException{str: str, key: "ipaddress.error.invalid.character.at.index", index: index}
								}
								val := extendedChars[currentChar]
								if val == 0 { //note that we already check for the currentChar '0' character at another else/if block, so any other character mapped to the value 0 is an invalid character
									return &addressStringException{str: str, key: "ipaddress.error.invalid.character.at.index", index: index}
								} else if extendedCharacterIndex < 0 {
									extendedCharacterIndex = index
								}
							} else {
								return &addressStringException{str: str, key: "ipaddress.error.invalid.character.at.index", index: index}
							}
							index++
						}
					}
					continue
				}
			}
			// ipv6 and mac segments handled here
			segCount := parseData.getSegmentCount()
			var hexMaxChars int
			if isMac {
				if segCount == 0 {
					if isSingleSegment {
						parseData.initSegmentData(1)
					} else {
						if hexDelimiterIndex >= 0 {
							return &addressStringException{str: str, key: "ipaddress.error.invalid.character.at.index", index: hexDelimiterIndex}
						} else {
							var isNoExc bool
							if isRangeChar {
								isNoExc = macOptions.AllowsDashed()
							} else if isSpace {
								isNoExc = macOptions.AllowsSpaceDelimited()
							} else {
								isNoExc = macOptions.AllowsColonDelimited()
							}
							if !isNoExc {
								return &addressStringException{str: str, key: "ipaddress.mac.error.format"}
							} else if isRangeChar {
								macFormat = DASHED
								macAddressParseData.setFormat(macFormat)
								checkCharCounts = false //counting chars later
							} else {
								if isSpace {
									macFormat = SPACE_DELIMITED
								} else {
									macFormat = COLON_DELIMITED
								}
								macAddressParseData.setFormat(macFormat)
							}
						}
						parseData.initSegmentData(ExtendedUniqueIdentifier64SegmentCount)
						isSegmented = true
					}
				} else {
					isExc := false
					if isRangeChar {
						isExc = macFormat != DASHED
					} else if isSpace {
						isExc = macFormat != SPACE_DELIMITED
					} else {
						isExc = macFormat != COLON_DELIMITED
					}
					if isExc {
						// TODO srarch for "ipaddress.error.invalid.character.at.index" should be 15, and 19 of "ipaddress.error.invalid.character.at.index", inside this func
						return &addressStringException{str: str, key: "ipaddress.mac.error.mix.format.characters.at.index", index: index}
					}
					var segLimit int
					if macOptions.AddressSize() == MAC {
						segLimit = MediaAccessControlSegmentCount
					} else {
						segLimit = ExtendedUniqueIdentifier64SegmentCount
					}
					if segCount >= segLimit {
						return &addressStringException{str: str, key: "ipaddress.error.too.many.segments"}
					}
				}
				hexMaxChars = MACSegmentMaxChars //will be ignored for single or double segments due to checkCharCounts booleans
			} else {
				if segCount == 0 {
					if !validationOptions.AllowsIPv6() {
						return &addressStringException{str: str, key: "ipaddress.error.ipv6"}
					}
					canBeBase85 = false
					version = IPv6
					ipAddressParseData.setVersion(version)
					stringFormatParams = ipv6SpecificOptions
					isSegmented = true

					if index == strStartIndex {
						firstIndex := index
						index++
						if index == strEndIndex {
							return &addressStringException{str: str, key: "ipaddress.error.too.few.segments"}
						} else if str[index] != IPv6SegmentSeparator {
							return &addressStringException{str: str, key: "ipaddress.error.ipv6.cannot.start.with.single.separator"}
						}
						parseData.initSegmentData(IPv6SegmentCount)
						parseData.setConsecutiveSeparatorSegmentIndex(0)
						parseData.setConsecutiveSeparatorIndex(firstIndex)
						assign3Attributes(index, index, parseData, 0, index)
						parseData.incrementSegmentCount()
						index++
						segmentValueStartIndex = index
						segmentStartIndex = segmentValueStartIndex
						continue
					} else {
						if isSingleSegment {
							parseData.initSegmentData(1)
						} else {
							if hexDelimiterIndex >= 0 {
								return &addressStringException{str: str, key: "ipaddress.error.invalid.character.at.index", index: hexDelimiterIndex}
							}
							parseData.initSegmentData(IPv6SegmentCount)
						}
					}
				} else if ipAddressParseData.getProviderIPVersion().isIPv4() {
					return &addressStringException{str: str, key: "ipaddress.error.ipv6.separator"}
				} else if segCount >= IPv6SegmentCount {
					return &addressStringException{str: str, key: "ipaddress.error.too.many.segments"}
				}
				hexMaxChars = IPv6SegmentMaxChars // will be ignored for single segment due to checkCharCounts boolean
			}
			if index == segmentStartIndex { // empty segment
				if isMac {
					return &addressStringException{str: str, key: "ipaddress.error.empty.segment.at.index", index: index}
				} else if parseData.getConsecutiveSeparatorIndex() >= 0 {
					return &addressStringException{str: str, key: "ipaddress.error.ipv6.ambiguous"}
				}
				parseData.setConsecutiveSeparatorSegmentIndex(segCount)
				parseData.setConsecutiveSeparatorIndex(index - 1)
				assign3Attributes(index, index, parseData, segCount, index)
				parseData.incrementSegmentCount()
			} else if wildcardCount > 0 && !isSingleIPv6 {
				if !stringFormatParams.GetRangeParameters().AllowsWildcard() {
					return &addressStringException{str: str, key: "ipaddress.error.no.wildcard"}
				}
				totalDigits := index - segmentStartIndex
				if wildcardCount != totalDigits || hexDelimiterIndex >= 0 {
					return &addressStringException{str: str, key: "ipaddress.error.invalid.character.combination.at.index", index: index}
				}
				parseData.setHasWildcard()
				startIndex := index - wildcardCount
				var maxVal uint64
				if isMac {
					if isDoubleSegment {
						maxVal = macMaxTriple
					} else {
						maxVal = MACMaxValuePerSegment
					}
				} else {
					maxVal = IPv6MaxValuePerSegment
				}
				assign6Attributes2Values1Flags(startIndex, index, startIndex, startIndex, index, startIndex,
					parseData, segCount, 0, maxVal, KEY_WILDCARD)
				parseData.incrementSegmentCount()
				wildcardCount = 0
			} else {
				startIndex := segmentValueStartIndex
				digitCount := index - startIndex
				noValuesToSet := false
				var value uint64
				var flags, rangeFlags uint32
				if leadingWithZero {
					if digitCount == 1 {
						// can only be a single 0
						if leadingZeroCount == 0 && rangeWildcardIndex < 0 {
							// handles 0 but not 1-0
							assign3Attributes(startIndex, index, parseData, segCount, segmentValueStartIndex)
							parseData.incrementSegmentCount()
							index++
							segmentValueStartIndex = index
							segmentStartIndex = segmentValueStartIndex
							leadingWithZero = false
							continue
						}
					} else {
						if hasDigits {
							leadingZeroCount++
						}
						startIndex += leadingZeroCount
						digitCount -= leadingZeroCount
					}
					leadingWithZero = false
				}
				if leadingZeroCount == 0 {
					if digitCount == 0 {
						// since we have already checked for an empty segment, this can only happen with a range, ie rangeWildcardIndex >= 0
						// we allow an empty range boundary to denote the max value
						if !stringFormatParams.GetRangeParameters().AllowsInferredBoundary() {
							// starts with '.', or has two consecutive '.'
							return &addressStringException{str: str, key: "ipaddress.error.empty.segment.at.index", index: index}
						} else if isMac {
							if isSingleSegment {
								if macAddressParseData.isExtended() {
									value = 0xffffffffffffffff
								} else {
									value = 0xffffffffffff
								}
							} else {
								value = MACMaxValuePerSegment
							}
						} else {
							if isSingleIPv6 {
								value = 0xffffffffffffffff
								extendedValue = value
							} else {
								value = IPv6MaxValuePerSegment
							}
						}
						rangeFlags = KEY_INFERRED_UPPER_BOUNDARY
					} else {
						if digitCount > hexMaxChars && checkCharCounts {
							return &addressStringException{str: str, key: "ipaddress.error.segment.too.long.at.index", index: segmentValueStartIndex}
						}
						if singleWildcardCount > 0 {
							noValuesToSet = true
							if rangeWildcardIndex >= 0 {
								return &addressStringException{str: str, key: "ipaddress.error.invalid.character.combination.at.index", index: index}
							} else if isSingleIPv6 { //We need this special call here because single ipv6 hex is 128 bits and cannot fit into a long
								parseSingleSegmentSingleWildcard16(currentValueHex, str, startIndex, index, singleWildcardCount, parseData, segCount, segmentValueStartIndex, stringFormatParams)
							} else {
								assignSingleWildcard16(currentValueHex, str, startIndex, index, singleWildcardCount, parseData, segCount, segmentValueStartIndex, stringFormatParams)
							}
							uppercase = false
							singleWildcardCount = 0
						} else {
							if isSingleIPv6 { //We need this special branch here because single ipv6 hex is 128 bits and cannot fit into a long
								midIndex := index - 16
								if startIndex < midIndex {
									extendedValue = parseLong16(str, startIndex, midIndex)
									value = parseLong16(str, midIndex, index)
								} else {
									value = currentValueHex
								}
							} else {
								value = currentValueHex
								if uppercase {
									uppercase = false
								} else {
									flags = KEY_STANDARD_STR
								}
							}
						}
						hasDigits = false
						currentValueHex = 0
					}
				} else {
					if leadingZeroCount == 1 && (digitCount == 17 || digitCount == 129) &&
						ipv6SpecificOptions.AllowsBinary() && isBinaryDelimiter(str, startIndex) {
						// IPv6 binary - to avoid ambiguity, all binary digits must be present, and preceded by 0b.
						// So for a single segment IPv6 segment:
						// 0b11 is a hex segment, 0b111 is hex, 0b1111 is invalid (too short for binary, too long for hex), 0b1100110011001100 is a binary segment
						if !stringFormatParams.AllowsLeadingZeros() {
							return &addressStringException{str: str, key: "ipaddress.error.segment.leading.zeros"}
						}
						startIndex++ // exclude the 'b' in 0b1100
						digitCount-- // exclude the 'b'
						if singleWildcardCount > 0 {
							if rangeWildcardIndex >= 0 {
								return &addressStringException{str: str, key: "ipaddress.error.invalid.character.combination.at.index", index: index}
							} else if isSingleIPv6 {
								parseSingleSegmentSingleWildcard2(str, startIndex, index, singleWildcardCount, parseData, segCount, segmentValueStartIndex, stringFormatParams)
							} else {
								switchSingleWildcard2(currentValueHex, str, startIndex, index, singleWildcardCount, parseData, segCount, segmentValueStartIndex, stringFormatParams)
							}
							noValuesToSet = true
							singleWildcardCount = 0
						} else {
							if isSingleIPv6 { //We need this special branch here because single ipv6 hex is 128 bits and cannot fit into a long
								midIndex := index - 64
								extendedValue = parseLong2(str, startIndex, midIndex)
								value = parseLong2(str, midIndex, index)
							} else {
								value, err = switchValue2(currentValueHex, str, digitCount)
								if err != nil {
									return err
								}
							}
							flags = 2 // radix
						}
						ipAddressParseData.setHasBinaryDigits(true)
						hasDigits = false
						currentValueHex = 0
					} else {
						if digitCount > hexMaxChars && checkCharCounts {
							return &addressStringException{str: str, key: "ipaddress.error.segment.too.long.at.index", index: segmentValueStartIndex}
						} else if !stringFormatParams.AllowsLeadingZeros() {
							return &addressStringException{str: str, key: "ipaddress.error.segment.leading.zeros"}
						} else if !stringFormatParams.AllowsUnlimitedLeadingZeros() && checkCharCounts && (digitCount+leadingZeroCount) > hexMaxChars {
							return &addressStringException{str: str, key: "ipaddress.error.segment.too.long.at.index", index: segmentValueStartIndex}
						}
						if singleWildcardCount > 0 {
							noValuesToSet = true
							if rangeWildcardIndex >= 0 {
								return &addressStringException{str: str, key: "ipaddress.error.invalid.character.combination.at.index", index: index}
							} else if isSingleIPv6 { //We need this special call here because single ipv6 hex is 128 bits and cannot fit into a long
								parseSingleSegmentSingleWildcard16(currentValueHex, str, startIndex, index, singleWildcardCount, parseData, segCount, segmentValueStartIndex, stringFormatParams)
							} else {
								assignSingleWildcard16(currentValueHex, str, startIndex, index, singleWildcardCount, parseData, segCount, segmentValueStartIndex, stringFormatParams)
							}
							uppercase = false
							singleWildcardCount = 0
						} else {
							if isSingleIPv6 { //We need this special branch here because single ipv6 hex is 128 bits and cannot fit into a long
								midIndex := index - 16
								if startIndex < midIndex {
									extendedValue = parseLong16(str, startIndex, midIndex)
									value = parseLong16(str, midIndex, index)
								} else {
									value = currentValueHex
								}
							} else {
								value = currentValueHex
								if uppercase {
									uppercase = false
								} else {
									flags = KEY_STANDARD_STR
								}
							}
						}
						hasDigits = false
						currentValueHex = 0
					}
				}
				if rangeWildcardIndex >= 0 {
					frontStartIndex := rangeWildcardIndex - frontDigitCount
					frontEndIndex := rangeWildcardIndex
					frontLeadingZeroStartIndex := frontStartIndex - frontLeadingZeroCount
					frontTotalDigitCount := frontDigitCount + frontLeadingZeroCount //the stuff that uses frontLeadingZeroCount needs to be sectioned off when singleIPv6
					if !stringFormatParams.GetRangeParameters().AllowsRangeSeparator() {
						return &addressStringException{str: str, key: "ipaddress.error.no.range"}
					} else if frontHexDelimiterIndex >= 0 && !isSingleSegment {
						return &addressStringException{str: str, key: "ipaddress.error.invalid.character.at.index", index: frontHexDelimiterIndex}
					} else if frontSingleWildcardCount > 0 || frontWildcardCount > 0 { // no wildcards in ranges
						return &addressStringException{str: str, key: "ipaddress.error.invalid.character.combination.at.index", index: rangeWildcardIndex}
					} else if isMac && !macSpecificOptions.AllowsShortSegments() && frontTotalDigitCount < 2 {
						return &addressStringException{str: str, key: "ipaddress.error.segment.too.short.at.index", index: frontLeadingZeroStartIndex}
					}
					var upperRadix uint32
					frontIsBinary := false
					var front, extendedFront uint64
					frontEmpty := frontStartIndex == frontEndIndex
					isReversed := false
					if frontEmpty {
						if !stringFormatParams.GetRangeParameters().AllowsInferredBoundary() {
							return &addressStringException{str: str, key: "ipaddress.error.empty.segment.at.index", index: index}
						}
						rangeFlags |= KEY_INFERRED_LOWER_BOUNDARY
					} else {
						if frontLeadingZeroCount == 1 && frontDigitCount == 17 && ipv6SpecificOptions.AllowsBinary() && isBinaryDelimiter(str, frontStartIndex) {
							// IPv6 binary - to avoid ambiguity, all binary digits must be present, and preceded by 0b.
							frontStartIndex++ // exclude the 'b' in 0b1100
							frontDigitCount-- // exclude the 'b'
							front, err = switchValue2(currentFrontValueHex, str, frontDigitCount)
							if err != nil {
								return err
							}
							upperRadix = 2          // radix
							rangeFlags = upperRadix // radix
							ipAddressParseData.setHasBinaryDigits(true)
							isReversed = front > value
							frontIsBinary = true
						} else if isSingleIPv6 { //We need this special block here because single ipv6 hex is 128 bits and cannot fit into a long
							if frontDigitCount == 129 { // binary
								frontStartIndex++       // exclude the 'b' in 0b1100
								frontDigitCount--       // exclude the 'b'
								upperRadix = 2          // radix
								upperRadix = rangeFlags // radix
								ipAddressParseData.setHasBinaryDigits(true)
								frontMidIndex := frontEndIndex - 64
								extendedFront = parseLong2(str, frontStartIndex, frontMidIndex)
								front = parseLong2(str, frontMidIndex, frontEndIndex)
							} else {
								frontMidIndex := frontEndIndex - 16
								if frontStartIndex < frontMidIndex {
									extendedFront = parseLong16(str, frontStartIndex, frontMidIndex)
									front = parseLong16(str, frontMidIndex, frontEndIndex)
								} else {
									front = currentFrontValueHex
								}
							}
							isReversed = (extendedFront > extendedValue) || (extendedFront == extendedValue && front > value)
						} else {
							if !stringFormatParams.AllowsLeadingZeros() && frontLeadingZeroCount > 0 {
								return &addressStringException{str: str, key: "ipaddress.error.segment.leading.zeros"}
							} else if checkCharCounts {
								if frontDigitCount > hexMaxChars {
									return &addressStringException{str: str, key: "ipaddress.error.segment.too.long.at.index", index: frontLeadingZeroStartIndex}
								} else if !stringFormatParams.AllowsUnlimitedLeadingZeros() && frontTotalDigitCount > hexMaxChars {
									return &addressStringException{str: str, key: "ipaddress.error.segment.too.long.at.index", index: frontLeadingZeroStartIndex}
								}
							}
							front = currentFrontValueHex
							isReversed = front > value
							extendedFront = 0
						}
					}
					backEndIndex := index
					if isReversed {
						if !stringFormatParams.GetRangeParameters().AllowsReverseRange() {
							return &addressStringException{str: str, key: "ipaddress.error.invalidRange"}
						}
						// switcheroo
						frontStartIndex, startIndex = startIndex, frontStartIndex
						frontEndIndex, backEndIndex = backEndIndex, frontEndIndex
						frontLeadingZeroStartIndex, segmentValueStartIndex = segmentValueStartIndex, frontLeadingZeroStartIndex
						front, value = value, front
						extendedFront, extendedValue = extendedValue, extendedFront
					}
					if isSingleIPv6 {
						assign6Attributes4Values2Flags(frontStartIndex, frontEndIndex, frontLeadingZeroStartIndex, startIndex, backEndIndex, segmentValueStartIndex,
							parseData, segCount, front, extendedFront, value, extendedValue, rangeFlags|KEY_RANGE_WILDCARD, upperRadix)
					} else {
						if !frontUppercase && !frontEmpty && !isReversed && !frontIsBinary {
							if leadingZeroCount == 0 && (flags&KEY_STANDARD_STR) != 0 && frontIsStandardRangeChar {
								rangeFlags |= KEY_STANDARD_RANGE_STR | KEY_STANDARD_STR
							} else {
								rangeFlags |= KEY_STANDARD_STR
							}
						}
						assign6Attributes2Values2Flags(frontStartIndex, frontEndIndex, frontLeadingZeroStartIndex, startIndex, backEndIndex, segmentValueStartIndex,
							parseData, segCount, front, value, rangeFlags|KEY_RANGE_WILDCARD, upperRadix)
					}
					rangeWildcardIndex = -1
				} else if !noValuesToSet {
					if isSingleIPv6 {
						assign3Attributes2Values1Flags(startIndex, index, segmentValueStartIndex, parseData, segCount, value, extendedValue, flags)
					} else {
						assign3Attributes1Values1Flags(startIndex, index, segmentValueStartIndex, parseData, segCount, value, flags)
					}
				}
				parseData.incrementSegmentCount()
				leadingZeroCount = 0
			}
			index++
			segmentValueStartIndex = index
			segmentStartIndex = segmentValueStartIndex
			// end of IPv6 and MAC segments
		} // end of all cases
	} // end of character loop
	return nil
}

func parsePortOrService(
	fullAddr string,
	zone Zone,
	validationOptions HostNameParameters,
	res *ParsedHostIdentifierStringQualifier,
	index,
	endIndex int) (err AddressStringException) {
	isPort := true
	var hasLetter, hasDigits, isAll bool
	var charCount, digitCount int
	var port int
	lastHyphen := -1
	charArray := chars
	for i := index; i < endIndex; i++ {
		c := fullAddr[i]
		if c >= '1' && c <= '9' {
			if isPort {
				digitCount++
				if digitCount > 5 { // 65535 is max
					isPort = false
				} else {
					hasDigits = true
					port = port*10 + int(charArray[c])
				}
			}
			charCount++
		} else if c == '0' {
			if isPort && hasDigits {
				digitCount++
				if digitCount > 5 { // 65535 is max
					isPort = false
				} else {
					port *= 10
				}
			}
			charCount++
		} else {
			//http://www.iana.org/assignments/port-numbers
			//valid service name chars:
			//https://tools.ietf.org/html/rfc6335#section-5.1
			//https://tools.ietf.org/html/rfc6335#section-10.1
			isPort = false
			isHyphen := c == '-'
			isAll = c == SegmentWildcard
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || isHyphen || isAll {
				if isHyphen {
					if i == index {
						err = &addressStringException{str: fullAddr, key: "ipaddress.host.error.invalid.service.hyphen.start"}
						return
					} else if i-1 == lastHyphen {
						err = &addressStringException{str: fullAddr, key: "ipaddress.host.error.invalid.service.hyphen.consecutive"}
						return
					} else if i == endIndex-1 {
						err = &addressStringException{str: fullAddr, key: "ipaddress.host.error.invalid.service.hyphen.end"}
						return
					}
					lastHyphen = i
				} else if isAll {
					if i > index {
						err = &addressStringException{str: fullAddr, key: "ipaddress.error.invalid.character.combination.at.index", index: i}
						return
					} else if i+1 < endIndex {
						err = &addressStringException{str: fullAddr, key: "ipaddress.error.invalid.character.combination.at.index", index: i + 1}
						return
					}
					hasLetter = true
					charCount++
					break
				} else {
					hasLetter = true
				}
				charCount++
			} else {
				err = &addressStringException{str: fullAddr, key: "ipaddress.host.error.invalid.port.service", index: i}
				return
			}
		}
	}
	if isPort {
		if !validationOptions.AllowsPort() {
			err = &addressStringException{str: fullAddr, key: "ipaddress.host.error.port"}
			return
		} else if port == 0 {
			err = &addressStringException{str: fullAddr, key: "ipaddress.host.error.invalidPort.no.digits"}
			return
		} else if port > 65535 {
			err = &addressStringException{str: fullAddr, key: "ipaddress.host.error.invalidPort.too.large"}
			return
		}
		res.zone = zone
		res.port = &port
		//res = &ParsedHostIdentifierStringQualifier{zone: zone, port: &port}
		return
	} else if !validationOptions.AllowsService() {
		err = &addressStringException{str: fullAddr, key: "ipaddress.host.error.service"}
		return
	} else if charCount == 0 {
		err = &addressStringException{str: fullAddr, key: "ipaddress.host.error.invalidService.no.chars"}
		return
	} else if charCount > 15 {
		err = &addressStringException{str: fullAddr, key: "ipaddress.host.error.invalidService.too.long"}
		return
	} else if !hasLetter {
		err = &addressStringException{str: fullAddr, key: "ipaddress.host.error.invalidService.no.letter"}
		return
	}
	res.zone = zone
	res.service = Service(fullAddr[index:endIndex])
	//res = &ParsedHostIdentifierStringQualifier{zone: zone, service: Service(fullAddr[index:endIndex])}xx
	return
}

func parseValidatedPrefix(
	result int,
	fullAddr string,
	zone Zone,
	validationOptions IPAddressStringParameters,
	res *ParsedHostIdentifierStringQualifier,
	digitCount,
	leadingZeros int,
	ipVersion IPVersion) (err AddressStringException) {
	if digitCount == 0 {
		//we know leadingZeroCount is > 0 since we have checked already if there were no characters at all
		leadingZeros--
		digitCount++
	}
	asIPv4 := ipVersion.isUnknown() && ipVersion.isIPv4()
	//tryCache := false
	if asIPv4 {
		if leadingZeros > 0 && !validationOptions.GetIPv4Parameters().AllowsPrefixLengthLeadingZeros() {
			err = &addressStringException{str: fullAddr, key: "ipaddress.error.ipv4.prefix.leading.zeros"}
			return
		}
		allowPrefixesBeyondAddressSize := validationOptions.GetIPv4Parameters().AllowsPrefixesBeyondAddressSize()
		if !allowPrefixesBeyondAddressSize && result > IPv4BitCount {
			if validationOptions.AllowsSingleSegment() {
				return //treat it as a single segment ipv4 mask
			}
			err = &addressStringException{str: fullAddr, key: "ipaddress.error.prefixSize"}
			return
		}
		//tryCache = result < len(PREFIX_CACHE)
	} else {
		if leadingZeros > 0 && !validationOptions.GetIPv6Parameters().AllowsPrefixLengthLeadingZeros() {
			err = &addressStringException{str: fullAddr, key: "ipaddress.error.ipv6.prefix.leading.zeros"}
			return
		}
		allowPrefixesBeyondAddressSize := validationOptions.GetIPv6Parameters().AllowsPrefixesBeyondAddressSize()
		if !allowPrefixesBeyondAddressSize && result > IPv6BitCount {
			err = &addressStringException{str: fullAddr, key: "ipaddress.error.prefixSize"}
			return
		}
		//tryCache = zone.IsEmpty() && result < len(PREFIX_CACHE)
	}
	//if tryCache {
	//	qual := PREFIX_CACHE[result]
	//	if qual == nil {
	//		qual = &ParsedHostIdentifierStringQualifier{networkPrefixLength: cacheBits(result)}xx
	//		PREFIX_CACHE[result] = qual
	//	}
	//	res = qual
	//	return
	//}
	//res = &ParsedHostIdentifierStringQualifier{networkPrefixLength: cacheBits(result), zone: zone}xx
	res.networkPrefixLength = cacheBits(result)
	res.zone = zone
	return
}

func validatePrefix(
	fullAddr string,
	zone Zone,
	validationOptions IPAddressStringParameters,
	hostValidationOptions HostNameParameters,
	res *ParsedHostIdentifierStringQualifier,
	index,
	endIndex int,
	ipVersion IPVersion) (isPrefix bool, err AddressStringException) {
	if index == len(fullAddr) {
		return
	}
	isPrefix = true
	//isPrefix := true
	prefixEndIndex := endIndex
	hasDigits := false
	var result, leadingZeros int
	charArray := chars
	//	var portQualifier *ParsedHostIdentifierStringQualifier
	for i := index; i < endIndex; i++ {
		c := fullAddr[i]
		if c >= '1' && c <= '9' {
			hasDigits = true
			result = result*10 + int(charArray[c])
		} else if c == '0' {
			if hasDigits {
				result *= 10
			} else {
				leadingZeros++
			}
		} else if c == PortSeparator && hostValidationOptions != nil &&
			(hostValidationOptions.AllowsPort() || hostValidationOptions.AllowsService()) && i > index {
			// check if we have a port or service.  If not, possibly an IPv6 mask.
			// Also, parsing for port first (rather than prefix) allows us to call
			// parseValidatedPrefix with the knowledge that whatever is supplied can only be a prefix.
			err = parsePortOrService(fullAddr, zone, hostValidationOptions, res, i+1, endIndex)
			//portQualifier, err = parsePortOrService(fullAddr, zone, hostValidationOptions, res, i+1, endIndex)
			if err != nil {
				return
			}
			prefixEndIndex = i
			break
		} else {
			isPrefix = false
			break
		}
	}
	//we treat as a prefix if all the characters were digits, even if there were too many, unless the mask options allow for inet_aton single segment
	if isPrefix {
		//prefixQualifier, perr := parseValidatedPrefix(result, fullAddr,
		//	zone, validationOptions, res, prefixEndIndex-index /* digitCount */, leadingZeros, ipVersion)
		err = parseValidatedPrefix(result, fullAddr,
			zone, validationOptions, res, prefixEndIndex-index /* digitCount */, leadingZeros, ipVersion)
		//if perr != nil {
		//	err = perr
		//	//return
		//}
		//if portQualifier != nil {
		//	portQualifier.overridePrefix(prefixQualifier)
		//	res = portQualifier
		//	return
		//}
		//res = prefixQualifier
		//return
	}
	return
}

func parseAddressQualifier(
	fullAddr string,
	validationOptions IPAddressStringParameters,
	hostValidationOptions HostNameParameters,
	ipAddressParseData *IPAddressParseData,
	endIndex int) (err AddressStringException) {
	qualifierIndex := ipAddressParseData.getQualifierIndex()
	addressIsEmpty := ipAddressParseData.getAddressParseData().isProvidingEmpty()
	ipVersion := ipAddressParseData.getProviderIPVersion()
	res := ipAddressParseData.getQualifier()
	if ipAddressParseData.hasPrefixSeparator() {
		return parsePrefix(fullAddr, noZone, validationOptions, hostValidationOptions,
			res, addressIsEmpty, qualifierIndex, endIndex, ipVersion)
	} else if ipAddressParseData.isZoned() {
		if ipAddressParseData.isBase85Zoned() && !ipAddressParseData.isProvidingBase85IPv6() {
			err = &addressStringException{str: fullAddr, key: "ipaddress.error.invalid.character.at.index", index: qualifierIndex - 1}
			return
		}
		if addressIsEmpty {
			err = &addressStringException{str: fullAddr, key: "ipaddress.error.only.zone"}
			return
		}
		return parseZone(fullAddr, validationOptions, res, addressIsEmpty, qualifierIndex, endIndex, ipVersion)
	}
	//res = NO_QUALIFIER
	return
}

func parseHostAddressQualifier(
	fullAddr string,
	validationOptions IPAddressStringParameters,
	hostValidationOptions HostNameParameters,
	isPrefixed,
	hasPort bool,
	ipAddressParseData *IPAddressParseData,
	qualifierIndex,
	endIndex int) (err AddressStringException) {
	res := ipAddressParseData.getQualifier()
	addressIsEmpty := ipAddressParseData.getAddressParseData().isProvidingEmpty()
	ipVersion := ipAddressParseData.getProviderIPVersion()
	if isPrefixed {
		return parsePrefix(fullAddr, noZone, validationOptions, hostValidationOptions,
			res, addressIsEmpty, qualifierIndex, endIndex, ipVersion)
	} else if ipAddressParseData.isZoned() {
		if addressIsEmpty {
			err = &addressStringException{str: fullAddr, key: "ipaddress.error.only.zone"}
			return
		}
		return parseEncodedZone(fullAddr, validationOptions, res, addressIsEmpty, qualifierIndex, endIndex, ipVersion)
	} else if hasPort { //isPort is always false when validating an address
		return parsePortOrService(fullAddr, noZone, hostValidationOptions, res, qualifierIndex, endIndex)
	}
	//res = NO_QUALIFIER
	return
}

func parsePrefix(
	fullAddr string,
	zone Zone,
	validationOptions IPAddressStringParameters,
	hostValidationOptions HostNameParameters,
	res *ParsedHostIdentifierStringQualifier,
	addressIsEmpty bool,
	index,
	endIndex int,
	ipVersion IPVersion) (err AddressStringException) {
	if validationOptions.AllowsPrefix() {
		//res, err = validatePrefix(fullAddr, zone, validationOptions, hostValidationOptions,
		//	index, endIndex, ipVersion)
		//if err != nil || res != nil {
		//	return
		//}
		var isPrefix bool
		isPrefix, err = validatePrefix(fullAddr, zone, validationOptions, hostValidationOptions,
			res, index, endIndex, ipVersion)
		if err != nil || isPrefix {
			return
		}
	}
	if addressIsEmpty {
		//PREFIX_ONLY must have a prefix and not a mask - we don't allow /255.255.0.0
		err = &addressStringException{str: fullAddr, key: "ipaddress.error.invalid.mask.address.empty"}
	} else if validationOptions.AllowsMask() {
		//check for a mask
		//check if we need a new validation options for the mask
		maskOptions := toMaskOptions(validationOptions, ipVersion)
		pa := &ParsedIPAddress{IPAddressParseData: IPAddressParseData{AddressParseData: AddressParseData{str: fullAddr}}, options: maskOptions}
		err = validateIPAddress(maskOptions, fullAddr, index, endIndex, pa.getIPAddressParseData(), false)
		if err != nil {
			err = WrapErrf(err, "ipaddress.error.invalidCIDRPrefixOrMask")
			return
		}
		maskParseData := pa.getAddressParseData()
		if maskParseData.isProvidingEmpty() {
			err = &addressStringException{str: fullAddr, key: "ipaddress.error.invalid.mask.empty"}
			return
		} else if maskParseData.isAll() {
			err = &addressStringException{str: fullAddr, key: "ipaddress.error.invalid.mask.wildcard"}
			return
		}
		err = checkSegments(fullAddr, maskOptions, pa.getIPAddressParseData())
		if err != nil {
			err = WrapErrf(err, "ipaddress.error.invalidCIDRPrefixOrMask")
			return
		}
		maskEndIndex := maskParseData.getAddressEndIndex()
		if maskEndIndex != endIndex { // 1.2.3.4/ or 1.2.3.4// or 1.2.3.4/%
			err = &addressStringException{str: fullAddr, key: "ipaddress.error.invalid.mask.extra.chars", index: maskEndIndex + 1}
			return
		}
		maskVersion := pa.getProviderIPVersion()
		if maskVersion.isIPv4() && maskParseData.getSegmentCount() == 1 && !maskParseData.hasWildcard() &&
			!validationOptions.GetIPv4Parameters().Allows_inet_aton_single_segment_mask() { //1.2.3.4/33 where 33 is an aton_inet single segment address and not a prefix length
			err = &addressStringException{str: fullAddr, key: "ipaddress.error.mask.single.segment"}
			return
		} else if !ipVersion.isUnknown() && (maskVersion.isIPv4() != ipVersion.isIPv4() || maskVersion.isIPv6() != ipVersion.isIPv6()) {
			//note that this also covers the cases of non-standard addresses in the mask, ie mask neither ipv4 or ipv6
			err = &addressStringException{str: fullAddr, key: "ipaddress.error.ipMismatch"}
			return
		}
		res.mask = pa
		res.zone = zone
		//res = &ParsedHostIdentifierStringQualifier{mask: pa, zone: zone}
	} else if validationOptions.AllowsPrefix() {
		err = &addressStringException{str: fullAddr, key: "ipaddress.error.invalidCIDRPrefixOrMask"}
	} else {
		err = &addressStringException{str: fullAddr, key: "ipaddress.error.CIDRNotAllowed"}
	}
	return
}

func parseHostNameQualifier(
	fullAddr string,
	validationOptions IPAddressStringParameters,
	hostValidationOptions HostNameParameters,
	res *ParsedHostIdentifierStringQualifier,
	isPrefixed,
	isPort, // always false for address
	addressIsEmpty bool,
	index,
	endIndex int,
	ipVersion IPVersion) (err AddressStringException) {
	if isPrefixed {
		return parsePrefix(fullAddr, noZone, validationOptions, hostValidationOptions,
			res, addressIsEmpty, index, endIndex, ipVersion)
	} else if isPort { // isPort is always false when validating an address
		return parsePortOrService(fullAddr, noZone, hostValidationOptions, res, index, endIndex)
	}
	//res = NO_QUALIFIER
	return
}

// ValidateZone returns the index of the first invalid character of the zone, or -1 if the zone is valid
func ValidateZone(zone Zone) int {
	for i := 0; i < len(zone); i++ {
		c := zone[i]
		if c == PrefixLenSeparator {
			return i
		}
		if c == IPv6SegmentSeparator {
			return i
		}
	}
	return -1
}

func isReserved(c byte) bool {
	isUnreserved :=
		(c >= '0' && c <= '9') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			c == RangeSeparator ||
			c == LabelSeparator ||
			c == '_' ||
			c == '~'
	return !isUnreserved
}

func parseZone(
	fullAddr string,
	validationOptions IPAddressStringParameters,
	res *ParsedHostIdentifierStringQualifier,
	addressIsEmpty bool,
	index,
	endIndex int,
	ipVersion IPVersion) (err AddressStringException) {
	for i := index; i < endIndex; i++ {
		c := fullAddr[i]
		if c == PrefixLenSeparator { //TODO you want to handle &/ here which it seems we do not
			zone := Zone(fullAddr[index:i])
			return parsePrefix(fullAddr, zone, validationOptions, nil, res, addressIsEmpty, i+1, endIndex, ipVersion)
		} else if c == IPv6SegmentSeparator {
			err = &addressStringException{str: fullAddr, key: "ipaddress.error.invalid.zone", index: i}
			return
		}
	}
	res.zone = Zone(fullAddr[index:endIndex])
	//res = &ParsedHostIdentifierStringQualifier{zone: Zone(fullAddr[index:endIndex])}xx
	return
}

func parseEncodedZone(
	fullAddr string,
	validationOptions IPAddressStringParameters,
	res *ParsedHostIdentifierStringQualifier,
	addressIsEmpty bool,
	index,
	endIndex int,
	ipVersion IPVersion) (err AddressStringException) {
	var result strings.Builder
	var zone string
	for i := index; i < endIndex; i++ {
		c := fullAddr[i]
		//we are in here when we have a square bracketed host like [::1]
		//not if we have a HostName with no brackets

		//https://tools.ietf.org/html/rfc6874
		//https://tools.ietf.org/html/rfc4007#section-11.7
		if c == IPv6ZoneSeparator {
			if i+2 >= endIndex {
				err = &addressStringException{str: fullAddr, key: "ipaddress.error.invalid.zone.encoding", index: i}
				return
			}
			//percent encoded
			if result.Cap() == 0 {
				result.Grow(endIndex - index)
				result.WriteString(fullAddr[index:i])
			}
			charArray := chars
			i++
			c = byte(charArray[fullAddr[i]]) << 4
			i++
			c |= byte(charArray[fullAddr[i]])
		} else if c == PrefixLenSeparator {
			if result.Len() > 0 {
				zone = result.String()
			} else {
				zone = fullAddr[index:i]
			}
			return parsePrefix(fullAddr, Zone(zone), validationOptions, nil, res, addressIsEmpty, i+1, endIndex, ipVersion)
		} else if isReserved(c) {
			err = &addressStringException{str: fullAddr, key: "ipaddress.error.invalid.zone", index: i}
			return
		}
		if result.Len() > 0 {
			result.WriteByte(c)
		}
	}
	if result.Len() == 0 {
		zone = fullAddr[index:endIndex]
		//res = &ParsedHostIdentifierStringQualifier{zone: Zone(fullAddr[index:endIndex])}xx
	} else {
		zone = result.String()
		//res = &ParsedHostIdentifierStringQualifier{zone: Zone(result.String())}xx
	}
	res.zone = Zone(zone)
	return
}

/**
 * Some options are not supported in masks (prefix, wildcards, etc)
 * So we eliminate those options while preserving the others from the address options.
 * @param validationOptions
 * @param ipVersion
 * @return
 */
func toMaskOptions(validationOptions IPAddressStringParameters,
	ipVersion IPVersion) (res IPAddressStringParameters) {
	//We must provide options that do not allow a mask with wildcards or ranges
	var builder *IPAddressStringParametersBuilder
	if ipVersion.isUnknown() || ipVersion.isIPv6() {
		ipv6Options := validationOptions.GetIPv6Parameters()
		if !ipv6Options.GetRangeParameters().IsNoRange() {
			builder = ToIPAddressStringParamsBuilder(validationOptions)
			builder.GetIPv6AddressParametersBuilder().SetRangeParameters(NO_RANGE)
		}
		if ipv6Options.AllowsMixed() && !ipv6Options.GetMixedParameters().GetIPv4Parameters().GetRangeParameters().IsNoRange() {
			if builder == nil {
				builder = ToIPAddressStringParamsBuilder(validationOptions)
			}
			builder.GetIPv6AddressParametersBuilder().SetRangeParameters(NO_RANGE)
		}
	}
	if ipVersion.isUnknown() || ipVersion.isIPv4() {
		ipv4Options := validationOptions.GetIPv4Parameters()
		if !ipv4Options.GetRangeParameters().IsNoRange() {
			if builder == nil {
				builder = ToIPAddressStringParamsBuilder(validationOptions)
			}
			builder.GetIPv4AddressParametersBuilder().SetRangeParameters(NO_RANGE)
		}
	}
	if validationOptions.AllowsAll() {
		if builder == nil {
			builder = ToIPAddressStringParamsBuilder(validationOptions)
		}
		builder.AllowAll(false)
	}
	if builder == nil {
		res = validationOptions
	} else {
		res = builder.ToParams()
	}
	return
}

func assign3Attributes(start, end int, parseData *AddressParseData, parsedSegIndex, leadingZeroStartIndex int) {
	ustart := uint32(start)
	uend := uint32(end)
	uleadingZeroStart := uint32(leadingZeroStartIndex)
	parseData.setIndex(parsedSegIndex,
		KEY_LOWER_STR_DIGITS_INDEX, uleadingZeroStart,
		KEY_LOWER_STR_START_INDEX, ustart,
		KEY_LOWER_STR_END_INDEX, uend,
		KEY_UPPER_STR_DIGITS_INDEX, uleadingZeroStart,
		KEY_UPPER_STR_START_INDEX, ustart,
		KEY_UPPER_STR_END_INDEX, uend)
}

func assign4Attributes(start, end int, parseData *AddressParseData, parsedSegIndex, radix, leadingZeroStartIndex int) {
	ustart := uint32(start)
	uend := uint32(end)
	uleadingZeroStart := uint32(leadingZeroStartIndex)
	parseData.set7IndexFlags(parsedSegIndex,
		KEY_LOWER_RADIX_INDEX, uint32(radix),
		KEY_LOWER_STR_DIGITS_INDEX, uleadingZeroStart,
		KEY_LOWER_STR_START_INDEX, ustart,
		KEY_LOWER_STR_END_INDEX, uend,
		KEY_UPPER_STR_DIGITS_INDEX, uleadingZeroStart,
		KEY_UPPER_STR_START_INDEX, ustart,
		KEY_UPPER_STR_END_INDEX, uend)
}

func assign6Attributes4Values2Flags(frontStart, frontEnd, frontLeadingZeroStartIndex, start, end, leadingZeroStartIndex int,
	parseData *AddressParseData, parsedSegIndex int, frontValue, frontExtendedValue, value, extendedValue uint64, flags uint32, upperRadix uint32) {
	parseData.set8Index4ValuesFlags(parsedSegIndex,
		FLAGS_INDEX, flags,
		KEY_LOWER_STR_DIGITS_INDEX, uint32(frontLeadingZeroStartIndex),
		KEY_LOWER_STR_START_INDEX, uint32(frontStart),
		KEY_LOWER_STR_END_INDEX, uint32(frontEnd),
		KEY_UPPER_RADIX_INDEX, uint32(upperRadix),
		KEY_UPPER_STR_DIGITS_INDEX, uint32(leadingZeroStartIndex),
		KEY_UPPER_STR_START_INDEX, uint32(start),
		KEY_UPPER_STR_END_INDEX, uint32(end),
		KEY_LOWER, frontValue,
		KEY_EXTENDED_LOWER, frontExtendedValue,
		KEY_UPPER, value,
		KEY_EXTENDED_UPPER, extendedValue)
}

func assign6Attributes4Values1Flags(frontStart, frontEnd, frontLeadingZeroStartIndex, start, end, leadingZeroStartIndex int,
	parseData *AddressParseData, parsedSegIndex int, frontValue, frontExtendedValue, value, extendedValue uint64, flags uint32) {
	parseData.set7Index4ValuesFlags(parsedSegIndex,
		FLAGS_INDEX, flags,
		KEY_LOWER_STR_DIGITS_INDEX, uint32(frontLeadingZeroStartIndex),
		KEY_LOWER_STR_START_INDEX, uint32(frontStart),
		KEY_LOWER_STR_END_INDEX, uint32(frontEnd),
		KEY_UPPER_STR_DIGITS_INDEX, uint32(leadingZeroStartIndex),
		KEY_UPPER_STR_START_INDEX, uint32(start),
		KEY_UPPER_STR_END_INDEX, uint32(end),
		KEY_LOWER, frontValue,
		KEY_EXTENDED_LOWER, frontExtendedValue,
		KEY_UPPER, value,
		KEY_EXTENDED_UPPER, extendedValue)
}

func assign6Attributes2Values1Flags(frontStart, frontEnd, frontLeadingZeroStartIndex, start, end, leadingZeroStartIndex int,
	parseData *AddressParseData, parsedSegIndex int, frontValue, value uint64, flags uint32) {
	parseData.set7Index2ValuesFlags(parsedSegIndex,
		FLAGS_INDEX, flags,
		KEY_LOWER_STR_DIGITS_INDEX, uint32(frontLeadingZeroStartIndex),
		KEY_LOWER_STR_START_INDEX, uint32(frontStart),
		KEY_LOWER_STR_END_INDEX, uint32(frontEnd),
		KEY_UPPER_STR_DIGITS_INDEX, uint32(leadingZeroStartIndex),
		KEY_UPPER_STR_START_INDEX, uint32(start),
		KEY_UPPER_STR_END_INDEX, uint32(end),
		KEY_LOWER, frontValue,
		KEY_UPPER, value)
}

func assign6Attributes2Values2Flags(frontStart, frontEnd, frontLeadingZeroStartIndex, start, end, leadingZeroStartIndex int,
	parseData *AddressParseData, parsedSegIndex int, frontValue, value uint64, flags /* includes lower radix */ uint32, upperRadix uint32) {
	parseData.set8Index2ValuesFlags(parsedSegIndex,
		FLAGS_INDEX, flags,
		KEY_LOWER_STR_DIGITS_INDEX, uint32(frontLeadingZeroStartIndex),
		KEY_LOWER_STR_START_INDEX, uint32(frontStart),
		KEY_LOWER_STR_END_INDEX, uint32(frontEnd),
		KEY_UPPER_RADIX_INDEX, uint32(upperRadix),
		KEY_UPPER_STR_DIGITS_INDEX, uint32(leadingZeroStartIndex),
		KEY_UPPER_STR_START_INDEX, uint32(start),
		KEY_UPPER_STR_END_INDEX, uint32(end),
		KEY_LOWER, frontValue,
		KEY_UPPER, value)
}

func assign3Attributes2Values1Flags(start, end, leadingZeroStart int,
	parseData *AddressParseData, parsedSegIndex int, value, extendedValue uint64, flags uint32) {
	ustart := uint32(start)
	uend := uint32(end)
	uleadingZeroStart := uint32(leadingZeroStart)
	parseData.set7Index4ValuesFlags(parsedSegIndex,
		FLAGS_INDEX, flags,
		KEY_LOWER_STR_DIGITS_INDEX, uleadingZeroStart,
		KEY_LOWER_STR_START_INDEX, ustart,
		KEY_LOWER_STR_END_INDEX, uend,
		KEY_UPPER_STR_DIGITS_INDEX, uleadingZeroStart,
		KEY_UPPER_STR_START_INDEX, ustart,
		KEY_UPPER_STR_END_INDEX, uend,
		KEY_LOWER, value,
		KEY_EXTENDED_LOWER, extendedValue,
		KEY_UPPER, value,
		KEY_EXTENDED_UPPER, extendedValue)
}

func assign3Attributes1Values1Flags(start, end, leadingZeroStart int,
	parseData *AddressParseData, parsedSegIndex int, value uint64, flags uint32) {
	ustart := uint32(start)
	uend := uint32(end)
	uleadingZeroStart := uint32(leadingZeroStart)
	parseData.set7Index2ValuesFlags(parsedSegIndex,
		FLAGS_INDEX, flags,
		KEY_UPPER_STR_DIGITS_INDEX, uleadingZeroStart,
		KEY_LOWER_STR_DIGITS_INDEX, uleadingZeroStart,
		KEY_UPPER_STR_START_INDEX, ustart,
		KEY_LOWER_STR_START_INDEX, ustart,
		KEY_UPPER_STR_END_INDEX, uend,
		KEY_LOWER_STR_END_INDEX, uend,
		KEY_LOWER, value,
		KEY_UPPER, value)
}

func isBinaryDelimiter(str string, index int) bool {
	c := str[index]
	return c == 'b' || c == 'B'
}

func isHexDelimiter(c byte) bool {
	return c == 'x' || c == 'X'
}

func parseBase85(
	validationOptions IPAddressStringParameters,
	str string,
	strStartIndex,
	strEndIndex int,
	ipAddressParseData *IPAddressParseData,
	extendedRangeWildcardIndex,
	totalCharacterCount,
	index int) (bool, AddressStringException) {
	//TODO parseBase85
	//AddressParseData parseData = ipAddressParseData.getAddressParseData();
	//if(extendedRangeWildcardIndex < 0) {
	//	if(totalCharacterCount == IPV6_BASE85_SINGLE_SEGMENT_DIGIT_COUNT) {
	//		if(!validationOptions.allowIPv6) {
	//			throw new AddressStringException(str, "ipaddress.error.ipv6");
	//		}
	//		ipAddressParseData.setVersion(IPVersion.IPV6);
	//		BigInteger val = parseBase85(str, strStartIndex, strEndIndex);
	//		long value = val.and(LOW_BITS_MASK).longValue();
	//		BigInteger shift64 = val.shiftRight(Long.SIZE);
	//		long extendedValue = shift64.longValue();
	//		//note that even with the correct number of digits, we can have a value too large
	//		BigInteger shiftMore = shift64.shiftRight(Long.SIZE);
	//		if(!shiftMore.equals(BigInteger.ZERO)) {
	//			throw new AddressStringException(str, "ipaddress.error.address.too.large");
	//		}
	//		parseData.initSegmentData(1);
	//		parseData.incrementSegmentCount();
	//		assignAttributesValuesFlags(strStartIndex, strEndIndex, strStartIndex, parseData, 0, value, extendedValue, IPv6Address.BASE_85_RADIX);
	//		ipAddressParseData.setBase85(true);
	//		return true;
	//	}
	//} else {
	//	if(totalCharacterCount == (IPV6_BASE85_SINGLE_SEGMENT_DIGIT_COUNT << 1) + 1 /* two base 85 addresses */ ||
	//			(totalCharacterCount == IPV6_BASE85_SINGLE_SEGMENT_DIGIT_COUNT + 1 &&
	//			(extendedRangeWildcardIndex == 0 || extendedRangeWildcardIndex + 1 == strEndIndex)) /* inferred boundary */) {/* note that we already check that extendedRangeWildcardIndex is at index 20 */
	//		if(!validationOptions.allowIPv6) {
	//			throw new AddressStringException(str, "ipaddress.error.ipv6");
	//		}
	//		IPv6AddressStringParameters ipv6SpecificOptions = validationOptions.getIPv6Parameters();
	//		if(!ipv6SpecificOptions.rangeOptions.allowsRangeSeparator()) {
	//			throw new AddressStringException(str, "ipaddress.error.no.range");
	//		}
	//		ipAddressParseData.setVersion(IPVersion.IPV6);
	//		int frontEndIndex = extendedRangeWildcardIndex, flags = 0;
	//		long value, value2, extendedValue, extendedValue2;
	//		int lowerStart, lowerEnd, upperStart, upperEnd;
	//
	//		if(frontEndIndex == strStartIndex + IPV6_BASE85_SINGLE_SEGMENT_DIGIT_COUNT) {
	//			BigInteger val = parseBase85(str, strStartIndex, frontEndIndex);
	//			value = val.and(LOW_BITS_MASK).longValue();
	//			BigInteger shift64 = val.shiftRight(Long.SIZE);
	//			extendedValue = shift64.longValue();
	//			if(frontEndIndex + 1 < strEndIndex) {
	//				BigInteger val2 = parseBase85(str, frontEndIndex + 1, strEndIndex);
	//				value2 = val2.and(LOW_BITS_MASK).longValue();
	//				shift64 = val2.shiftRight(Long.SIZE);
	//				extendedValue2 = shift64.longValue();
	//				BigInteger shiftMoreVal2 = shift64.shiftRight(Long.SIZE);
	//
	//				if(val.compareTo(val2) > 0) {
	//					BigInteger shiftMoreVal = shift64.shiftRight(Long.SIZE);
	//					if(!ipv6SpecificOptions.rangeOptions.allowsReverseRange()) {
	//						throw new AddressStringException(str, "ipaddress.error.invalidRange");
	//					} else if(!shiftMoreVal.equals(BigInteger.ZERO)) {
	//						throw new AddressStringException(str, "ipaddress.error.address.too.large");
	//					}
	//					lowerStart = frontEndIndex + 1;
	//					lowerEnd = strEndIndex;
	//					upperStart = strStartIndex;
	//					upperEnd = frontEndIndex;
	//				} else {
	//					if(!shiftMoreVal2.equals(BigInteger.ZERO)) {
	//						throw new AddressStringException(str, "ipaddress.error.address.too.large");
	//					}
	//					lowerStart = strStartIndex;
	//					lowerEnd = frontEndIndex;
	//					upperStart = frontEndIndex + 1;
	//					upperEnd = strEndIndex;
	//				}
	//			} else {
	//				if(!ipv6SpecificOptions.rangeOptions.allowsInferredBoundary()) {
	//					throw new AddressStringException(str, "ipaddress.error.empty.segment.at.index", index);
	//				}
	//				lowerStart = strStartIndex;
	//				lowerEnd = frontEndIndex;
	//				upperStart = upperEnd = strEndIndex;
	//				value2 = extendedValue2 = -1;
	//				flags = AddressParseData.KEY_INFERRED_UPPER_BOUNDARY;
	//			}
	//		} else if(frontEndIndex == 0) {
	//			if(!ipv6SpecificOptions.rangeOptions.allowsInferredBoundary()) {
	//				throw new AddressStringException(str, "ipaddress.error.empty.segment.at.index", index);
	//			}
	//			lowerStart = lowerEnd = 0;
	//			value = extendedValue = 0;
	//			flags = AddressParseData.KEY_INFERRED_LOWER_BOUNDARY;
	//			BigInteger val2 = parseBase85(str, frontEndIndex + 1, strEndIndex);
	//			value2 = val2.and(LOW_BITS_MASK).longValue();
	//			BigInteger shift64 = val2.shiftRight(Long.SIZE);
	//			extendedValue2 = shift64.longValue();
	//			BigInteger shiftMoreVal2 = shift64.shiftRight(Long.SIZE);
	//			if(!shiftMoreVal2.equals(BigInteger.ZERO)) {
	//				throw new AddressStringException(str, "ipaddress.error.address.too.large");
	//			}
	//			upperStart = 1;
	//			upperEnd = strEndIndex;
	//		} else {
	//			throw new AddressStringException(str, extendedRangeWildcardIndex);
	//		}
	//		parseData.incrementSegmentCount();
	//		parseData.initSegmentData(1);
	//		//parseData.setHasRange();
	//		assignAttributesValuesFlags(lowerStart, lowerEnd, lowerStart, upperStart, upperEnd, upperStart,
	//				parseData, 0, value, extendedValue, value2, extendedValue2,
	//				AddressParseData.KEY_RANGE_WILDCARD | IPv6Address.BASE_85_RADIX | flags, IPv6Address.BASE_85_RADIX);
	//		ipAddressParseData.setBase85(true);
	//		return true;
	//	}
	//}
	return false, nil
}

func chooseMACAddressProvider(fromString *MACAddressString,
	validationOptions MACAddressStringParameters, pa *ParsedMACAddress,
	addressParseData *AddressParseData) (res MACAddressProvider, err AddressStringException) {
	if addressParseData.isProvidingEmpty() {
		res = macAddressEmptyProvider
	} else if addressParseData.isAll() {
		if validationOptions == defaultMACAddrParameters {
			res = macAddressDefaultAllProvider
		} else {
			res = MACAddressAllProvider{validationOptions}
		}
	} else {
		err = checkMACSegments(
			fromString.str,
			fromString.params,
			pa)
		res = pa
	}
	return
}

var MASK_CACHE = [3][IPv6BitCount + 1]MaskCreator{}
var LOOPBACK_CACHE = &LoopbackCreator{VersionedAddressCreator: VersionedAddressCreator{parameters: defaultIPAddrParameters}}

func init() {
	for i := 0; i < 3; i++ {
		var version IPVersion
		if i == 1 {
			version = IPv4
		} else if i == 2 {
			version = IPv6
		}
		for j := 0; j < len(MASK_CACHE[i]); j++ {
			var cache = &MASK_CACHE[i][j]
			cache.adjustedVersion = version
			bc := BitCount(j)
			cache.networkPrefixLength = &bc
			cache.parameters = defaultIPAddrParameters
			//TODO maybe we initialize to masks right away?
			//GOtta be sure the network masks are ready.  Maybe we need to do it from that code.
			// Probably ok to do it from here if there is no reverse dependency (oh, but there is, this file is needed to create the masks?  No, they are not created from strings)
		}
	}
}

func chooseIPAddressProvider(
	originator HostIdentifierString,
	fullAddr string,
	validationOptions *ipAddressStringParameters,
	parseData *ParsedIPAddress) (res IPAddressProvider, err AddressStringException) {
	qualifier := parseData.getQualifier()
	version := parseData.getProviderIPVersion()
	if version.isUnknown() {
		version = qualifier.inferVersion(validationOptions)
		optionsVersion := validationOptions.inferVersion()
		if version.isUnknown() {
			version = optionsVersion
			parseData.setVersion(version)
		} else if !optionsVersion.isUnknown() && version != optionsVersion {
			var key string
			if version.isIPv6() {
				key = "ipaddress.error.ipv6"
			} else {
				key = "ipaddress.error.ipv4"
			}
			err = &addressStringException{str: fullAddr, key: key}
			return
		}
		addressParseData := parseData.getAddressParseData()
		if addressParseData.isProvidingEmpty() {
			networkPrefixLength := qualifier.getNetworkPrefixLength()
			if networkPrefixLength != nil {
				prefLen := *networkPrefixLength
				if validationOptions == defaultIPAddrParameters && *networkPrefixLength <= IPv6BitCount {
					index := 0
					if version.isIPv4() {
						index = 1
					} else if version.isIPv6() {
						index = 2
					}
					res = &MASK_CACHE[index][prefLen]
					return
				}
				//return new MaskCreator(networkPrefixLength, version, validationOptions);
				res = &MaskCreator{AdjustedAddressCreator: AdjustedAddressCreator{adjustedVersion: version, networkPrefixLength: networkPrefixLength, VersionedAddressCreator: VersionedAddressCreator{parameters: validationOptions, ipAddrProvider: ipAddrProvider{ipType: PREFIX_ONLY}}}}
				return
			} else {
				//Note: we do not support loopback with zone, it seems the loopback is never associated with a link-local zone
				if validationOptions.EmptyIsLoopback() {
					if validationOptions == defaultIPAddrParameters {
						res = LOOPBACK_CACHE
						return
					}
					res = &LoopbackCreator{VersionedAddressCreator: VersionedAddressCreator{parameters: validationOptions}}
					return
				}
				res = EMPTY_PROVIDER
				return
			}
		} else { //isAll
			//We also need the AllCreator to use the equivalent prefix length, much like in ParsedIPAddress
			res = &AllCreator{AdjustedAddressCreator: AdjustedAddressCreator{adjustedVersion: version, VersionedAddressCreator: VersionedAddressCreator{parameters: validationOptions, ipAddrProvider: ipAddrProvider{ipType: ALL}}},
				originator: originator, qualifier: *qualifier}
			//qualifier, version, originator, validationOptions);
			return
		}
	} else {
		if parseData.isZoned() && version.isIPv4() {
			err = &addressStringException{str: fullAddr, key: "ipaddress.error.only.ipv6.has.zone"}
			return
		}
		//parseData.setQualifier(qualifier);
		err = checkSegments(fullAddr, validationOptions, parseData.getIPAddressParseData())
		res = parseData
	}
	return
}

func checkSegmentMaxValues(
	fullAddr string,
	parseData *AddressParseData,
	segmentIndex int,
	params AddressStringFormatParameters,
	maxValue uint64,
	maxDigitCount,
	maxUpperDigitCount int) AddressStringException {
	if parseData.getFlag(segmentIndex, KEY_SINGLE_WILDCARD) {
		value := parseData.getValue(segmentIndex, KEY_LOWER)
		if value > maxValue {
			return &addressStringException{str: fullAddr, key: "ipaddress.error.ipv4.segment.too.large"}
		}
		if parseData.getValue(segmentIndex, KEY_UPPER) > maxValue {
			parseData.setValue(segmentIndex, KEY_UPPER, maxValue)
		}
		if !params.AllowsUnlimitedLeadingZeros() {
			lowerRadix := parseData.getRadix(segmentIndex, KEY_LOWER_RADIX_INDEX)
			if parseData.getIndex(segmentIndex, KEY_LOWER_STR_END_INDEX)-parseData.getIndex(segmentIndex, KEY_LOWER_STR_DIGITS_INDEX)-getStringPrefixCharCount(lowerRadix) > maxDigitCount {
				return &addressStringException{str: fullAddr, key: "ipaddress.error.segment.too.long"}
			}
		}
	} else {
		value := parseData.getValue(segmentIndex, KEY_UPPER)
		if value > maxValue {
			return &addressStringException{str: fullAddr, key: "ipaddress.error.ipv4.segment.too.large"}
		}
		if !params.AllowsUnlimitedLeadingZeros() {
			lowerRadix := parseData.getRadix(segmentIndex, KEY_LOWER_RADIX_INDEX)
			lowerEndIndex := parseData.getIndex(segmentIndex, KEY_LOWER_STR_END_INDEX)
			upperEndIndex := parseData.getIndex(segmentIndex, KEY_UPPER_STR_END_INDEX)
			if lowerEndIndex-parseData.getIndex(segmentIndex, KEY_LOWER_STR_DIGITS_INDEX)-getStringPrefixCharCount(lowerRadix) > maxDigitCount {
				return &addressStringException{str: fullAddr, key: "ipaddress.error.segment.too.long"}
			}
			if lowerEndIndex != upperEndIndex {
				upperRadix := parseData.getRadix(segmentIndex, KEY_UPPER_RADIX_INDEX)
				if upperEndIndex-parseData.getIndex(segmentIndex, KEY_UPPER_STR_DIGITS_INDEX)-getStringPrefixCharCount(upperRadix) > maxUpperDigitCount {
					return &addressStringException{str: fullAddr, key: "ipaddress.error.segment.too.long"}
				}
			}
		}
	}
	return nil
}

func checkMACSegments(
	fullAddr string,
	validationOptions MACAddressStringParameters,
	parseData *ParsedMACAddress) AddressStringException {
	var err error
	format := parseData.getFormat()
	if format != UNKNOWN_FORMAT {
		addressParseData := parseData.getAddressParseData()
		hasWildcardSeparator := addressParseData.hasWildcard() && validationOptions.GetFormatParameters().AllowsWildcardedSeparator()
		//note that too many segments is checked inside the general parsing method
		segCount := addressParseData.getSegmentCount()
		if format == DOTTED {
			if segCount <= MediaAccessControlDottedSegmentCount && validationOptions.AddressSize() != EUI64 {
				if !hasWildcardSeparator && segCount != MediaAccessControlDottedSegmentCount {
					return &addressStringException{str: fullAddr, key: "ipaddress.error.too.few.segments"}
				}
			} else if !hasWildcardSeparator && segCount < MediaAccessControlDotted64SegmentCount {
				return &addressStringException{str: fullAddr, key: "ipaddress.error.too.few.segments"}
			} else {
				parseData.setExtended(true)
			}
		} else if segCount > 2 {
			if segCount <= MediaAccessControlSegmentCount && validationOptions.AddressSize() != EUI64 {
				if !hasWildcardSeparator && segCount != MediaAccessControlSegmentCount {
					return &addressStringException{str: fullAddr, key: "ipaddress.error.too.few.segments"}
				}
			} else if !hasWildcardSeparator && segCount < ExtendedUniqueIdentifier64SegmentCount {
				return &addressStringException{str: fullAddr, key: "ipaddress.error.too.few.segments"}
			} else {
				parseData.setExtended(true)
			}
			// we do not check char counts in the main parsing code for dashed, because we allow both
			// aabbcc-ddeeff and aa-bb-cc-dd-ee-ff, so we defer to the check until here
			if parseData.getFormat() == DASHED {
				for i := 0; i < segCount; i++ {
					err = checkSegmentMaxValues(
						fullAddr,
						addressParseData,
						i,
						validationOptions.GetFormatParameters(),
						MACMaxValuePerSegment,
						MACSegmentMaxChars,
						MACSegmentMaxChars)
					if err != nil {
						return err
					}
				}
			}
		} else {
			if parseData.getFormat() == DASHED {
				//for single segment, we have already counted the exact number of hex digits
				//for double segment, we have already counted the exact number of hex digits in some cases and not others.
				//Basically, for address like a-b we have already counted the exact number of hex digits,
				//for addresses starting with a|b- or a-b| we have not,
				//but rather than figure out which are checked and which are not it's just as quick to check them all here
				if parseData.isDoubleSegment() {
					params := validationOptions.GetFormatParameters()
					err = checkSegmentMaxValues(fullAddr, addressParseData, 0, params, macMaxTriple, MAC_DOUBLE_SEGMENT_DIGIT_COUNT, MAC_DOUBLE_SEGMENT_DIGIT_COUNT)
					if err != nil {
						return err
					}
					if parseData.isExtended() {
						err = checkSegmentMaxValues(fullAddr, addressParseData, 1, params, macMaxQuintuple, MAC_EXTENDED_DOUBLE_SEGMENT_DIGIT_COUNT, MAC_EXTENDED_DOUBLE_SEGMENT_DIGIT_COUNT)
					} else {
						err = checkSegmentMaxValues(fullAddr, addressParseData, 1, params, macMaxTriple, MAC_DOUBLE_SEGMENT_DIGIT_COUNT, MAC_DOUBLE_SEGMENT_DIGIT_COUNT)
					}
					if err != nil {
						return err
					}
				}
			} else if !hasWildcardSeparator {
				return &addressStringException{str: fullAddr, key: "ipaddress.error.too.few.segments"}
			}
			if validationOptions.AddressSize() == EUI64 {
				parseData.setExtended(true)
			}
		}
	} //else single segment
	return nil
}

func checkSegments(
	fullAddr string,
	validationOptions IPAddressStringParameters,
	parseData *IPAddressParseData) AddressStringException {
	addressParseData := parseData.getAddressParseData()
	segCount := addressParseData.getSegmentCount()
	version := parseData.getProviderIPVersion()
	if version.isIPv4() {
		missingCount := IPv4SegmentCount - segCount
		ipv4Options := validationOptions.GetIPv4Parameters()
		hasWildcardSeparator := addressParseData.hasWildcard() && ipv4Options.AllowsWildcardedSeparator()

		//single segments are handled in the parsing code with the allowSingleSegment setting
		if missingCount > 0 && segCount > 1 {
			if ipv4Options.Allows_inet_aton_joinedSegments() {
				parseData.set_inet_aton_joined(true)
			} else if !hasWildcardSeparator {
				return &addressStringException{str: fullAddr, key: "ipaddress.error.ipv4.too.few.segments"}
			}
		}

		//here we check whether values are too large
		notUnlimitedLength := !ipv4Options.AllowsUnlimitedLeadingZeros()
		hasMissingSegs := missingCount > 0 && ipv4Options.Allows_inet_aton_joinedSegments()
		for i := 0; i < segCount; i++ {
			var max uint64
			if hasMissingSegs && i == segCount-1 {
				max = getMaxIPv4Value(missingCount + 1)
				if addressParseData.isInferredUpperBoundary(i) {
					parseData.setValue(i, KEY_UPPER, max)
					continue
				}
			} else {
				max = IPv4MaxValuePerSegment
			}
			if parseData.getFlag(i, KEY_SINGLE_WILDCARD) {
				var value uint64 = parseData.getValue(i, KEY_LOWER)
				if value > max {
					return &addressStringException{str: fullAddr, key: "ipaddress.error.ipv4.segment.too.large"}
				}
				if parseData.getValue(i, KEY_UPPER) > max {
					parseData.setValue(i, KEY_UPPER, max)
				}
				if notUnlimitedLength {
					lowerRadix := addressParseData.getRadix(i, KEY_LOWER_RADIX_INDEX)
					maxDigitCount := getMaxIPv4StringLength(missingCount, lowerRadix)
					if parseData.getIndex(i, KEY_LOWER_STR_END_INDEX)-parseData.getIndex(i, KEY_LOWER_STR_DIGITS_INDEX)-getStringPrefixCharCount(lowerRadix) > maxDigitCount {
						return &addressStringException{str: fullAddr, key: "ipaddress.error.segment.too.long"}
					}
				}
			} else {
				var value uint64 = parseData.getValue(i, KEY_UPPER)
				if value > max {
					return &addressStringException{str: fullAddr, key: "ipaddress.error.ipv4.segment.too.large"}
				}
				if notUnlimitedLength {
					lowerRadix := addressParseData.getRadix(i, KEY_LOWER_RADIX_INDEX)
					maxDigitCount := getMaxIPv4StringLength(missingCount, lowerRadix)
					lowerEndIndex := parseData.getIndex(i, KEY_LOWER_STR_END_INDEX)
					upperEndIndex := parseData.getIndex(i, KEY_UPPER_STR_END_INDEX)
					if lowerEndIndex-parseData.getIndex(i, KEY_LOWER_STR_DIGITS_INDEX)-getStringPrefixCharCount(lowerRadix) > maxDigitCount {
						return &addressStringException{str: fullAddr, key: "ipaddress.error.segment.too.long"}
					}
					if lowerEndIndex != upperEndIndex {
						upperRadix := parseData.getRadix(i, KEY_UPPER_RADIX_INDEX)
						maxUpperDigitCount := getMaxIPv4StringLength(missingCount, upperRadix)
						if upperEndIndex-parseData.getIndex(i, KEY_UPPER_STR_DIGITS_INDEX)-getStringPrefixCharCount(upperRadix) > maxUpperDigitCount {
							return &addressStringException{str: fullAddr, key: "ipaddress.error.segment.too.long"}
						}
					}
				}
			}
		}
	} else {
		totalSegmentCount := segCount
		if parseData.isProvidingMixedIPv6() {
			totalSegmentCount += IPv6MixedReplacedSegmentCount
		}
		hasWildcardSeparator := addressParseData.hasWildcard() && validationOptions.GetIPv6Parameters().AllowsWildcardedSeparator()
		if !hasWildcardSeparator && totalSegmentCount != 1 && totalSegmentCount < IPv6SegmentCount && !parseData.isCompressed() {
			return &addressStringException{str: fullAddr, key: "ipaddress.error.too.few.segments"}
		}
	}
	return nil
}

func checkSingleWildcard(str string, start, end, digitsEnd int, options AddressStringFormatParameters) AddressStringException {
	if !options.GetRangeParameters().AllowsSingleWildcard() {
		return &addressStringException{str: str, key: "ipaddress.error.no.single.wildcard"}
	}
	for k := digitsEnd; k < end; k++ {
		if str[k] != SegmentSqlSingleWildcard {
			return &addressStringException{str: str, key: "ipaddress.error.single.wildcard.order"}
		}
	}
	return nil
}

func switchSingleWildcard10(currentValueHex uint64, s string, start, end, numSingleWildcards int, parseData *AddressParseData, parsedSegIndex, leadingZeroStartIndex int, options AddressStringFormatParameters) (err AddressStringException) {
	digitsEnd := end - numSingleWildcards
	err = checkSingleWildcard(s, start, end, digitsEnd, options)
	if err != nil {
		return
	}
	var lower uint64
	if start < digitsEnd {
		lower, err = switchValue10(currentValueHex, s, digitsEnd-start)
		if err != nil {
			return
		}
	}
	var upper uint64

	switch numSingleWildcards {
	case 1:
		lower *= 10
		upper = lower + 9
	case 2:
		lower *= 100
		upper = lower + 99
	case 3:
		lower *= 1000
		upper = lower + 999
	default:
		power := uint64(math.Pow10(numSingleWildcards))
		lower *= power
		upper = lower + power - 1
	}
	var radix uint32 = 10
	assign6Attributes2Values2Flags(start, end, leadingZeroStartIndex, start, end, leadingZeroStartIndex,
		parseData, parsedSegIndex, lower, upper, KEY_SINGLE_WILDCARD|radix, radix)
	return
}

func switchSingleWildcard2(currentValueHex uint64, s string, start, end, numSingleWildcards int, parseData *AddressParseData, parsedSegIndex, leadingZeroStartIndex int, options AddressStringFormatParameters) (err AddressStringException) {
	digitsEnd := end - numSingleWildcards
	err = checkSingleWildcard(s, start, end, digitsEnd, options)
	if err != nil {
		return
	}
	var lower, upper uint64
	if start < digitsEnd {
		lower, err = switchValue2(currentValueHex, s, digitsEnd-start)
		if err != nil {
			return
		}
	} else {
		lower = 0
	}
	lower <<= numSingleWildcards
	switch numSingleWildcards {
	case 1:
		upper = lower | 0x1
	case 2:
		upper = lower | 0x3
	case 3:
		upper = lower | 0x7
	case 4:
		upper = lower | 0xf
	case 5:
		upper = lower | 0x1f
	case 6:
		upper = lower | 0x3f
	case 7:
		upper = lower | 0x7f
	case 8:
		upper = lower | 0xff
	case 9:
		upper = lower | 0x1ff
	case 10:
		upper = lower | 0x3ff
	case 11:
		upper = lower | 0x7ff
	case 12:
		upper = lower | 0xfff
	case 13:
		upper = lower | 0x1fff
	case 14:
		upper = lower | 0x3fff
	case 15:
		upper = lower | 0x7fff
	case 16:
		upper = lower | 0xffff
	default:
		upper = lower | ^(^uint64(0) << numSingleWildcards)
	}
	var radix uint32 = 2
	assign6Attributes2Values2Flags(start, end, leadingZeroStartIndex, start, end, leadingZeroStartIndex,
		parseData, parsedSegIndex, lower, upper, KEY_SINGLE_WILDCARD|radix, radix)
	return
}

func switchSingleWildcard8(currentValueHex uint64, s string, start, end, numSingleWildcards int, parseData *AddressParseData, parsedSegIndex, leadingZeroStartIndex int, options AddressStringFormatParameters) (err AddressStringException) {
	digitsEnd := end - numSingleWildcards
	err = checkSingleWildcard(s, start, end, digitsEnd, options)
	if err != nil {
		return
	}
	var lower, upper uint64
	if start < digitsEnd {
		lower, err = switchValue8(currentValueHex, s, digitsEnd-start)
		if err != nil {
			return
		}
	}
	switch numSingleWildcards {
	case 1:
		lower <<= 3
		upper = lower | 07
	case 2:
		lower <<= 6
		upper = lower | 077
	case 3:
		lower <<= 9
		upper = lower | 0777
	default:
		shift := numSingleWildcards * 3
		lower <<= shift
		upper = lower | ^(^uint64(0) << shift)
	}
	var radix uint32 = 8
	assign6Attributes2Values2Flags(start, end, leadingZeroStartIndex, start, end, leadingZeroStartIndex,
		parseData, parsedSegIndex, lower, upper, KEY_SINGLE_WILDCARD|radix, radix)
	return
}

func assignSingleWildcard16(lower uint64, s string, start, end, numSingleWildcards int, parseData *AddressParseData, parsedSegIndex, leadingZeroStartIndex int, options AddressStringFormatParameters) (err AddressStringException) {
	digitsEnd := end - numSingleWildcards
	err = checkSingleWildcard(s, start, end, digitsEnd, options)
	if err != nil {
		return
	}
	shift := numSingleWildcards << 2
	lower <<= shift
	upper := lower | ^(^uint64(0) << shift)
	assign6Attributes2Values1Flags(start, end, leadingZeroStartIndex, start, end, leadingZeroStartIndex,
		parseData, parsedSegIndex, lower, upper, KEY_SINGLE_WILDCARD)
	return
}

func parseSingleSegmentSingleWildcard16(currentValueHex uint64, s string, start, end, numSingleWildcards int, parseData *AddressParseData, parsedSegIndex, leadingZeroStartIndex int, options AddressStringFormatParameters) (err AddressStringException) {
	digitsEnd := end - numSingleWildcards
	err = checkSingleWildcard(s, start, end, digitsEnd, options)
	if err != nil {
		return
	}
	var upper, lower, extendedLower, extendedUpper uint64
	if numSingleWildcards < LONG_HEX_DIGITS {
		midIndex := end - LONG_HEX_DIGITS
		lower = parseLong16(s, midIndex, digitsEnd)
		shift := numSingleWildcards << 2
		lower <<= shift
		upper = lower | ^(^uint64(0) << shift)
		extendedLower = parseLong16(s, start, midIndex)
		extendedUpper = extendedLower
	} else if numSingleWildcards == LONG_HEX_DIGITS {
		lower = 0
		upper = 0xffffffffffffffff
		extendedUpper = currentValueHex
		extendedLower = currentValueHex
	} else {
		lower = 0
		upper = 0xffffffffffffffff
		extendedLower = currentValueHex
		shift := (numSingleWildcards - LONG_HEX_DIGITS) << 2
		extendedLower <<= shift
		extendedUpper = extendedLower | ^(^uint64(0) << shift)
	}
	assign6Attributes4Values1Flags(start, end, leadingZeroStartIndex, start, end, leadingZeroStartIndex,
		parseData, parsedSegIndex, lower, extendedLower, upper, extendedUpper, KEY_SINGLE_WILDCARD)
	return
}

func parseSingleSegmentSingleWildcard2(s string, start, end, numSingleWildcards int, parseData *AddressParseData, parsedSegIndex, leadingZeroStartIndex int, options AddressStringFormatParameters) (err AddressStringException) {
	digitsEnd := end - numSingleWildcards
	err = checkSingleWildcard(s, start, end, digitsEnd, options)
	if err != nil {
		return
	}
	var upper, lower, extendedLower, extendedUpper uint64
	midIndex := end - LONG_BINARY_DIGITS
	if numSingleWildcards < LONG_BINARY_DIGITS {
		lower = parseLong2(s, midIndex, digitsEnd)
		shift := numSingleWildcards
		lower <<= shift
		upper = lower | ^(^uint64(0) << shift)
		extendedLower = parseLong2(s, start, midIndex)
		extendedUpper = extendedLower
	} else if numSingleWildcards == LONG_BINARY_DIGITS {
		upper = 0xffffffffffffffff
		extendedLower = parseLong2(s, start, midIndex)
		extendedUpper = extendedLower
	} else {
		upper = 0xffffffffffffffff
		shift := numSingleWildcards - LONG_BINARY_DIGITS
		extendedLower = parseLong2(s, start, midIndex-shift)
		extendedLower <<= shift
		extendedUpper = extendedLower | ^(^uint64(0) << shift)
	}
	assign6Attributes4Values1Flags(start, end, leadingZeroStartIndex, start, end, leadingZeroStartIndex,
		parseData, parsedSegIndex, lower, extendedLower, upper, extendedUpper, KEY_SINGLE_WILDCARD)
	return
}

////////////////////////

var MAX_VALUES = [5]uint64{0, IPv4MaxValuePerSegment, 0xffff, 0xffffff, 0xffffffff} //TODO uncapitalize later

func getMaxIPv4Value(segmentCount int) uint64 {
	return MAX_VALUES[segmentCount]
}

func getStringPrefixCharCount(radix uint32) int {
	switch radix {
	case 10:
		return 0
	case 16:
	case 2:
		return 2
	default:
	}
	return 1
}

var MAX_IPv4_STRING_LEN [9][]int = [9][]int{ //indices are [radix / 2][additionalSegments], and we handle radices 8, 10, 16 //TODO uncapitalize later
	{3, 6, 8, 11},   //no radix supplied we treat as octal, the longest
	{8, 16, 24, 32}, // binary
	{}, {},
	{3, 6, 8, 11},                   //octal: 0377, 0177777, 077777777, 037777777777
	{IPv4SegmentMaxChars, 5, 8, 10}, //decimal: 255, 65535, 16777215, 4294967295
	{}, {},
	{2, 4, 6, 8}, //hex: 0xff, 0xffff, 0xffffff, 0xffffffff
}

func getMaxIPv4StringLength(additionalSegmentsCovered int, radix uint32) int {
	radixHalved := radix >> 1
	if radixHalved < uint32(len(MAX_IPv4_STRING_LEN)) {
		sl := MAX_IPv4_STRING_LEN[radixHalved]
		if additionalSegmentsCovered >= 0 && additionalSegmentsCovered < len(sl) {
			return sl[additionalSegmentsCovered]
		}
	}
	return 0
}

func switchValue2(currentHexValue uint64, s string, digitCount int) (result uint64, err AddressStringException) {
	result = 0xf & currentHexValue
	if result > 1 {
		err = &addressStringException{str: s, key: "ipaddress.error.ipv4.invalid.binary.digit"}
		return
	}
	shift := 0

	for digitCount--; digitCount > 0; digitCount-- {
		shift++
		currentHexValue >>= 4
		next := 0xf & currentHexValue
		if next >= 1 {
			if next == 1 {
				result |= 1 << shift
			} else {
				err = &addressStringException{str: s, key: "ipaddress.error.ipv4.invalid.binary.digit"}
				return
			}
		}
	}
	return
}

/**
 * The digits were stored as a hex value, this switches them to an octal value.
 *
 * @param currentHexValue
 * @param digitCount
 * @return
 */
func switchValue8(currentHexValue uint64, s string, digitCount int) (result uint64, err AddressStringException) {
	result = 0xf & currentHexValue
	if result >= 8 {
		err = &addressStringException{str: s, key: "ipaddress.error.ipv4.invalid.octal.digit"}
		return
	}
	shift := 0
	for digitCount--; digitCount > 0; digitCount-- {
		shift += 3
		currentHexValue >>= 4
		next := 0xf & currentHexValue
		if next >= 8 {
			err = &addressStringException{str: s, key: "ipaddress.error.ipv4.invalid.octal.digit"}
			return
		}
		result |= next << shift
	}
	return
}

func switchValue10(currentHexValue uint64, s string, digitCount int) (result uint64, err AddressStringException) {
	result = 0xf & currentHexValue
	if result >= 10 {
		err = &addressStringException{str: s, key: "ipaddress.error.ipv4.invalid.decimal.digit"}
		return
	}
	digitCount--
	if digitCount > 0 {
		factor := uint64(10)
		for {
			currentHexValue >>= 4
			next := 0xf & currentHexValue
			if next >= 10 {
				err = &addressStringException{str: s, key: "ipaddress.error.ipv4.invalid.decimal.digit"}
				return
			}
			result += next * factor
			digitCount--
			if digitCount == 0 {
				break
			}
			if factor == 10 {
				factor = 100
			} else if factor == 100 {
				factor = 1000
			} else {
				factor *= 10
			}
		}
	}
	return
}

func parseLong2(s string, start, end int) uint64 {
	charArray := chars
	result := charArray[s[start]]
	for start++; start < end; start++ {
		c := s[start]
		if c == '1' {
			result = (result << 1) | 1
		} else {
			result <<= 1
		}
	}
	return result
}

func parseLong8(s string, start, end int) uint64 {
	charArray := chars
	result := charArray[s[start]]
	for start++; start < end; start++ {
		result = (result << 3) | charArray[s[start]]
	}
	return result
}

func parseLong10(s string, start, end int) uint64 {
	charArray := chars
	result := charArray[s[start]]
	for start++; start < end; start++ {
		result = (result * 10) + charArray[s[start]]
	}
	return result
}

func parseLong16(s string, start, end int) uint64 {
	charArray := chars
	result := charArray[s[start]]
	for start++; start < end; start++ {
		result = (result << 4) | charArray[s[start]]
	}
	return result
}
