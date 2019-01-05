/*
 * Copyright 2016-2018 Sean C Foley
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *     or at
 *     https://github.com/seancfoley/IPAddress/blob/master/LICENSE
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package inet.ipaddr.format.validate;

import java.math.BigInteger;

import inet.ipaddr.Address;
import inet.ipaddr.AddressStringException;
import inet.ipaddr.AddressStringParameters;
import inet.ipaddr.AddressStringParameters.AddressStringFormatParameters;
import inet.ipaddr.AddressStringParameters.RangeParameters;
import inet.ipaddr.HostIdentifierString;
import inet.ipaddr.HostName;
import inet.ipaddr.HostNameException;
import inet.ipaddr.HostNameParameters;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.IPAddressStringParameters;
import inet.ipaddr.MACAddressString;
import inet.ipaddr.MACAddressStringParameters;
import inet.ipaddr.MACAddressStringParameters.AddressSize;
import inet.ipaddr.MACAddressStringParameters.MACAddressStringFormatParameters;
import inet.ipaddr.format.large.IPAddressLargeDivision;
import inet.ipaddr.format.validate.IPAddressProvider.AllCreator;
import inet.ipaddr.format.validate.IPAddressProvider.LoopbackCreator;
import inet.ipaddr.format.validate.IPAddressProvider.MaskCreator;
import inet.ipaddr.format.validate.MACAddressParseData.MACFormat;
import inet.ipaddr.format.validate.ParsedHost.EmbeddedAddress;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv4.IPv4AddressSegment;
import inet.ipaddr.ipv4.IPv4AddressStringParameters;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.ipv6.IPv6AddressSegment;
import inet.ipaddr.ipv6.IPv6AddressStringParameters;
import inet.ipaddr.mac.MACAddress;
import inet.ipaddr.mac.MACAddressSegment;


/**
 * Validates host strings, address strings, and prefix lengths.
 * 
 * @author sfoley
 *
 */
public class Validator implements HostIdentifierStringValidator {
	
	private static final int extendedChars[] = new int[128]; static {
		char[] extendedDigits = IPAddressLargeDivision.EXTENDED_DIGITS;
		for(int i = 0; i < extendedDigits.length; i++) {
			extendedChars[extendedDigits[i]] = i;
		}
	}
	
	private static final int chars[] = new int[128]; static {
		int charArray[] = chars;
		int i = 0;
		for(char c = '0'; i < 10; i++, c++) {
			charArray[c] = i;
		}
		for(char c = 'a', c2 = 'A'; i < 26; i++, c++, c2++) {
			charArray[c] = charArray[c2] = i;
		}
	}

	private static final int MAX_HOST_LENGTH = 253;
	private static final int MAX_HOST_SEGMENTS = 127;
	private static final int MAX_LABEL_LENGTH = 63;
	
	private static final long MAC_MAX_TRIPLE = (MACAddress.MAX_VALUE_PER_SEGMENT << (MACAddress.BITS_PER_SEGMENT << 1)) | (MACAddress.MAX_VALUE_PER_SEGMENT << MACAddress.BITS_PER_SEGMENT) | MACAddress.MAX_VALUE_PER_SEGMENT;
	private static final long MAC_MAX_QUINTUPLE = (MAC_MAX_TRIPLE << (MACAddress.BITS_PER_SEGMENT << 1)) | (MAC_MAX_TRIPLE >>> MACAddress.BITS_PER_SEGMENT);
	private static final int MAC_DOUBLE_SEGMENT_DIGIT_COUNT = 6;
	private static final int MAC_EXTENDED_DOUBLE_SEGMENT_DIGIT_COUNT = 10;
	private static final int MAC_SINGLE_SEGMENT_DIGIT_COUNT = 12;
	private static final int MAC_EXTENDED_SINGLE_SEGMENT_DIGIT_COUNT = 16;
	private static final int IPV6_SINGLE_SEGMENT_DIGIT_COUNT = 32;
	private static final int IPV6_BASE85_SINGLE_SEGMENT_DIGIT_COUNT = 20;
	private static final int IPV4_SINGLE_SEGMENT_OCTAL_DIGIT_COUNT = 11;
	private static final int LONG_HEX_DIGITS = Long.SIZE >>> 2;
	
	private static final char IPvFUTURE_UPPERCASE = Character.toUpperCase(HostIdentifierStringValidator.IPvFUTURE);

	private static final int EMPTY_INDICES[] = new int[0];
	private static final ParsedHostIdentifierStringQualifier PREFIX_CACHE[] = new ParsedHostIdentifierStringQualifier[IPv6Address.BIT_COUNT + 1];
	static final MaskCreator MASK_CACHE[][] = new MaskCreator[3][];
	private static final LoopbackCreator LOOPBACK_CACHE = new LoopbackCreator(IPAddressString.DEFAULT_VALIDATION_OPTIONS);
	private static final ParsedHost DEFAULT_EMPTY_HOST = new ParsedHost("", EMPTY_INDICES, null, ParsedHost.NO_QUALIFIER);
	private static final IPAddressStringParameters DEFAULT_PREFIX_OPTIONS = new IPAddressStringParameters.Builder().toParams();

	public static final HostIdentifierStringValidator VALIDATOR = new Validator();
	
	//note we allow single segment and mixed here, as well as base 85, as well as all * but we interpret that as IPv6, as well as ranges
	private static final IPAddressStringParameters DEFAULT_UNC_OPTS = new IPAddressStringParameters.Builder().
			allowIPv4(false).allowEmpty(false).allowMask(false).allowPrefixOnly(false).allowPrefix(false).toParams();
	
	private static final IPAddressStringParameters REVERSE_DNS_IPV4_OPTS = new IPAddressStringParameters.Builder().
			allowIPv6(false).allowEmpty(false).allowMask(false).allowPrefixOnly(false).allowPrefix(false).
			getIPv4AddressParametersBuilder().allow_inet_aton(false).getParentBuilder().toParams();
	
	private static final IPAddressStringParameters REVERSE_DNS_IPV6_OPTS = new IPAddressStringParameters.Builder().
			allowIPv4(false).allowEmpty(false).allowMask(false).allowPrefixOnly(false).allowPrefix(false).
			getIPv6AddressParametersBuilder().allowMixed(false).allowZone(false).getParentBuilder().toParams();
	
	private static final BigInteger BASE_85_POWERS[] = new BigInteger[10];
	private static final BigInteger LOW_BITS_MASK = BigInteger.valueOf(0xffffffffffffffffL);
	
	/**
	 * Singleton - this class has no state
	 */
	private Validator() {}

	@Override
	public ParsedHost validateHost(HostName fromHost) throws HostNameException {
		return validateHostImpl(fromHost);
	}
	
	@Override
	public IPAddressProvider validateAddress(IPAddressString fromString) throws AddressStringException {
		String str = fromString.toString();
		IPAddressStringParameters validationOptions = fromString.getValidationOptions();
		ParsedIPAddress pa = new ParsedIPAddress(fromString, str, validationOptions);
		validateIPAddress(validationOptions, str, 0, str.length(), pa, false);
		return chooseProvider(fromString, str, validationOptions, pa,
			parseAddressQualifier(str, validationOptions, null, pa, str.length()));
	}

	@Override
	public MACAddressProvider validateAddress(MACAddressString fromString) throws AddressStringException {
		String str = fromString.toString();
		MACAddressStringParameters validationOptions = fromString.getValidationOptions();
		ParsedMACAddress pa = new ParsedMACAddress(fromString, str);
		validateMACAddress(validationOptions, str, 0, str.length(), pa);
		AddressParseData addressParseData = pa.getAddressParseData();
		if(addressParseData.isProvidingEmpty()) {
			return MACAddressProvider.EMPTY_PROVIDER;
		} else if(addressParseData.isAll()) {
			return MACAddressProvider.getAllProvider(validationOptions);
		} else {
			checkSegments(
					fromString.toString(),
					fromString.getValidationOptions(),
					pa);
			return pa;
		}
	}
	
	private static void validateIPAddress(
			final IPAddressStringParameters validationOptions,
			final CharSequence str,
			final int strStartIndex,
			int strEndIndex,
			IPAddressParseData parseData,
			boolean isEmbeddedIPv4) throws AddressStringException {
		validateAddress(validationOptions, null, str, strStartIndex, strEndIndex, parseData, null, isEmbeddedIPv4);
	}
	
	private static void validateMACAddress(
			final MACAddressStringParameters validationOptions,
			final String str,
			final int strStartIndex,
			int strEndIndex,
			MACAddressParseData parseData) throws AddressStringException {
		validateAddress(null, validationOptions, str, strStartIndex, strEndIndex, null, parseData, false);
	}

	/**
	 * This method is the mega-parser.
	 * It is designed to go through the characters one-by-one if a big if/else.
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
	 * @param validationOptions
	 * @param macOptions
	 * @param str
	 * @param strStartIndex
	 * @param strEndIndex
	 * @param ipAddressParseData
	 * @param macAddressParseData
	 * @throws AddressStringException
	 */
	private static void validateAddress(
			final IPAddressStringParameters validationOptions,
			final MACAddressStringParameters macOptions,
			final CharSequence str,
			final int strStartIndex,
			int strEndIndex,
			IPAddressParseData ipAddressParseData,
			MACAddressParseData macAddressParseData,
			boolean isEmbeddedIPv4) throws AddressStringException {
		boolean isMac = macAddressParseData != null;
		AddressParseData parseData;
		AddressStringFormatParameters stringFormatParams;
		IPv6AddressStringParameters ipv6SpecificOptions = null;
		IPv4AddressStringParameters ipv4SpecificOptions = null;
		MACAddressStringFormatParameters macSpecificOptions = null;
		AddressStringParameters baseOptions;
		MACFormat macFormat = null;
		boolean isBase85;
		if(isMac) {
			baseOptions = macOptions;
			stringFormatParams = macSpecificOptions = macOptions.getFormatParameters();
			parseData = macAddressParseData.getAddressParseData();
			isBase85 = false;
		} else {
			baseOptions = validationOptions;
			//later we set stringFormatParams when we know what ip version we have
			stringFormatParams = null;
			parseData = ipAddressParseData.getAddressParseData();
			ipv6SpecificOptions = validationOptions.getIPv6Parameters();
			isBase85 = ipv6SpecificOptions.allowBase85;
			ipv4SpecificOptions = validationOptions.getIPv4Parameters();
		}
		
		int index = strStartIndex;
		
		//per segment variables
		int lastSeparatorIndex, digitCount, leadingZeroCount, rangeWildcardIndex, hexDelimiterIndex, singleWildcardCount, wildcardCount;
		int frontDigitCount, frontLeadingZeroCount, frontWildcardCount, frontSingleWildcardCount, frontHexDelimiterIndex;
		boolean notOctal, notDecimal, uppercase, isSingleIPv6Hex, isSingleSegment, isDoubleSegment, isStandard;
		boolean frontNotOctal, frontNotDecimal, frontUppercase, frontIsStandardRange;
		boolean firstSegmentDashedRange, checkCharCounts;
		int extendedCharacterIndex, extendedRangeWildcardIndex;
		boolean atEnd;
		long currentValueHex, currentFrontValueHex;
		final int charArray[] = chars;
		
		frontDigitCount = frontLeadingZeroCount = frontSingleWildcardCount = digitCount = leadingZeroCount = singleWildcardCount = wildcardCount = frontWildcardCount = 0;
		extendedCharacterIndex = extendedRangeWildcardIndex = lastSeparatorIndex = rangeWildcardIndex = hexDelimiterIndex = frontHexDelimiterIndex = -1;
		isStandard = frontIsStandardRange = atEnd = firstSegmentDashedRange = frontNotOctal = frontNotDecimal = frontUppercase = notOctal = notDecimal = uppercase = isSingleIPv6Hex = isSingleSegment = isDoubleSegment = false;
		currentValueHex = currentFrontValueHex = 0;
		checkCharCounts = true;
		
		boolean endOfHexSegment, isSpace, isZoneChar, isDashedRangeChar, isRangeChar, isJustZero, isSingleWildcard;
		isSingleWildcard = isJustZero = isSpace = isDashedRangeChar = isRangeChar = isZoneChar = false;
		long extendedValue = 0;
		
		while(index < strEndIndex || (atEnd = (index == strEndIndex))) {
			char currentChar;
			if(atEnd) {
				parseData.setAddressEndIndex(index);
				int totalDigits = leadingZeroCount + digitCount;
				IPVersion version = null;
				boolean isSegmented = isMac ? macFormat != null : (version = ipAddressParseData.getProviderIPVersion()) != null;
				if(isSegmented) {
					if(isMac) {
						currentChar = macFormat.getSeparator();
						macAddressParseData.setDoubleSegment(isDoubleSegment = (parseData.getSegmentCount() == 1 && currentChar == Address.RANGE_SEPARATOR));
						if(isDoubleSegment) {
							macAddressParseData.setExtended(totalDigits == MAC_EXTENDED_DOUBLE_SEGMENT_DIGIT_COUNT);
						}
					} else {
						//current char is either . or : to handle last segment, unless we have double :: in which case we already handled last segment
						if(version.isIPv4()) {
							currentChar = IPv4Address.SEGMENT_SEPARATOR;
						} else { //ipv6
							if(index == lastSeparatorIndex + 1) {
								if(index == parseData.getConsecutiveSeparatorIndex() + 2) {
									//ends with ::, we've already parsed the last segment
									break;
								}
								throw new AddressStringException(str, "ipaddress.error.cannot.end.with.single.separator");
							} else if(ipAddressParseData.isProvidingMixedIPv6()) {
								//no need to parse the last segment, since it is mixed we already have
								break;
							} else {
								currentChar = IPv6Address.SEGMENT_SEPARATOR;
							}
						}
					}
				} else {
					//no segment separator so far and segmentCount is 0
					//it could be all addresses like "*", single segment like 12345 , empty "", or prefix only ip address like /64
					int totalCharacterCount = index - strStartIndex;
					if(totalCharacterCount == 0) {
						//it is prefix-only or ""
						if(!isMac && ipAddressParseData.hasPrefixSeparator()) {
							if(!validationOptions.allowPrefixOnly) {
								throw new AddressStringException(str, "ipaddress.error.prefix.only");
							}
						} else if(!baseOptions.allowEmpty) {
							throw new AddressStringException(str, "ipaddress.error.empty");
						}
						parseData.setEmpty(true);
						break;
					} else if(wildcardCount == totalCharacterCount) {// "*"
						if(singleWildcardCount > 0 || rangeWildcardIndex >= 0 || leadingZeroCount > 0 || digitCount > 0 || hexDelimiterIndex >= 0) {//wildcards must appear alone
							throw new AddressStringException(str, index, true);
						}
						if(!baseOptions.allowAll) {
							throw new AddressStringException(str, "ipaddress.error.all");
						}
						parseData.setHasWildcard(true);
						parseData.setAll(true);
						break;
					}

					if(isMac) {
						//we handle the double segment format abcdef-abcdef here
						int frontTotalDigits = frontLeadingZeroCount + frontDigitCount;
						if(		(	((totalDigits == MAC_DOUBLE_SEGMENT_DIGIT_COUNT || totalDigits == MAC_EXTENDED_DOUBLE_SEGMENT_DIGIT_COUNT) && (frontTotalDigits == MAC_DOUBLE_SEGMENT_DIGIT_COUNT || frontWildcardCount > 0)) || 
									(frontTotalDigits == MAC_DOUBLE_SEGMENT_DIGIT_COUNT && wildcardCount > 0) ||
									(frontWildcardCount > 0 && wildcardCount > 0)
								) && !firstSegmentDashedRange) {//checks for *-abcdef and abcdef-* and abcdef-abcdef and *-* two segment addresses
								//firstSegmentDashedRange means that the range character is '|'
							AddressSize addressSize = macOptions.addressSize;
							if(addressSize == AddressSize.EUI64 && totalDigits == MAC_DOUBLE_SEGMENT_DIGIT_COUNT) {
								throw new AddressStringException(str, "ipaddress.error.too.few.segments");
							} else if(addressSize == AddressSize.MAC && totalDigits == MAC_EXTENDED_DOUBLE_SEGMENT_DIGIT_COUNT) {
								throw new AddressStringException(str, "ipaddress.error.too.many.segments");
							}

							//we have aaaaaa-bbbbbb
							if(!macOptions.allowSingleDashed) {
								throw new AddressStringException(str, "ipaddress.mac.error.format");
							}
							macAddressParseData.setDoubleSegment(isDoubleSegment = true);
							macAddressParseData.setExtended(totalDigits == MAC_EXTENDED_DOUBLE_SEGMENT_DIGIT_COUNT);
							currentChar = MACAddress.DASH_SEGMENT_SEPARATOR;
							checkCharCounts = false; //counted chars already
						} else if((frontWildcardCount > 0) || (wildcardCount > 0)) {
							//either x-* or *-x, we treat these as if they can be expanded to x-*-*-*-*-* or *-*-*-*-*-x
							if(!macOptions.allowSingleDashed) {
								throw new AddressStringException(str, "ipaddress.mac.error.format");
							}
							currentChar = MACAddress.DASH_SEGMENT_SEPARATOR;
						} else {
							//a string of digits with no segment separator
							//here we handle abcdefabcdef or abcdefabcdef|abcdefabcdef or abcdefabcdef-abcdefabcdef
							if(!baseOptions.allowSingleSegment) {
								throw new AddressStringException(str, "ipaddress.error.single.segment");
							}
							boolean is12Digits = totalDigits == MAC_SINGLE_SEGMENT_DIGIT_COUNT;
							if(is12Digits || totalDigits == MAC_EXTENDED_SINGLE_SEGMENT_DIGIT_COUNT) {
								if(rangeWildcardIndex >= 0) {
									if(frontTotalDigits != (is12Digits ? MAC_SINGLE_SEGMENT_DIGIT_COUNT : MAC_EXTENDED_SINGLE_SEGMENT_DIGIT_COUNT)) {
										throw new AddressStringException("ipaddress.error.front.digit.count");
									}
								}
								parseData.setSingleSegment(isSingleSegment = true);
								macAddressParseData.setExtended(!is12Digits);
								currentChar = MACAddress.COLON_SEGMENT_SEPARATOR;
								checkCharCounts = false;//counted chars already
							} else {
								throw new AddressStringException("ipaddress.error.too.few.segments.digit.count");
							}
						}
					} else {
						//a string of digits with no segment separator
						if(!baseOptions.allowSingleSegment) {
							throw new AddressStringException(str, "ipaddress.error.single.segment");
						}
						if(totalDigits == IPV6_SINGLE_SEGMENT_DIGIT_COUNT) {
							if(rangeWildcardIndex >= 0) {
								int frontTotalDigits = frontLeadingZeroCount + frontDigitCount;
								if(frontTotalDigits != IPV6_SINGLE_SEGMENT_DIGIT_COUNT) {
									throw new AddressStringException("ipaddress.error.front.digit.count");
								}
							}
							parseData.setSingleSegment(isSingleSegment = isSingleIPv6Hex = true);
							currentChar = IPv6Address.SEGMENT_SEPARATOR;
							checkCharCounts = false;//counted chars already
						} else {
							if(isBase85) {
								if(extendedRangeWildcardIndex < 0) {
									if(totalCharacterCount == IPV6_BASE85_SINGLE_SEGMENT_DIGIT_COUNT) {
										if(!validationOptions.allowIPv6) {
											throw new AddressStringException(str, "ipaddress.error.ipv6");
										}
										ipAddressParseData.setVersion(IPVersion.IPV6);
										BigInteger val = parseBig85(str, strStartIndex, strEndIndex);
										long value = val.and(LOW_BITS_MASK).longValue();
										BigInteger shift64 = val.shiftRight(Long.SIZE);
										extendedValue = shift64.longValue();
										//note that even with the correct number of digits, we can have a value too large
										BigInteger shiftMore = shift64.shiftRight(Long.SIZE);
										if(!shiftMore.equals(BigInteger.ZERO)) {
											throw new AddressStringException(str, "ipaddress.error.address.too.large");
										}
										parseData.initSegmentData(1);
										parseData.incrementSegmentCount();
										assignAttributes(strStartIndex, strEndIndex, parseData, 0, IPv6Address.DEFAULT_TEXTUAL_RADIX, strStartIndex);
										parseData.setValue(0, 
												AddressParseData.KEY_LOWER, value,
												AddressParseData.KEY_UPPER, value,
												AddressParseData.KEY_EXTENDED_LOWER, extendedValue,
												AddressParseData.KEY_EXTENDED_UPPER, extendedValue);
										ipAddressParseData.setBase85(true);
										break;
									}
								} else {
									if(totalCharacterCount == (IPV6_BASE85_SINGLE_SEGMENT_DIGIT_COUNT << 1) + 1) {/* note that we already check that extendedRangeWildcardIndex is at index 20 */
										if(!validationOptions.allowIPv6) {
											throw new AddressStringException(str, "ipaddress.error.ipv6");
										}
										ipAddressParseData.setVersion(IPVersion.IPV6);
										int frontEndIndex = strStartIndex + IPV6_BASE85_SINGLE_SEGMENT_DIGIT_COUNT;
										BigInteger val = parseBig85(str, strStartIndex, frontEndIndex);
										BigInteger val2 = parseBig85(str, frontEndIndex + 1, strEndIndex);
										long value = val.and(LOW_BITS_MASK).longValue();
										BigInteger shift64 = val.shiftRight(Long.SIZE);
										extendedValue = shift64.longValue();
										BigInteger shiftMore = shift64.shiftRight(Long.SIZE);
										long value2 = val2.and(LOW_BITS_MASK).longValue();
										shift64 = val2.shiftRight(Long.SIZE);
										long extendedValue2 = shift64.longValue();
										shiftMore = shift64.shiftRight(Long.SIZE);
										if(!shiftMore.equals(BigInteger.ZERO)) {
											throw new AddressStringException(str, "ipaddress.error.address.too.large");
										} else if(val.compareTo(val2) > 0) {
											throw new AddressStringException(str, "ipaddress.error.invalidRange");
										}
										parseData.incrementSegmentCount();
										parseData.initSegmentData(1);
										assignAttributes(strStartIndex, frontEndIndex, frontEndIndex + 1, strEndIndex, parseData, 0, strStartIndex, frontEndIndex + 1, IPv6Address.DEFAULT_TEXTUAL_RADIX, IPv6Address.DEFAULT_TEXTUAL_RADIX);
										parseData.setValue(0, 
												AddressParseData.KEY_LOWER, value,
												AddressParseData.KEY_UPPER, value2,
												AddressParseData.KEY_EXTENDED_LOWER, extendedValue,
												AddressParseData.KEY_EXTENDED_UPPER, extendedValue2);
										ipAddressParseData.setBase85(true);
										parseData.setFlag(0, AddressParseData.KEY_RANGE_WILDCARD, true);
										break;
									}
								}
							}
							if (digitCount <= IPV4_SINGLE_SEGMENT_OCTAL_DIGIT_COUNT)  {
								if(rangeWildcardIndex >= 0) {
									if(frontDigitCount > IPV4_SINGLE_SEGMENT_OCTAL_DIGIT_COUNT) {
										throw new AddressStringException("ipaddress.error.front.digit.count");
									}
								}
								
								//we treat as inet_aton, which means decimal ipv4 or if there is a 0 or 0x we treat as octal or hex ipv4
								currentChar = IPv4Address.SEGMENT_SEPARATOR;
							} else {
								throw new AddressStringException("ipaddress.error.too.few.segments.digit.count");
							}
						}
					}
				}
			} else {
				currentChar = str.charAt(index);
			}

			// evaluate the character
			if(currentChar <= '9' && currentChar >= '0') {
				if(currentChar == '0') {
					if(digitCount > 0) {
						++digitCount;
						currentValueHex <<= 4;
					} else {
						++leadingZeroCount;
					}
				} else {
					++digitCount;
					currentValueHex = (currentValueHex << 4) | charArray[currentChar];
					if(currentChar >= '8') {
						notOctal = true;
					}
				}
				++index;
			} else if(currentChar >= 'a' && currentChar <= 'f') {
				++digitCount;
				++index;
				currentValueHex = (currentValueHex << 4) | charArray[currentChar];
				notOctal = notDecimal = true;
			} else if(currentChar == IPv4Address.SEGMENT_SEPARATOR) {
				int segCount = parseData.getSegmentCount();
				IPVersion version = null;
				if(!isMac && (version = ipAddressParseData.getProviderIPVersion()) != null && version.isIPv6()) {
					//we are not base 85, so throw if necessary
					if(extendedCharacterIndex >= 0) {
						throw new AddressStringException(str, extendedCharacterIndex);
					}
					isBase85 = false;
					//mixed IPv6 address like 1:2:3:4:5:6:1.2.3.4
					if(!ipv6SpecificOptions.allowMixed) {
						throw new AddressStringException(str, "ipaddress.error.no.mixed");
					}
					int totalSegmentCount = segCount + IPv6Address.MIXED_REPLACED_SEGMENT_COUNT;
					if(totalSegmentCount > IPv6Address.SEGMENT_COUNT) {
						throw new AddressStringException(str, "ipaddress.error.too.many.segments");
					}
					if(wildcardCount > 0) {
						parseData.setHasWildcard(true);
					}
					boolean isNotExpandable = wildcardCount > 0 && parseData.getConsecutiveSeparatorIndex() < 0;
					if(isNotExpandable && 
							totalSegmentCount < IPv6Address.SEGMENT_COUNT && 
							ipv6SpecificOptions.allowWildcardedSeparator) {
						//the '*' is covering an additional ipv6 segment (eg 1:2:3:4:5:*.2.3.4, the * covers both an ipv4 and ipv6 segment)
						parseData.setFlag(segCount, AddressParseData.KEY_WILDCARD, true);
						parseData.setValue(segCount, AddressParseData.KEY_UPPER, IPv6Address.MAX_VALUE_PER_SEGMENT);
						parseData.incrementSegmentCount();
					}
					IPAddressStringParameters mixedOptions = ipv6SpecificOptions.getMixedParameters();
					ParsedIPAddress pa = new ParsedIPAddress(null, str, mixedOptions);
					validateIPAddress(mixedOptions, str, lastSeparatorIndex + 1, strEndIndex, pa, true);
					pa.clearQualifier();
					checkSegments(str, mixedOptions, pa);
					ipAddressParseData.setMixedParsedAddress(pa);
					index = pa.getAddressParseData().getAddressEndIndex();
				} else {
					//could be mac or ipv4, we handle either one
					int maxChars;
					if(isMac) {
						if(segCount == 0) {
							if(!macOptions.allowDotted) {
								throw new AddressStringException(str, "ipaddress.mac.error.format");
							}
							macAddressParseData.setFormat(macFormat = MACFormat.DOTTED);
							parseData.initSegmentData(MACAddress.MEDIA_ACCESS_CONTROL_DOTTED_64_SEGMENT_COUNT);
						} else {
							if(macFormat != MACFormat.DOTTED) {
								throw new AddressStringException(str, "ipaddress.mac.error.mix.format.characters.at.index", index);
							}
							if(segCount >= ((macOptions.addressSize == AddressSize.MAC) ? 
									MACAddress.MEDIA_ACCESS_CONTROL_DOTTED_SEGMENT_COUNT : 
										MACAddress.MEDIA_ACCESS_CONTROL_DOTTED_64_SEGMENT_COUNT)) {
								throw new AddressStringException(str, "ipaddress.error.too.many.segments");
							}
						}
						maxChars = 4;//for mac: 1111.2222.3333
					} else {
						//we are not base 85, so throw if necessary
						if(extendedCharacterIndex >= 0) {
							throw new AddressStringException(str, extendedCharacterIndex);
						}
						isBase85 = false;
						//end of an ipv4 segment
						if(!validationOptions.allowIPv4) {
							throw new AddressStringException(str, "ipaddress.error.ipv4");
						}
						ipAddressParseData.setVersion(IPVersion.IPV4);
						stringFormatParams = ipv4SpecificOptions;
						if(segCount == 0) {
							parseData.initSegmentData(IPv4Address.SEGMENT_COUNT);
						} else if(segCount >= IPv4Address.SEGMENT_COUNT) {
							throw new AddressStringException(str, "ipaddress.error.ipv4.too.many.segments");
						}
						maxChars = getMaxIPv4StringLength(3, 8);
					}
					if(wildcardCount > 0) {
						if(!stringFormatParams.rangeOptions.allowsWildcard()) {
							throw new AddressStringException(str, "ipaddress.error.no.wildcard");
						}
						//wildcards must appear alone
						if(singleWildcardCount > 0 || rangeWildcardIndex >= 0 || leadingZeroCount > 0 || digitCount > 0 || hexDelimiterIndex >= 0) {
							throw new AddressStringException(str, index, true);
						}
						parseData.setHasWildcard(true);
						parseData.setFlag(segCount, AddressParseData.KEY_WILDCARD, true);
						parseData.setValue(segCount, AddressParseData.KEY_UPPER, isMac ? MACAddress.MAX_VALUE_PER_DOTTED_SEGMENT : IPv4Address.MAX_VALUE_PER_SEGMENT);
						int startIndex = index - wildcardCount;
						assignAttributes(startIndex, index, parseData, segCount, startIndex);
						wildcardCount = 0;
					} else {
						long value;
						int radix;
						int startIndex = index - digitCount;
						int leadingZeroStartIndex = startIndex - leadingZeroCount;
						if(digitCount == 0) {
							boolean noLeadingZeros = leadingZeroCount == 0;
							if(noLeadingZeros && rangeWildcardIndex >= 0 && hexDelimiterIndex < 0) { // we allow an empty range boundary to denote the max value
								if(isMac) {
									value = MACAddress.MAX_VALUE_PER_DOTTED_SEGMENT;
									radix = 16;
								} else {
									value = IPv4Address.MAX_VALUE_PER_SEGMENT;
									radix = 10;
								}
							} else if(noLeadingZeros) {
								// starts with '.', or has two consecutive '.'
								throw new AddressStringException(str, "ipaddress.error.empty.segment.at.index", index);
							} else {
								value = 0;
								isJustZero = true;
								startIndex--;
								if(hexDelimiterIndex >= 0) {
									if(isMac) {
										throw new AddressStringException(str, hexDelimiterIndex);
									}
									if(!ipv4SpecificOptions.inet_aton_hex) {
										throw new AddressStringException(str, "ipaddress.error.ipv4.segment.hex");
									}
									radix = 16;
									hexDelimiterIndex = -1;
								} else if(isMac) {
									if(leadingZeroCount > 0 && !stringFormatParams.allowLeadingZeros) {
										throw new AddressStringException(str, "ipaddress.error.segment.leading.zeros");
									} else if(!stringFormatParams.allowUnlimitedLeadingZeros && leadingZeroCount > maxChars) {
										throw new AddressStringException(str, "ipaddress.error.segment.too.long.at.index", leadingZeroStartIndex);
									} else if(!macSpecificOptions.allowShortSegments && leadingZeroCount < 2) {
										throw new AddressStringException(str, "ipaddress.error.segment.too.short.at.index", leadingZeroStartIndex);
									}
									radix = 16;
								} else if(leadingZeroCount > 0 && ipv4SpecificOptions.inet_aton_octal) {
									radix = 8;
								} else {
									if(leadingZeroCount > 0) {
										if(!stringFormatParams.allowLeadingZeros) {
											throw new AddressStringException(str, "ipaddress.error.segment.leading.zeros");
										}
										ipAddressParseData.setHasIPv4LeadingZeros(true);
									}
									radix = 10;
								}
								leadingZeroCount--;
								parseData.setFlag(segCount, AddressParseData.KEY_STANDARD_STR, true);
								assignAttributes(startIndex, index, parseData, segCount, radix, leadingZeroStartIndex);
							}
							
						} else { // digitCount > 0
							//Note: we cannot do max value check on ipv4 until after all segments have been read due to inet_aton joined segments, 
							//although we can do a preliminary check here that is in fact needed to prevent overflow when calculating values later
							if(digitCount > maxChars) {
								throw new AddressStringException(str, "ipaddress.error.segment.too.long.at.index", leadingZeroStartIndex);
							}
							isSingleWildcard = singleWildcardCount > 0;
							if(isMac || hexDelimiterIndex >= 0) {
								if(isMac) {
									int totalDigits = digitCount + leadingZeroCount;
									if(hexDelimiterIndex >= 0) {
										throw new AddressStringException(str, hexDelimiterIndex);
									} else if(leadingZeroCount > 0 && !stringFormatParams.allowLeadingZeros) {
										throw new AddressStringException(str, "ipaddress.error.segment.leading.zeros");
									} else if(!stringFormatParams.allowUnlimitedLeadingZeros && totalDigits > maxChars) {
										throw new AddressStringException(str, "ipaddress.error.segment.too.long.at.index", leadingZeroStartIndex);
									} else if(!macSpecificOptions.allowShortSegments && totalDigits < 2) {
										throw new AddressStringException(str, "ipaddress.error.segment.too.short.at.index", leadingZeroStartIndex);
									}
								} else if(!ipv4SpecificOptions.inet_aton_hex) {
									throw new AddressStringException(str, "ipaddress.error.ipv4.segment.hex");
								} else {
									ipAddressParseData.set_has_inet_aton_value(true);
								}
								radix = 16;
								if(isSingleWildcard) {
									if(rangeWildcardIndex >= 0) {
										throw new AddressStringException(str, index, true);
									}
									assignSingleWildcard16(currentValueHex, str, startIndex, index, singleWildcardCount, parseData, segCount, leadingZeroStartIndex, stringFormatParams);
									value = 0;
								} else {
									value = currentValueHex;
								}
								hexDelimiterIndex = -1;
								notDecimal = false;
								notOctal = false;
							} else {
								boolean isOctal = leadingZeroCount > 0 && ipv4SpecificOptions.inet_aton_octal;
								if(isOctal) {
									if(notOctal) {
										throw new AddressStringException(str, "ipaddress.error.ipv4.invalid.octal.digit");
									}
									ipAddressParseData.set_has_inet_aton_value(true);
									radix = 8;
									if(isSingleWildcard) {
										if(rangeWildcardIndex >= 0) {
											throw new AddressStringException(str, index, true);
										}
										switchSingleWildcard8(currentValueHex, str, startIndex, index, singleWildcardCount, parseData, segCount, leadingZeroStartIndex, stringFormatParams);
										value = 0;
									} else {
										value = switchValue8(currentValueHex, index - startIndex);
									}
								} else {
									if(notDecimal) {
										throw new AddressStringException(str, "ipaddress.error.ipv4.invalid.decimal.digit");
									}
									if(leadingZeroCount > 0) {
										if(!stringFormatParams.allowLeadingZeros) {
											throw new AddressStringException(str, "ipaddress.error.segment.leading.zeros");
										}
										ipAddressParseData.setHasIPv4LeadingZeros(true);
									}
									radix = 10;
									if(isSingleWildcard) {
										if(rangeWildcardIndex >= 0) {
											throw new AddressStringException(str, index, true);
										}
										switchSingleWildcard10(currentValueHex, str, startIndex, index, singleWildcardCount, parseData, segCount, leadingZeroStartIndex, ipv4SpecificOptions);
										value = 0;
									} else {
										value = switchValue10(currentValueHex, index - startIndex);
										isStandard = true;
									}
								}
							}
							digitCount = 0;
							currentValueHex = 0;
						}
						if(rangeWildcardIndex >= 0) {
							int frontRadix;
							long front;
							int frontStartIndex = rangeWildcardIndex - frontDigitCount, frontEndIndex = rangeWildcardIndex;
							int frontLeadingZeroStartIndex = frontStartIndex - frontLeadingZeroCount;
							if(!stringFormatParams.rangeOptions.allowsRangeSeparator()) {
								throw new AddressStringException(str, "ipaddress.error.no.range");
							} else if(!stringFormatParams.allowLeadingZeros && frontLeadingZeroCount > 0) {
								throw new AddressStringException(str, "ipaddress.error.segment.leading.zeros");
							} else if(frontDigitCount > maxChars) {
								throw new AddressStringException(str, "ipaddress.error.segment.too.long.at.index", frontLeadingZeroStartIndex);
							}
							boolean frontEmpty = frontStartIndex == frontEndIndex;
							if(isMac || frontHexDelimiterIndex >= 0) {
								if(isMac) {
									if(frontHexDelimiterIndex >= 0) {
										throw new AddressStringException(str, frontHexDelimiterIndex);
									} else if(!macSpecificOptions.allowShortSegments && (frontDigitCount + frontLeadingZeroCount) < 2) {
										throw new AddressStringException(str, "ipaddress.error.segment.too.short.at.index", frontLeadingZeroStartIndex);
									}
									if(!frontEmpty) {//we allow the front of a range to be empty in which case it is 0
										front = currentFrontValueHex;
									} else {
										front = 0;
									}
								} else if(!ipv4SpecificOptions.inet_aton_hex) {
									throw new AddressStringException(str, "ipaddress.error.ipv4.segment.hex");
								} else {
									ipAddressParseData.set_has_inet_aton_value(true);
									//Note that here we allow 0x-0x3 or even 0x-3
									if(!frontEmpty) {//we allow the front of a range to be empty in which case it is 0
										front = currentFrontValueHex;
									} else {
										front = 0;
									}
								}
								frontRadix = 16;
							} else { 
								boolean frontIsOctal = frontLeadingZeroCount > 0 && frontHexDelimiterIndex < 0 && ipv4SpecificOptions.inet_aton_octal;
								if(frontIsOctal) {
									if(frontNotOctal) {
										throw new AddressStringException(str, "ipaddress.error.ipv4.invalid.octal.digit");
									}
									ipAddressParseData.set_has_inet_aton_value(true);
									front = switchValue8(currentFrontValueHex, frontEndIndex - frontStartIndex);
									frontRadix = 8;
								} else {
									if(frontNotDecimal) {
										throw new AddressStringException(str, "ipaddress.error.ipv4.invalid.decimal.digit");
									}
									if(frontLeadingZeroCount == 0) {
										if(!frontEmpty) {
											parseData.setFlag(segCount, AddressParseData.KEY_STANDARD_STR, true);
											if(isStandard && leadingZeroCount == 0) {
												parseData.setFlag(segCount, AddressParseData.KEY_STANDARD_RANGE_STR, true);
											}
										}
									} else {
										ipAddressParseData.setHasIPv4LeadingZeros(true);
									}
									if(!frontEmpty) {//we allow the front of a range to be empty in which case it is 0
										front = switchValue10(currentFrontValueHex, frontEndIndex - frontStartIndex);
									} else {
										front = 0;
									}
									frontRadix = 10;
								}
							}
							if(front > value) {
								throw new AddressStringException(str, "ipaddress.error.invalidRange");
							} //else we would have to flip the values and the indices and we would not set or flags[ParseData.STANDARD_RANGE_STR_INDEX]
							if(isJustZero) {
								isJustZero = false;
							} else {
								assignAttributes(frontStartIndex, frontEndIndex, startIndex, index, parseData, segCount, frontLeadingZeroStartIndex, leadingZeroStartIndex, frontRadix, radix);
								parseData.setValue(segCount, 
										AddressParseData.KEY_LOWER, front,
										AddressParseData.KEY_UPPER, value);
							}
							parseData.setFlag(segCount, AddressParseData.KEY_RANGE_WILDCARD, true);
							frontDigitCount = frontLeadingZeroCount = frontWildcardCount = frontSingleWildcardCount = 0;
							frontNotOctal = frontNotDecimal = frontUppercase = false;
							frontHexDelimiterIndex = -1;
							currentFrontValueHex = 0;
							isStandard = false;
							isSingleWildcard = false;
							singleWildcardCount = 0;
							rangeWildcardIndex = -1;
						} else if(isJustZero) {
							isJustZero = false;
						} else if(isSingleWildcard) {
							isSingleWildcard = false;
							singleWildcardCount = 0;
						} else {
							if(isStandard) {
								parseData.setFlag(segCount, AddressParseData.KEY_STANDARD_STR, true);
								isStandard = false;
							}
							assignAttributes(startIndex, index, parseData, segCount, radix, leadingZeroStartIndex);
							parseData.setValue(segCount, 
									AddressParseData.KEY_LOWER, value,
									AddressParseData.KEY_UPPER, value);
						}
						leadingZeroCount = 0;
					}
					parseData.incrementSegmentCount();
					lastSeparatorIndex = index;
					++index;
				}
			} else {
				//this is the case for all IPv6 and MAC segments, as well as the front range of all segments IPv4, IPv6, and MAC
				//they are in the same case because the range character - is the same as one of the separators - for MAC, 
				//so further work is required to distinguish between the front of IPv6/IPv4/MAC range and MAC segment
				//we also handle IPv6 segment and MAC segment in the same place to avoid code duplication
				if((endOfHexSegment = (currentChar == IPv6Address.SEGMENT_SEPARATOR)) || 
						(isRangeChar = (currentChar == Address.RANGE_SEPARATOR)) ||
						(isMac &&
								(isDashedRangeChar = (currentChar == MACAddress.DASHED_SEGMENT_RANGE_SEPARATOR)) ||
								(endOfHexSegment = isSpace = (currentChar == MACAddress.SPACE_SEGMENT_SEPARATOR)))) {
					/*
					 There are 3 cases here, A, B and C.
					 A - we have two MAC segments a-b- 
					 B - we have the front of a range segment, either a-b which is MAC or IPV6,  or a|b or a<space>b which is MAC
					 C - we have a single segment, either a MAC segment a- or an IPv6 or MAC segment a:
					 */
					if(!endOfHexSegment) {
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
						 
						 If we have a '|' character, we have front of range, case B
						*/
						// we know either isRangeChar or isDashedRangeChar is true at this point
						if(isMac) {
							if(macFormat == null) {
								if(rangeWildcardIndex >= 0 && !firstSegmentDashedRange) {
									
									//case A, we have two segments a-b- or a-b| 
								
									//we handle the first segment here, we handle the segment segment in the usual place below
									if(frontHexDelimiterIndex >= 0) {
										throw new AddressStringException(str, frontHexDelimiterIndex);
									}
									if(hexDelimiterIndex >= 0) {
										throw new AddressStringException(str, hexDelimiterIndex);
									}
									if(!macOptions.allowDashed) {
										throw new AddressStringException(str, "ipaddress.mac.error.format");
									}
									macAddressParseData.setFormat(macFormat = MACFormat.DASHED);
									checkCharCounts = false;//counting chars later
									parseData.initSegmentData(MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT);
									if(frontWildcardCount > 0) {
										if(!stringFormatParams.rangeOptions.allowsWildcard()) {
											throw new AddressStringException(str, "ipaddress.error.no.wildcard");
										}
										if(frontSingleWildcardCount > 0 || frontLeadingZeroCount > 0 || frontDigitCount > 0 || frontHexDelimiterIndex >= 0) {//wildcards must appear alone
											throw new AddressStringException(str, rangeWildcardIndex, true);
										}
										parseData.setHasWildcard(true);
										parseData.setFlag(0, AddressParseData.KEY_WILDCARD, true);
										if(isDoubleSegment || digitCount + leadingZeroCount == MAC_DOUBLE_SEGMENT_DIGIT_COUNT) {
											//even when not already identified as a double segment address, which is something we can see
											//only when we reach the end of the address, we may have a-b| where a is * and b is a 6 digit value.
											//Here we are considering the max value of a.
											//If b is 6 digits, we need to consider the max value of * as if we know already it will be double segment.
											//We can do this because the max values will be checked after the address has been parsed,
											//so even if a-b| ends up being a full address a-b|c-d-e-f-a and not a-b|c,
											//the fact that we have 6 digits here will invalidate the first address,
											//so we can safely assume that this address must be a double segment a-b|c even before we have seen that.
											parseData.setValue(0, AddressParseData.KEY_UPPER, MAC_MAX_TRIPLE);
										} else {
											parseData.setValue(0, AddressParseData.KEY_UPPER, MACAddress.MAX_VALUE_PER_SEGMENT);
										}
										int startIndex = rangeWildcardIndex - frontWildcardCount;
										assignAttributes(startIndex, rangeWildcardIndex, parseData, 0, startIndex);
										frontWildcardCount = 0;
										rangeWildcardIndex = -1;
									} else {
										if(!stringFormatParams.allowLeadingZeros && frontLeadingZeroCount > 0) {
											throw new AddressStringException(str, "ipaddress.error.segment.leading.zeros");
										}
										long value = 0;
										int startIndex = rangeWildcardIndex - frontDigitCount;
										int leadingZeroStartIndex = startIndex - frontLeadingZeroCount;
										int endIndex = rangeWildcardIndex;
										if(frontSingleWildcardCount > 0) {
											assignSingleWildcard16(currentFrontValueHex, str, startIndex, endIndex, singleWildcardCount, parseData, 0, leadingZeroStartIndex, stringFormatParams);
										} else {
											value = currentFrontValueHex;
											if(!uppercase) {
												parseData.setFlag(0, AddressParseData.KEY_STANDARD_STR, true);
											}
											assignAttributes(startIndex, endIndex, parseData, 0, MACAddress.DEFAULT_TEXTUAL_RADIX, leadingZeroStartIndex);
											parseData.setValue(0, 
													AddressParseData.KEY_LOWER, value,
													AddressParseData.KEY_UPPER, value);
										}
										frontDigitCount = frontLeadingZeroCount = frontWildcardCount = frontSingleWildcardCount = 0;
										frontNotOctal = frontNotDecimal = frontUppercase = false;
										frontHexDelimiterIndex = rangeWildcardIndex = -1;
										currentFrontValueHex = 0;
									}
									parseData.incrementSegmentCount();
									//end of handling the first segment a- in a-b-
									//below we handle b- by setting endOfSegment here
									endOfHexSegment = isRangeChar;
								} else {//we will treat this as the front of a range
									if(isDashedRangeChar) {
										firstSegmentDashedRange = true;
									} else {
										endOfHexSegment = firstSegmentDashedRange;
									}
								}
							} else {
								if(macFormat == MACFormat.DASHED) {
									endOfHexSegment = isRangeChar;
								} else {
									if(isDashedRangeChar) {
										throw new AddressStringException(str, index);
									}
								}
							}
						}
						isDashedRangeChar = false;//we don't need this var any more, so set it back to default value
						if(!endOfHexSegment) {
							if(extendedCharacterIndex < 0) {
								//case B
								if(rangeWildcardIndex >= 0) {
									if(isBase85) {
										if(extendedCharacterIndex < 0) {
											extendedCharacterIndex = index;
										}
									} else {
										throw new AddressStringException(str, index, true);
									}
								} else {
									//here is where we handle the front 'a' of a range like 'a-b'
									rangeWildcardIndex = index;
									frontIsStandardRange = isRangeChar;
									frontDigitCount = digitCount;
									frontLeadingZeroCount = leadingZeroCount;
									if(frontDigitCount == 0) {
										if(frontLeadingZeroCount != 0) {
											frontDigitCount++;
											frontLeadingZeroCount--;
										} //else we allow empty front of range to be considered 0
									}
									frontNotOctal = notOctal;
									frontNotDecimal = notDecimal;
									frontUppercase = uppercase;
									frontHexDelimiterIndex = hexDelimiterIndex;
									frontWildcardCount = wildcardCount;
									frontSingleWildcardCount = singleWildcardCount;
									currentFrontValueHex = currentValueHex;
									leadingZeroCount = digitCount = 0;
									notOctal = notDecimal = uppercase = false;
									hexDelimiterIndex = -1;
									wildcardCount = singleWildcardCount = 0;
									currentValueHex = 0;
								}
							}
							++index;
						}
					}
					//now we know if we are looking at the end of a segment, so we handle that now
					if(endOfHexSegment) { //either MAC segment a- or a: or 'a ', or IPv6 a:
						//case C, an ipv6 or mac segment
						if(hexDelimiterIndex >= 0) {
							if(!isSingleSegment) {
								throw new AddressStringException(str, hexDelimiterIndex);
							}
							hexDelimiterIndex = -1;
						}
						int segCount = parseData.getSegmentCount();
						int maxChars;
						if(isMac) {
							if(segCount == 0) {
								if(isSingleSegment) {
									parseData.initSegmentData(1);
								} else {
									if(!(isRangeChar ? macOptions.allowDashed : (isSpace ? macOptions.allowSpaceDelimited : macOptions.allowColonDelimited))) {
										throw new AddressStringException(str, "ipaddress.mac.error.format");
									}
									if(isRangeChar) {
										macAddressParseData.setFormat(macFormat = MACFormat.DASHED);
										checkCharCounts = false;//counting chars later
									} else {
										macAddressParseData.setFormat(macFormat = (isSpace ? MACFormat.SPACE_DELIMITED : MACFormat.COLON_DELIMITED));						
									}
									parseData.initSegmentData(MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT);
								}
							} else {
								if(isRangeChar ? (macFormat != MACFormat.DASHED) : (macFormat != (isSpace ? MACFormat.SPACE_DELIMITED : MACFormat.COLON_DELIMITED))) {
									throw new AddressStringException(str, "ipaddress.mac.error.mix.format.characters.at.index", index);
								}
								if(segCount >= ((macOptions.addressSize == AddressSize.MAC) ? 
										MACAddress.MEDIA_ACCESS_CONTROL_SEGMENT_COUNT : 
											MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT)) {
									throw new AddressStringException(str, "ipaddress.error.too.many.segments");
								}
							}
							maxChars = MACAddressSegment.MAX_CHARS;//will be ignored for single or double segments due to countedCharacters and countingCharsLater booleans
						} else {
							//we are not base 85, so throw if necessary
							if(extendedCharacterIndex >= 0) {
								throw new AddressStringException(str, extendedCharacterIndex);
							}
							isBase85 = false;
							if(segCount == 0) {
								parseData.initSegmentData(isSingleSegment ? 1 : IPv6Address.SEGMENT_COUNT);
							} else {
								if(segCount >= IPv6Address.SEGMENT_COUNT) {
									throw new AddressStringException(str, "ipaddress.error.too.many.segments");
								}
								IPVersion version = ipAddressParseData.getProviderIPVersion();
								if(version == null || version.isIPv4()) {
									throw new AddressStringException(str, "ipaddress.error.ipv6.separator");
								}
							}
							if(!validationOptions.allowIPv6) {
								throw new AddressStringException(str, "ipaddress.error.ipv6");
							}
							ipAddressParseData.setVersion(IPVersion.IPV6);
							stringFormatParams = ipv6SpecificOptions;
							maxChars = IPv6AddressSegment.MAX_CHARS;//will be ignored for single segment due to countedCharacters and countingCharsLater boolean
						}
						if(wildcardCount > 0) {
							if(!stringFormatParams.rangeOptions.allowsWildcard()) {
								throw new AddressStringException(str, "ipaddress.error.no.wildcard");
							}
							if(singleWildcardCount > 0 || rangeWildcardIndex >= 0 || leadingZeroCount > 0 || digitCount > 0) {//wildcards must appear alone
								throw new AddressStringException(str, index, true);
							}
							parseData.setHasWildcard(true);
							parseData.setFlag(segCount, AddressParseData.KEY_WILDCARD, true);
							parseData.setValue(segCount, AddressParseData.KEY_UPPER, isMac ? (isDoubleSegment ? MAC_MAX_TRIPLE : MACAddress.MAX_VALUE_PER_SEGMENT) : IPv6Address.MAX_VALUE_PER_SEGMENT);
							int startIndex = index - wildcardCount;
							assignAttributes(startIndex, index, parseData, segCount, startIndex);
							parseData.incrementSegmentCount();
							wildcardCount = 0;
						} else {
							if(index == strStartIndex) {
								if(isMac) {
									throw new AddressStringException(str, "ipaddress.error.empty.segment.at.index", index);
								}
								if(index + 1 == strEndIndex) {
									throw new AddressStringException(str, "ipaddress.error.too.few.segments");
								}
								if(str.charAt(index + 1) != IPv6Address.SEGMENT_SEPARATOR) {
									throw new AddressStringException(str, "ipaddress.error.ipv6.cannot.start.with.single.separator");
								}
								//no segment, so we do not increment segmentCount
							} else if(index == lastSeparatorIndex + 1) {
								if(isMac) {
									throw new AddressStringException(str, "ipaddress.error.empty.segment.at.index", index);
								}
								if(parseData.getConsecutiveSeparatorIndex() >= 0) {
									throw new AddressStringException(str, "ipaddress.error.ipv6.ambiguous");
								}
								parseData.setConsecutiveSeparatorSegmentIndex(segCount);
								parseData.setConsecutiveSeparatorIndex(index - 1);
								assignAttributes(index, index, parseData, segCount, index);
								parseData.incrementSegmentCount();
							} else {
								if(!stringFormatParams.allowLeadingZeros && leadingZeroCount > 0) {
									throw new AddressStringException(str, "ipaddress.error.segment.leading.zeros");
								}
								long value;
								int startIndex = index - digitCount;
								int leadingZeroStartIndex = startIndex - leadingZeroCount;
								if(checkCharCounts && !stringFormatParams.allowUnlimitedLeadingZeros && (digitCount + leadingZeroCount) > maxChars) {
									throw new AddressStringException(str, "ipaddress.error.segment.too.long.at.index", leadingZeroStartIndex);
								} else if(isMac && !macSpecificOptions.allowShortSegments && (digitCount + leadingZeroCount) < 2) {
									throw new AddressStringException(str, "ipaddress.error.segment.too.short.at.index", leadingZeroStartIndex);
								}
								if(digitCount == 0) {
									if(rangeWildcardIndex >= 0 && leadingZeroCount == 0) {//we allow an empty range boundary to denote the max value
										value = isMac ? MACAddress.MAX_VALUE_PER_SEGMENT : IPv6Address.MAX_VALUE_PER_SEGMENT;
									} else {
										//note we know there is a zero as we have already checked for empty segments so here we know leadingZeroCount is non-zero
										startIndex--;
										leadingZeroCount--;
										isJustZero = true;
										parseData.setFlag(segCount, AddressParseData.KEY_STANDARD_STR, true);
										assignAttributes(startIndex, index, parseData, segCount, leadingZeroStartIndex);
										value = 0;
									}
								} else if(checkCharCounts && digitCount > maxChars) {
									throw new AddressStringException(str, "ipaddress.error.segment.too.long.at.index", leadingZeroStartIndex);
								} else { // digitCount > 0
									if(isSingleWildcard = (singleWildcardCount > 0)) {
										if(rangeWildcardIndex >= 0) {
											throw new AddressStringException(str, index, true);
										}
										if(isSingleIPv6Hex) {//We need this special call here because single ipv6 hex is 128 bits and cannot fit into a long
											parseSingleSegmentSingleWildcard16(currentValueHex, str, startIndex, index, singleWildcardCount, parseData, segCount, leadingZeroStartIndex, stringFormatParams);
										} else {
											assignSingleWildcard16(currentValueHex, str, startIndex, index, singleWildcardCount, parseData, segCount, leadingZeroStartIndex, stringFormatParams);
										}
										value = 0;
									} else {
										if(isSingleIPv6Hex) { //We need this special call here because single ipv6 hex is 128 bits and cannot fit into a long
											int midIndex = index - 16;
											if(startIndex < midIndex) {
												extendedValue = parseLong16(str, startIndex, midIndex);
												value = parseLong16(str, midIndex, index);
											} else {
												value = currentValueHex;
											}
										} else {
											value = currentValueHex;
										}
										isStandard = !uppercase;
									}
									notOctal = notDecimal = uppercase = false;
									digitCount = 0;
									currentValueHex = 0;
								}
								if(rangeWildcardIndex >= 0) {
									int frontStartIndex = rangeWildcardIndex - frontDigitCount, frontEndIndex = rangeWildcardIndex;
									int frontLeadingZeroStartIndex = frontStartIndex - frontLeadingZeroCount;
									int frontTotalDigitCount = frontDigitCount + frontLeadingZeroCount;
									if(!stringFormatParams.rangeOptions.allowsRangeSeparator()) {
										throw new AddressStringException(str, "ipaddress.error.no.range");
									} else if(frontHexDelimiterIndex >= 0 && !isSingleSegment) {
										throw new AddressStringException(str, frontHexDelimiterIndex);
									} else if(!stringFormatParams.allowLeadingZeros && frontLeadingZeroCount > 0) {
										throw new AddressStringException(str, "ipaddress.error.segment.leading.zeros");
									} else if(isMac && !macSpecificOptions.allowShortSegments && frontTotalDigitCount < 2) {
										throw new AddressStringException(str, "ipaddress.error.segment.too.short.at.index", frontLeadingZeroStartIndex);
									} else if(checkCharCounts) { 
										if(frontDigitCount > maxChars) {
											throw new AddressStringException(str, "ipaddress.error.segment.too.long.at.index", frontLeadingZeroStartIndex);
										} else if(!stringFormatParams.allowUnlimitedLeadingZeros && frontTotalDigitCount > maxChars) {
											throw new AddressStringException(str, "ipaddress.error.segment.too.long.at.index", frontLeadingZeroStartIndex);
										}
									}
									long front, extendedFront;
									boolean frontEmpty;
									if(isSingleIPv6Hex) {//We need this special block here because single ipv6 hex is 128 bits and cannot fit into a long
										frontEmpty = false;
										int frontMidIndex = frontEndIndex - 16;
										extendedFront = parseLong16(str, frontStartIndex, frontMidIndex);
										front = parseLong16(str, frontMidIndex, frontEndIndex);
									} else {
										frontEmpty = frontStartIndex == frontEndIndex;
										if(!frontEmpty) {
											front = currentFrontValueHex;
										} else {
											front = 0;
										}
										extendedFront = 0;
										if(front > value) {
											throw new AddressStringException(str, "ipaddress.error.invalidRange");
										} //else we would have to flip the values and the indices and we would not set or flags[ParseData.STANDARD_RANGE_STR_INDEX]
									}
									if(isJustZero) {
										isJustZero = false;
									} else {
										if(!frontUppercase && frontLeadingZeroCount == 0 && !frontEmpty) {
											if(isStandard && leadingZeroCount == 0 && frontIsStandardRange) {
												parseData.setFlag(segCount, AddressParseData.KEY_STANDARD_STR, true);
												parseData.setFlag(segCount, AddressParseData.KEY_STANDARD_RANGE_STR, true);
											} else {
												parseData.setFlag(segCount, AddressParseData.KEY_STANDARD_STR, true);
											}
										}
										assignAttributes(frontStartIndex, frontEndIndex, startIndex, index, parseData, segCount, frontLeadingZeroStartIndex, leadingZeroStartIndex, IPv6Address.DEFAULT_TEXTUAL_RADIX, IPv6Address.DEFAULT_TEXTUAL_RADIX);
										if(isSingleIPv6Hex) {//We need this special call here because single ipv6 hex is 128 bits and cannot fit into a long
											parseData.setValue(segCount, 
													AddressParseData.KEY_LOWER, front,
													AddressParseData.KEY_UPPER, value,
													AddressParseData.KEY_EXTENDED_LOWER, extendedFront,
													AddressParseData.KEY_EXTENDED_UPPER, extendedValue);
										} else {
											parseData.setValue(segCount, 
													AddressParseData.KEY_LOWER, front,
													AddressParseData.KEY_UPPER, value);
										}
									}
									parseData.setFlag(segCount, AddressParseData.KEY_RANGE_WILDCARD, true);
									frontDigitCount = frontLeadingZeroCount = frontWildcardCount = frontSingleWildcardCount = 0;
									frontNotOctal = frontNotDecimal = frontUppercase = false;
									frontHexDelimiterIndex = -1;
									currentFrontValueHex = 0;
									isStandard = false;
									isSingleWildcard = false;
									singleWildcardCount = 0;
									rangeWildcardIndex = -1;
								} else if(isJustZero) {
									isJustZero = false;
								} else if(isSingleWildcard) {
									isSingleWildcard = false;
									singleWildcardCount = 0;
								} else {
									if(isStandard) {
										parseData.setFlag(segCount, AddressParseData.KEY_STANDARD_STR, true);
										isStandard = false;
									}
									assignAttributes(startIndex, index, parseData, segCount, IPv6Address.DEFAULT_TEXTUAL_RADIX /* same as MAC, so no problem */, leadingZeroStartIndex);
									if(isSingleIPv6Hex) {//We need this special call here because single ipv6 hex is 128 bits and cannot fit into a long
										parseData.setValue(segCount, 
												AddressParseData.KEY_LOWER, value,
												AddressParseData.KEY_UPPER, value,
												AddressParseData.KEY_EXTENDED_LOWER, extendedValue,
												AddressParseData.KEY_EXTENDED_UPPER, extendedValue);
									} else {
										parseData.setValue(segCount, 
												AddressParseData.KEY_LOWER, value,
												AddressParseData.KEY_UPPER, value);	
									}
								}
								parseData.incrementSegmentCount();
								leadingZeroCount = 0;
							}
						}
						lastSeparatorIndex = index;
						isSpace = endOfHexSegment = false;
						++index;
					}
					isRangeChar = false;
				} else if(currentChar >= 'A' && currentChar <= 'F') {
					++digitCount;
					++index;
					currentValueHex = (currentValueHex << 4) | charArray[currentChar];
					notOctal = notDecimal = uppercase = true;
				} else if(currentChar == IPAddress.PREFIX_LEN_SEPARATOR) {
					//we are not base 85, so throw if necessary
					if(isMac) {
						throw new AddressStringException(str, index);
					}
					strEndIndex = index;
					ipAddressParseData.setHasPrefixSeparator(true);
					ipAddressParseData.setQualifierIndex(index + 1);
				} else if(currentChar == Address.SEGMENT_WILDCARD || (isZoneChar = (currentChar == Address.SEGMENT_SQL_WILDCARD))) {
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
					if(isZoneChar && 
							!isMac && 
							ipv6SpecificOptions.allowZone &&
							((parseData.getSegmentCount() > 0 && (isEmbeddedIPv4 || ipAddressParseData.getProviderIPVersion() == IPVersion.IPV6) /* at end of IPv6 regular or mixed */) || 
									(leadingZeroCount + digitCount == 32 && (rangeWildcardIndex < 0 || frontLeadingZeroCount + frontDigitCount == 32) /* at end of ipv6 single segment */) || 
									wildcardCount == index /* all wildcards so far */)
							) {
						//we are not base 85, so throw if necessary
						if(extendedCharacterIndex >= 0) {
							throw new AddressStringException(str, extendedCharacterIndex);
						}
						isBase85 = false;
						strEndIndex = index;
						ipAddressParseData.setZoned(true);
						ipAddressParseData.setQualifierIndex(index + 1);
					} else {
						++wildcardCount;
						++index;
					}
					isZoneChar = false;
				} else if(currentChar == Address.SEGMENT_SQL_SINGLE_WILDCARD) {
					++digitCount;
					++index;
					++singleWildcardCount;
				} else if(currentChar == 'x') {
					if(digitCount > 0 || leadingZeroCount != 1 || hexDelimiterIndex >= 0 || singleWildcardCount > 0) {
						if(isBase85) {
							if(extendedCharacterIndex < 0) {
								extendedCharacterIndex = index;
							}
						} else {
							throw new AddressStringException(str, index, true);
						}
					} else {
						hexDelimiterIndex = index;
						leadingZeroCount = 0;
					}
					++index;
				//the remaining possibilities are base85 only
				} else if(currentChar == IPAddressLargeDivision.EXTENDED_DIGITS_RANGE_SEPARATOR) {
					if(isBase85) {
						if(extendedCharacterIndex < 0) {
							extendedCharacterIndex = index;
						}
						int base85TotalDigits = index - strStartIndex;
						if(base85TotalDigits == IPV6_BASE85_SINGLE_SEGMENT_DIGIT_COUNT) {
							extendedRangeWildcardIndex = index;
						} else {
							throw new AddressStringException(str, extendedCharacterIndex);
						}
					} else {
						throw new AddressStringException(str, index);
					}
					++index;
				} else if(currentChar == IPv6Address.ALTERNATIVE_ZONE_SEPARATOR) {
					if(isBase85 && !isMac && ipv6SpecificOptions.allowZone) {
						strEndIndex = index;
						ipAddressParseData.setZoned(true);
						ipAddressParseData.setBase85Zoned(true);
						ipAddressParseData.setQualifierIndex(index + 1);
					} else {
						throw new AddressStringException(str, index);
					}
				} else {
					if(isBase85) {
						if(currentChar < 0 || currentChar > extendedChars.length - 1) {
							throw new AddressStringException(str, index);
						}
						int val = extendedChars[currentChar];
						if(val == 0) {//note that we already check for the currentChar '0' character at another else/if block, so any other character mapped to the value 0 is an invalid character
							throw new AddressStringException(str, index);
						}
						if(extendedCharacterIndex < 0) {
							extendedCharacterIndex = index;
						}
					} else {
						throw new AddressStringException(str, index);
					}
					++index;
				}
			}
		}
	}

	private static void checkSegments(
			final String fullAddr,
			final MACAddressStringParameters validationOptions,
			final ParsedMACAddress parseData) throws AddressStringException {
		MACFormat format = parseData.getFormat();
		if(format != null) {
			AddressParseData addressParseData = parseData.getAddressParseData();
			boolean hasWildcardSeparator = addressParseData.hasWildcard() && validationOptions.getFormatParameters().allowWildcardedSeparator;
			//note that too many segments is checked inside the general parsing method
			int segCount = addressParseData.getSegmentCount();
			if(format == MACFormat.DOTTED) {
				if(segCount <= MACAddress.MEDIA_ACCESS_CONTROL_DOTTED_SEGMENT_COUNT && validationOptions.addressSize != AddressSize.EUI64) {
					if(!hasWildcardSeparator && segCount != MACAddress.MEDIA_ACCESS_CONTROL_DOTTED_SEGMENT_COUNT) {
						throw new AddressStringException(fullAddr, "ipaddress.error.too.few.segments");
					}
				} else if(!hasWildcardSeparator && segCount < MACAddress.MEDIA_ACCESS_CONTROL_DOTTED_64_SEGMENT_COUNT) {
					throw new AddressStringException(fullAddr, "ipaddress.error.too.few.segments");
				} else {
					parseData.setExtended(true);
				}
			} else {
				if(segCount > 2) {
					if(segCount <= MACAddress.MEDIA_ACCESS_CONTROL_SEGMENT_COUNT && validationOptions.addressSize != AddressSize.EUI64) {
						if(!hasWildcardSeparator && segCount != MACAddress.MEDIA_ACCESS_CONTROL_SEGMENT_COUNT) {
							throw new AddressStringException(fullAddr, "ipaddress.error.too.few.segments");
						}
					} else if(!hasWildcardSeparator && segCount < MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT) {
						throw new AddressStringException(fullAddr, "ipaddress.error.too.few.segments");
					} else {
						parseData.setExtended(true);
					}
					if(parseData.getFormat() == MACFormat.DASHED) {
						int max = MACAddress.MAX_VALUE_PER_SEGMENT;
						int maxChars = MACAddressSegment.MAX_CHARS;
						for(int i = 0; i < segCount; i++) {
							checkMaxValues(
									fullAddr,
									addressParseData,
									i,
									validationOptions.getFormatParameters(),
									max,
									maxChars,
									maxChars);
						}
					}
				} else {
					if(parseData.getFormat() == MACFormat.DASHED) {
						//for single segment, we have already counted the exact number of hex digits
						//for double segment, we have already counted the exact number of hex digits in some cases and not others.
						//Basically, for address like a-b we have already counted the exact number of hex digits,
						//for addresses starting with a|b- or a-b| we have not,
						//but rather than figure out which are checked out which not it's just as quick to check them all here
						if(parseData.isDoubleSegment()) {
							MACAddressStringFormatParameters params = validationOptions.getFormatParameters();
							checkMaxValues(fullAddr, addressParseData, 0, params, MAC_MAX_TRIPLE, MAC_DOUBLE_SEGMENT_DIGIT_COUNT, MAC_DOUBLE_SEGMENT_DIGIT_COUNT);
							if(parseData.isExtended()) {
								checkMaxValues(fullAddr, addressParseData, 1, params, MAC_MAX_QUINTUPLE, MAC_EXTENDED_DOUBLE_SEGMENT_DIGIT_COUNT, MAC_EXTENDED_DOUBLE_SEGMENT_DIGIT_COUNT);
							} else {
								checkMaxValues(fullAddr, addressParseData, 1, params, MAC_MAX_TRIPLE, MAC_DOUBLE_SEGMENT_DIGIT_COUNT, MAC_DOUBLE_SEGMENT_DIGIT_COUNT);
							}
						}
					} else if(!hasWildcardSeparator) {
						throw new AddressStringException(fullAddr, "ipaddress.error.too.few.segments");
					}
					
					
					if(validationOptions.addressSize == AddressSize.EUI64) {
						parseData.setExtended(true);
					}
				}
			}
		} //else single segment
	}

	private static IPAddressProvider chooseProvider(
			final HostIdentifierString originator,
			final CharSequence fullAddr,
			final IPAddressStringParameters validationOptions,
			final ParsedIPAddress parseData,
			final ParsedHostIdentifierStringQualifier qualifier) throws AddressStringException {
		IPVersion version = parseData.getProviderIPVersion();
		if(version == null) {
			version = qualifier.inferVersion(validationOptions);
			IPVersion optionsVersion = validationOptions.inferVersion();
			if(version == null) {
				parseData.setVersion(version = optionsVersion);
			} else if(optionsVersion != null && !version.equals(optionsVersion)) {
				throw new AddressStringException(fullAddr, version == IPVersion.IPV6 ? "ipaddress.error.ipv6" : "ipaddress.error.ipv4");
			}
			AddressParseData addressParseData = parseData.getAddressParseData();
			if(addressParseData.isProvidingEmpty()) {
				Integer networkPrefixLength = qualifier.getNetworkPrefixLength();
				if(networkPrefixLength != null) {
					int prefLen = networkPrefixLength;
					if(validationOptions == IPAddressString.DEFAULT_VALIDATION_OPTIONS && networkPrefixLength <= IPv6Address.BIT_COUNT) {
						int index = version == null ? 0 : version.isIPv4() ? 1 : 2;
						MaskCreator cached[] = MASK_CACHE[index];
						if(cached == null) {
							MASK_CACHE[index] = cached = new MaskCreator[IPv6Address.BIT_COUNT + 1];
						}
						MaskCreator result = cached[prefLen];
						if(result == null) {
							cached[prefLen] = result = new MaskCreator(networkPrefixLength, version, IPAddressString.DEFAULT_VALIDATION_OPTIONS);
						}
						return result;
					}
					return new MaskCreator(networkPrefixLength, version, validationOptions);
				} else {
					//Note: we do not support loopback with zone, it seems the loopback is never associated with a link-local zone
					if(validationOptions.emptyIsLoopback) {
						if(validationOptions == IPAddressString.DEFAULT_VALIDATION_OPTIONS) {
							return LOOPBACK_CACHE;
						}
						return new LoopbackCreator(validationOptions);
					}
					return IPAddressProvider.EMPTY_PROVIDER;
				}
			} else { //isAll
				//We also need the AllCreator to use the equivalent prefix length, much like in ParsedIPAddress
				return new AllCreator(qualifier, version, originator, validationOptions);
			}
		} else {
			if(parseData.isZoned() && version.isIPv4()) {
				throw new AddressStringException(fullAddr, "ipaddress.error.only.ipv6.has.zone");
			}
			parseData.setQualifier(qualifier);
			checkSegments(fullAddr, validationOptions, parseData);
			return parseData;
		}
	}

	private static void checkMaxValues(
			final CharSequence fullAddr,
			AddressParseData parseData,
			int segmentIndex,
			AddressStringFormatParameters params,
			long maxValue,
			long maxDigitCount,
			long maxUpperDigitCount) throws AddressStringException {
		int lowerRadix = parseData.getRadix(segmentIndex, AddressParseData.KEY_LOWER_RADIX);
		if(parseData.getFlag(segmentIndex, AddressParseData.KEY_SINGLE_WILDCARD)) {
			if(parseData.getValue(segmentIndex, AddressParseData.KEY_LOWER) > maxValue) {
				throw new AddressStringException(fullAddr, "ipaddress.error.ipv4.segment.too.large");
			}
			if(parseData.getValue(segmentIndex, AddressParseData.KEY_UPPER) > maxValue) {
				parseData.setValue(segmentIndex, AddressParseData.KEY_UPPER, maxValue);
			}
			if(!params.allowUnlimitedLeadingZeros) {
				if(parseData.getIndex(segmentIndex, AddressParseData.KEY_LOWER_STR_END_INDEX) - parseData.getIndex(segmentIndex, AddressParseData.KEY_LOWER_STR_DIGITS_INDEX) -  getStringPrefixCharCount(lowerRadix) > maxDigitCount) {
					throw new AddressStringException(fullAddr, "ipaddress.error.segment.too.long");
				}
			}
		} else {
			if(parseData.getValue(segmentIndex, AddressParseData.KEY_UPPER) > maxValue) {
				throw new AddressStringException(fullAddr, "ipaddress.error.ipv4.segment.too.large");
			}
			int upperRadix = parseData.getRadix(segmentIndex, AddressParseData.KEY_UPPER_RADIX);
			if(!params.allowUnlimitedLeadingZeros) {
				if(parseData.getIndex(segmentIndex, AddressParseData.KEY_LOWER_STR_END_INDEX) - parseData.getIndex(segmentIndex, AddressParseData.KEY_LOWER_STR_DIGITS_INDEX) - getStringPrefixCharCount(lowerRadix) > maxDigitCount) {
					throw new AddressStringException(fullAddr, "ipaddress.error.segment.too.long");
				}
				if(parseData.getIndex(segmentIndex, AddressParseData.KEY_UPPER_STR_END_INDEX) - parseData.getIndex(segmentIndex, AddressParseData.KEY_UPPER_STR_DIGITS_INDEX) - getStringPrefixCharCount(upperRadix) > maxUpperDigitCount) {
					throw new AddressStringException(fullAddr, "ipaddress.error.segment.too.long");
				}
			}
		}
	}

	private static void checkSegments(
			final CharSequence fullAddr,
			final IPAddressStringParameters validationOptions,
			final IPAddressParseData parseData) throws AddressStringException {
		AddressParseData addressParseData = parseData.getAddressParseData();
		int segCount = addressParseData.getSegmentCount();
		IPVersion version = parseData.getProviderIPVersion();
		if(version.isIPv4()) {
			int missingCount = IPv4Address.SEGMENT_COUNT - segCount;
			final IPv4AddressStringParameters ipv4Options = validationOptions.getIPv4Parameters();
			boolean hasWildcardSeparator = addressParseData.hasWildcard() && ipv4Options.allowWildcardedSeparator;
			
			//single segments are handled in the parsing code with the allowSingleSegment setting
			if(missingCount > 0 && segCount > 1) {
				if(ipv4Options.inet_aton_joinedSegments) {
					parseData.set_inet_aton_joined(true);
				} else if(!hasWildcardSeparator) {
					throw new AddressStringException(fullAddr, "ipaddress.error.ipv4.too.few.segments");
				}
			}
			//here we check whether values are too large or strings too long
			long oneSegmentMax = getMaxIPv4Value(1);
			for(int i = 0; i < segCount; i++) {
				long max;
				int maxDigits, maxUpperDigits;
				int lowerRadix = addressParseData.getRadix(i, AddressParseData.KEY_LOWER_RADIX);
				int upperRadix = addressParseData.getRadix(i, AddressParseData.KEY_UPPER_RADIX);
				if(i == segCount - 1 && missingCount > 0 && ipv4Options.inet_aton_joinedSegments) {
					max = getMaxIPv4Value(missingCount + 1);
					maxDigits = getMaxIPv4StringLength(missingCount, lowerRadix);
					maxUpperDigits = (upperRadix != lowerRadix) ? getMaxIPv4StringLength(missingCount, upperRadix) : maxDigits;
				} else {
					max = oneSegmentMax;
					maxDigits = getMaxIPv4StringLength(0, lowerRadix);
					maxUpperDigits = (upperRadix != lowerRadix) ? getMaxIPv4StringLength(0, upperRadix) : maxDigits;
				}
				checkMaxValues(
						fullAddr,
						addressParseData,
						i,
						ipv4Options,
						max,
						maxDigits,
						maxUpperDigits);
			}
		} else {
			int totalSegmentCount = segCount;
			if(parseData.isProvidingMixedIPv6()) {
				totalSegmentCount += IPv6Address.MIXED_REPLACED_SEGMENT_COUNT;
			}
			boolean hasWildcardSeparator = addressParseData.hasWildcard() && validationOptions.getIPv6Parameters().allowWildcardedSeparator;
			if(!hasWildcardSeparator && totalSegmentCount != 1 && totalSegmentCount < IPv6Address.SEGMENT_COUNT && !parseData.isCompressed()) {
				throw new AddressStringException(fullAddr, "ipaddress.error.too.few.segments");
			}
		}
	}
	
	@Override
	public int validatePrefix(CharSequence fullAddr, IPVersion version) throws AddressStringException {
		return validatePrefixImpl(fullAddr, version);
	}

	static int validatePrefixImpl(CharSequence fullAddr, IPVersion version) throws AddressStringException {
		ParsedHostIdentifierStringQualifier qualifier = validatePrefix(fullAddr, null, DEFAULT_PREFIX_OPTIONS, null, 0, fullAddr.length(), version);
		if(qualifier == null) {
			throw new AddressStringException(fullAddr.toString(), "ipaddress.error.invalidCIDRPrefix");
		}
		return qualifier.getNetworkPrefixLength();
	}

/* 
	Here is the call tree for validating qualifiers of either hosts or addresses:

	validateHost
		-> parseHostQualifier for addresses with [], parsing the part inside the []
			-> parsePortOrService handles as port
			-> parsePrefix
				-> validatePrefix
					-> parseValidatedPrefix
					-> parsePortOrService (see above)
				or handles as mask
			-> parseZone
				-> parsePrefix (see above)
				or handles as zone
		-> parseHostNameQualifier for (a) domains and string host names and (b) addresses with [], parsing the part following the ]
			-> parsePortOrService handles as port 
			-> parsePrefix (see above)
		-> parseAddressQualifier for address with no [], and also handles splitting off the port for two such calls
			-> parsePrefix (see above)
			-> parseZone (see above)
		-> checkSpecialHosts for domains that map to addresses
			-> parseAddressQualifier (see above)
	
	validateAddressImpl
		-> parseAddressQualifier for addresses
	
	Note: we never allow a mask/port combo.  It would get very hairy if we did, since port looks a lot like an ipv6 segment
	
	-----------------------------------------------------------------
	
	We merge qualifiers, with calls to mergePrefix, in checkSpecialHosts, and in validateHost handling [] addresses
	 	
	-----------------------------------------------------------------
	
	no catch and no return null:
		parseQualifier
		parseAddressQualifier
		parseHostQualifier
		parsePortOrService
		parseValidatedPrefix
		parseZone
	
	checkSpecialHosts: catches everything, also can return null
	parsePrefix: evaluates if prefix through validatePrefix, catches and translates mask exceptions, no return null
		validatePrefix: evaluates if prefix, catches and evaluates if prefix and port, returns null

	Basically, validatePrefix is the only one that does not make a final decision on what it is looking at (ie valid or throw),
		that is because parsePrefix needs to evaluate as a mask if not a prefix
*/
	/*
	 https://tools.ietf.org/html/rfc5952 has some other possibly ways of denoting port numbers.
   o  [2001:db8::1]:80
   o  2001:db8::1:80
   o  2001:db8::1.80
   o  2001:db8::1 port 80
   o  2001:db8::1p80
   o  2001:db8::1#80
   Currently we handle the first two.  The 3rd, 5th and 6th could be considered, although I don't think I've seen them anywhere (maybe the 3rd?)
   Probably could handle those fairly easily though, except for '.'
   Problem with '.' is if it follows IPv4
	 */
	
	private static ParsedHostIdentifierStringQualifier parsePortOrService(
			final CharSequence fullAddr,
			final CharSequence zone,
			final HostNameParameters validationOptions,
			final int index,
			final int endIndex) throws AddressStringException {
		boolean isPort = true;
		boolean hasLetter = false;
		int digitCount = 0;
		int charCount = 0;
		int lastHyphen = -1;
		boolean isAll = false;
		for(int i = index; i < endIndex; i++) {
			char c = fullAddr.charAt(i);
			if(c >= '1' && c <= '9') {
				++digitCount;
				++charCount;
			} else if(c == '0') {
				if(digitCount > 0) {
					++digitCount;
				}
				++charCount;
			} else {
				//http://www.iana.org/assignments/port-numbers
				//valid service name chars:
				//https://tools.ietf.org/html/rfc6335#section-5.1
				//https://tools.ietf.org/html/rfc6335#section-10.1
				isPort = false;
				boolean isHyphen = false;
				if((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (isHyphen = (c == '-')) || (isAll = (c == Address.SEGMENT_WILDCARD))) {
					if(isHyphen) {
						if(i == index) {
							throw new AddressStringException(fullAddr.toString(), "ipaddress.host.error.invalid.service.hyphen.start");
						} else if(i - 1 == lastHyphen) {
							throw new AddressStringException(fullAddr.toString(), "ipaddress.host.error.invalid.service.hyphen.consecutive");
						} else if(i == endIndex - 1) {
							throw new AddressStringException(fullAddr.toString(), "ipaddress.host.error.invalid.service.hyphen.end");
						}
						lastHyphen = i;
					} else if(isAll) {
						if(i > index) {
							throw new AddressStringException(fullAddr.toString(), i, true);
						} else if(i + 1 < endIndex) {
							throw new AddressStringException(fullAddr.toString(), i + 1, true);
						}
						hasLetter = true;
						++charCount;
						break;
					} else {
						hasLetter = true;
					}
					++charCount;
				} else {
					throw new AddressStringException(fullAddr.toString(), "ipaddress.host.error.invalid.port.service", i);
				}
			}
		}
		if(isPort) {
			if(!validationOptions.allowPort) {
				throw new AddressStringException(fullAddr.toString(), "ipaddress.host.error.port");
			} else if(digitCount == 0) {
				throw new AddressStringException(fullAddr.toString(), "ipaddress.host.error.invalidPort.no.digits");
			} else if(digitCount > 5) {
				throw new AddressStringException(fullAddr.toString(), "ipaddress.host.error.invalidPort.too.large");
			}
			int result = parse10(fullAddr, index, endIndex);
			if(result > 65535) {
				throw new AddressStringException(fullAddr.toString(), "ipaddress.host.error.invalidPort.too.large");
			}
			return new ParsedHostIdentifierStringQualifier(zone, cachePorts(result));
		} else if(!validationOptions.allowService) {
			throw new AddressStringException(fullAddr.toString(), "ipaddress.host.error.service");
		} else if(charCount == 0) {
			throw new AddressStringException(fullAddr.toString(), "ipaddress.host.error.invalidService.no.chars");
		} else if(charCount > 15) {
			throw new AddressStringException(fullAddr.toString(), "ipaddress.host.error.invalidService.too.long");
		} else if(!hasLetter) {
			throw new AddressStringException(fullAddr.toString(), "ipaddress.host.error.invalidService.no.letter");
		}
		CharSequence service = fullAddr.subSequence(index, endIndex);
		return new ParsedHostIdentifierStringQualifier(zone, service);
	}

	private static ParsedHostIdentifierStringQualifier parseValidatedPrefix(
			int result,
			final CharSequence fullAddr,
			final CharSequence zone,
			final IPAddressStringParameters validationOptions,
			final HostNameParameters hostValidationOptions,
			final int index,
			final int endIndex,
			int digitCount,
			int leadingZeros,
			final IPVersion ipVersion) throws AddressStringException {
		if(digitCount == 0) {
			//we know leadingZeroCount is > 0 since we have checked already if there were no characters at all
			leadingZeros--;
			digitCount++;
		}
		boolean asIPv4 = (ipVersion != null && ipVersion.isIPv4());
		boolean tryCache;
		if(asIPv4) {
			if(leadingZeros > 0 && !validationOptions.getIPv4Parameters().allowPrefixLengthLeadingZeros) {
				throw new AddressStringException(fullAddr.toString(), "ipaddress.error.ipv4.prefix.leading.zeros");
			}
			boolean allowPrefixesBeyondAddressSize = validationOptions.getIPv4Parameters().allowPrefixesBeyondAddressSize;
			if(!allowPrefixesBeyondAddressSize && result > IPv4Address.BIT_COUNT) {
				if(validationOptions.allowSingleSegment) {
					return null; //treat it as a single segment ipv4 mask
				}
				throw new AddressStringException(fullAddr.toString(), "ipaddress.error.prefixSize");
			}
			tryCache = result < PREFIX_CACHE.length;
		} else {
			if(leadingZeros > 0 && !validationOptions.getIPv6Parameters().allowPrefixLengthLeadingZeros) {
				throw new AddressStringException(fullAddr.toString(), "ipaddress.error.ipv6.prefix.leading.zeros");
			}
			boolean allowPrefixesBeyondAddressSize = validationOptions.getIPv6Parameters().allowPrefixesBeyondAddressSize;
			if(!allowPrefixesBeyondAddressSize && result > IPv6Address.BIT_COUNT) {
				throw new AddressStringException(fullAddr.toString(), "ipaddress.error.prefixSize");
			}
			tryCache = zone == null && result < PREFIX_CACHE.length;
		}
		if(tryCache) {
			ParsedHostIdentifierStringQualifier qual = PREFIX_CACHE[result];
			if(qual == null) {
				qual = PREFIX_CACHE[result] = new ParsedHostIdentifierStringQualifier(cacheBits(result), null);
			}
			return qual;
		}
		return new ParsedHostIdentifierStringQualifier(cacheBits(result), zone);
	}
	
	private static Integer cacheBits(int i) {
		return ParsedAddressGrouping.cache(i);
	}
	
	private static Integer cachePorts(int i) {
		return ParsedAddressGrouping.cache(i);
	}

	private static ParsedHostIdentifierStringQualifier validatePrefix(
			final CharSequence fullAddr,
			final CharSequence zone,
			final IPAddressStringParameters validationOptions,
			final HostNameParameters hostValidationOptions,
			final int index,
			final int endIndex,
			final IPVersion ipVersion) throws AddressStringException {
		if(index == fullAddr.length()) {
			return null;
		}
		boolean isPrefix = true;
		int prefixEndIndex = endIndex;
		int digitCount, leadingZeros;
		digitCount = leadingZeros = 0;
		int result = 0;
		int charArray[] = chars;
		ParsedHostIdentifierStringQualifier portQualifier = null;
		for(int i = index; i < endIndex; i++) {
			char c = fullAddr.charAt(i);
			if(c >= '1' && c <= '9') {
				++digitCount;
				result = result * 10 + charArray[c];
			} else if(c == '0') {
				if(digitCount > 0) {
					++digitCount;
					result *= 10;
				} else {
					++leadingZeros;
				}
			} else if(c == HostName.PORT_SEPARATOR && hostValidationOptions != null && 
					(hostValidationOptions.allowPort || hostValidationOptions.allowService) && i > index) {
				//check if we have a port or service.  If not, possibly an IPv6 mask.  
				//Also, parsing for port first (rather than prefix) allows us to call parseValidatedPrefix with the knowledge that whatever is supplied can only be a prefix.
				try {
					portQualifier = parsePortOrService(fullAddr, zone, hostValidationOptions, i + 1, endIndex);
					prefixEndIndex = i;
					break;
				} catch(AddressStringException e) {
					return null;
				}
			} else {
				isPrefix = false;
				break;
			}
		}
		//we treat as a prefix if all the characters were digits, even if there were too many, unless the mask options allow for inet_aton single segment
		if(isPrefix) {
			ParsedHostIdentifierStringQualifier prefixQualifier = parseValidatedPrefix(result, fullAddr, zone, validationOptions, hostValidationOptions, index, prefixEndIndex, digitCount, leadingZeros, ipVersion);
			if(portQualifier != null) {
				portQualifier.mergePrefix(prefixQualifier);
				return portQualifier;
			}
			return prefixQualifier;
		}
		return null;
	}

	private static ParsedHostIdentifierStringQualifier parseAddressQualifier(
			CharSequence fullAddr,
			IPAddressStringParameters validationOptions,
			final HostNameParameters hostValidationOptions,
			IPAddressParseData ipAddressParseData,
			int endIndex) throws AddressStringException {
		int qualifierIndex = ipAddressParseData.getQualifierIndex();
		boolean addressIsEmpty = ipAddressParseData.getAddressParseData().isProvidingEmpty();
		IPVersion ipVersion = ipAddressParseData.getProviderIPVersion();
		if(ipAddressParseData.hasPrefixSeparator()) {
			return parsePrefix(fullAddr, null, validationOptions, hostValidationOptions,
					addressIsEmpty, qualifierIndex, endIndex, ipVersion);
		} else if(ipAddressParseData.isZoned()) {
			if(ipAddressParseData.isBase85Zoned() && !ipAddressParseData.isProvidingBase85IPv6()) {
				throw new AddressStringException(fullAddr, qualifierIndex - 1);
			}
			if(addressIsEmpty) {
				throw new AddressStringException(fullAddr, "ipaddress.error.only.zone");
			}
			return parseZone(fullAddr, validationOptions, addressIsEmpty, qualifierIndex, endIndex, ipVersion);
		} 
		return ParsedHost.NO_QUALIFIER;
	}
	
	private static ParsedHostIdentifierStringQualifier parseHostAddressQualifier(
			CharSequence fullAddr,
			IPAddressStringParameters validationOptions,
			HostNameParameters hostValidationOptions,
			boolean isPrefixed,
			boolean hasPort,
			IPAddressParseData ipAddressParseData,
			int qualifierIndex,
			int endIndex) throws AddressStringException {
		boolean addressIsEmpty = ipAddressParseData.getAddressParseData().isProvidingEmpty();
		IPVersion ipVersion = ipAddressParseData.getProviderIPVersion();
		if(isPrefixed) {
			return parsePrefix(fullAddr, null, validationOptions, hostValidationOptions,
					addressIsEmpty, qualifierIndex, endIndex, ipVersion);
		} else if(ipAddressParseData.isZoned()) {
			if(addressIsEmpty) {
				throw new AddressStringException(fullAddr, "ipaddress.error.only.zone");
			}
			return parseEncodedZone(fullAddr, validationOptions, addressIsEmpty, qualifierIndex, endIndex, ipVersion);
		} else if(hasPort) {//isPort is always false when validating an address
			return parsePortOrService(fullAddr, null, hostValidationOptions, qualifierIndex, endIndex);
		}
		return ParsedHost.NO_QUALIFIER;
	}
	
	private static ParsedHostIdentifierStringQualifier parsePrefix(
			final CharSequence fullAddr,
			final CharSequence zone,
			final IPAddressStringParameters validationOptions,
			final HostNameParameters hostValidationOptions,
			final boolean addressIsEmpty,
			final int index,
			final int endIndex,
			final IPVersion ipVersion) throws AddressStringException {
		if(validationOptions.allowPrefix) {
			ParsedHostIdentifierStringQualifier qualifier = validatePrefix(fullAddr, zone, validationOptions, hostValidationOptions,
					index, endIndex, ipVersion);
			if(qualifier != null) {
				return qualifier;
			}
		}
		if(addressIsEmpty) {
			//PREFIX_ONLY must have a prefix and not a mask - we don't allow /255.255.0.0
			throw new AddressStringException(fullAddr, "ipaddress.error.invalid.mask.address.empty");
		} else if(validationOptions.allowMask) {
			try {
				//check for a mask
				//check if we need a new validation options for the mask
				IPAddressStringParameters maskOptions = toMaskOptions(validationOptions, ipVersion);
				ParsedIPAddress pa = new ParsedIPAddress(null, fullAddr, maskOptions);
				validateIPAddress(maskOptions, fullAddr, index, endIndex, pa, false);
				AddressParseData maskParseData = pa.getAddressParseData();
				if(maskParseData.isProvidingEmpty()) {
					throw new AddressStringException(fullAddr, "ipaddress.error.invalid.mask.empty");
				} else if(maskParseData.isAll()) {
					throw new AddressStringException(fullAddr, "ipaddress.error.invalid.mask.wildcard");
				}
				checkSegments(fullAddr, maskOptions, pa);
				int maskEndIndex = maskParseData.getAddressEndIndex();
				if(maskEndIndex != endIndex) { // 1.2.3.4/ or 1.2.3.4// or 1.2.3.4/%
					throw new AddressStringException(fullAddr, "ipaddress.error.invalid.mask.extra.chars", maskEndIndex + 1);
				}
				IPVersion maskVersion = pa.getProviderIPVersion();
				if(maskVersion.isIPv4() && maskParseData.getSegmentCount() == 1 && !maskParseData.hasWildcard() && !validationOptions.getIPv4Parameters().inet_aton_single_segment_mask) {//1.2.3.4/33 where 33 is an aton_inet single segment address and not a prefix length
					throw new AddressStringException(fullAddr, "ipaddress.error.mask.single.segment");
				} else if(ipVersion != null && (maskVersion.isIPv4() != ipVersion.isIPv4() || maskVersion.isIPv6() != ipVersion.isIPv6())) {
					//note that this also covers the cases of non-standard addresses in the mask, ie mask neither ipv4 or ipv6
					throw new AddressStringException(fullAddr, "ipaddress.error.ipMismatch");
				}
				return new ParsedHostIdentifierStringQualifier(pa, zone);
			} catch(AddressStringException e) {
				throw new AddressStringException(fullAddr, "ipaddress.error.invalidCIDRPrefixOrMask", e);
			}
		}
		throw new AddressStringException(fullAddr, 
				validationOptions.allowPrefix ? "ipaddress.error.invalidCIDRPrefixOrMask" : "ipaddress.error.CIDRNotAllowed");
	}

	private static ParsedHostIdentifierStringQualifier parseHostNameQualifier(
			final CharSequence fullAddr,
			final IPAddressStringParameters validationOptions,
			final HostNameParameters hostValidationOptions,
			final boolean isPrefixed,
			final boolean isPort,//always false for address
			final boolean addressIsEmpty,
			final int index,
			final int endIndex,
			final IPVersion ipVersion) throws AddressStringException {
		if(isPrefixed) {
			return parsePrefix(fullAddr, null, validationOptions, hostValidationOptions,
					addressIsEmpty, index, endIndex, ipVersion);
		} else if(isPort) {//isPort is always false when validating an address
			return parsePortOrService(fullAddr, null, hostValidationOptions, index, endIndex);
		}
		return ParsedHost.NO_QUALIFIER;
	}
	
	
	
	/**
	 * Returns the index of the first invalid character of the zone, or -1 if the zone is valid
	 * 
	 * @param sequence
	 * @return
	 */
	public static int validateZone(CharSequence zone) {
		for(int i = 0; i < zone.length(); i++) {
			char c = zone.charAt(i);
			if (c == IPAddress.PREFIX_LEN_SEPARATOR) {
				return i;
			}
			if (c == IPv6Address.SEGMENT_SEPARATOR) {
				return i;
			}
		}
		return -1;
	}
	
	public static boolean isReserved(char c) {
		boolean isUnreserved = 
				(c >= '0' && c <= '9') ||
				(c >= 'A' && c <= 'Z') ||
				(c >= 'a' && c <= 'z') ||
				c == Address.RANGE_SEPARATOR ||
				c == HostName.LABEL_SEPARATOR ||
				c == '_' ||
				c == '~';
		return !isUnreserved;
	}
	
	private static ParsedHostIdentifierStringQualifier parseZone(
			final CharSequence fullAddr, 
			final IPAddressStringParameters validationOptions,
			final boolean addressIsEmpty,
			final int index,
			final int endIndex,
			final IPVersion ipVersion) throws AddressStringException {
		for(int i = index; i < endIndex; i++) {
			char c = fullAddr.charAt(i);
			if(c == IPAddress.PREFIX_LEN_SEPARATOR) {
				CharSequence zone = fullAddr.subSequence(index, i);
				return parsePrefix(fullAddr, zone, validationOptions, null, addressIsEmpty, i + 1, endIndex, ipVersion);
			} else if(c == IPv6Address.SEGMENT_SEPARATOR) {
				throw new AddressStringException(fullAddr, "ipaddress.error.invalid.zone", i);
			}
		}
		return new ParsedHostIdentifierStringQualifier(fullAddr.subSequence(index, endIndex));
	}
	
	private static ParsedHostIdentifierStringQualifier parseEncodedZone(
			final CharSequence fullAddr, 
			final IPAddressStringParameters validationOptions,
			final boolean addressIsEmpty,
			final int index,
			final int endIndex,
			final IPVersion ipVersion) throws AddressStringException {
		StringBuilder result = null;
		for(int i = index; i < endIndex; i++) {
			char c = fullAddr.charAt(i);
			//we are in here when we have a square bracketed host like [::1]
			//not if we have a HostName with no brackets
			
			//https://tools.ietf.org/html/rfc6874
			//https://tools.ietf.org/html/rfc4007#section-11.7
			if(c == IPv6Address.ZONE_SEPARATOR) {
				if(i + 2 >= endIndex) {
					throw new AddressStringException(fullAddr, "ipaddress.error.invalid.zone.encoding", i);
				}
				//percent encoded
				if(result == null) {
					result = new StringBuilder(endIndex - index);
					result.append(fullAddr, index, i);
				}
				int charArray[] = chars;
				c = (char) (charArray[fullAddr.charAt(++i)] << 4);
				c |= charArray[fullAddr.charAt(++i)];
			} else if(c == IPAddress.PREFIX_LEN_SEPARATOR) {
				CharSequence zone = result != null ? result : fullAddr.subSequence(index, i);
				return parsePrefix(fullAddr, zone, validationOptions, null, addressIsEmpty, i + 1, endIndex, ipVersion);
			} else if(isReserved(c)) {
				throw new AddressStringException(fullAddr, "ipaddress.error.invalid.zone", i);
			}
			if(result != null) {
				result.append(c);
			}
		}
		if(result == null) {
			return new ParsedHostIdentifierStringQualifier(fullAddr.subSequence(index, endIndex));
		}
		return new ParsedHostIdentifierStringQualifier(result);
	}

	/**
	 * Some options are not supported in masks (prefix, wildcards, etc)
	 * So we eliminate those options while preserving the others from the address options.
	 * @param validationOptions
	 * @param ipVersion
	 * @return
	 */
	private static IPAddressStringParameters toMaskOptions(final IPAddressStringParameters validationOptions,
			final IPVersion ipVersion) {
		//We must provide options that do not allow a mask with wildcards or ranges
		IPAddressStringParameters.Builder builder = null;
		if(ipVersion == null || ipVersion.isIPv6()) {
			IPv6AddressStringParameters ipv6Options = validationOptions.getIPv6Parameters();
			if(!ipv6Options.rangeOptions.isNoRange()) {
				builder = validationOptions.toBuilder();
				builder.getIPv6AddressParametersBuilder().setRangeOptions(RangeParameters.NO_RANGE);
			}
			if(ipv6Options.allowMixed && !ipv6Options.getMixedParameters().getIPv4Parameters().rangeOptions.isNoRange()) {
				if(builder == null) {
					builder = validationOptions.toBuilder();
				}
				builder.getIPv6AddressParametersBuilder().setRangeOptions(RangeParameters.NO_RANGE);
			}
		}
		if(ipVersion == null || ipVersion.isIPv4()) {
			IPv4AddressStringParameters ipv4Options = validationOptions.getIPv4Parameters();
			if(!ipv4Options.rangeOptions.isNoRange()) {
				if(builder == null) {
					builder = validationOptions.toBuilder();
				}
				builder.getIPv4AddressParametersBuilder().setRangeOptions(RangeParameters.NO_RANGE);
			}
		}
		if(validationOptions.allowAll) {
			if(builder == null) {
				builder = validationOptions.toBuilder();
			}
			builder.allowAll(false);
		}
		IPAddressStringParameters maskOptions = (builder == null) ? validationOptions : builder.toParams();
		return maskOptions;
	}
	
	private static void assignAttributes(int frontStart, int frontEnd, int start, int end, AddressParseData parseData, int parsedSegIndex, int frontLeadingZeroStartIndex, int leadingZeroStartIndex) {
		parseData.setIndex(parsedSegIndex, 
				AddressParseData.KEY_LOWER_STR_DIGITS_INDEX, frontLeadingZeroStartIndex,
				AddressParseData.KEY_LOWER_STR_START_INDEX, frontStart,
				AddressParseData.KEY_LOWER_STR_END_INDEX, frontEnd,
				AddressParseData.KEY_UPPER_STR_DIGITS_INDEX, leadingZeroStartIndex,
				AddressParseData.KEY_UPPER_STR_START_INDEX, start,
				AddressParseData.KEY_UPPER_STR_END_INDEX, end);
	}
	
	private static void assignAttributes(int frontStart, int frontEnd, int start, int end, AddressParseData parseData, int parsedSegIndex, int frontLeadingZeroStartIndex, int leadingZeroStartIndex, int frontRadix, int radix) {
		parseData.setRadix(parsedSegIndex,
				AddressParseData.KEY_LOWER_RADIX, frontRadix,
				AddressParseData.KEY_UPPER_RADIX, radix);
		assignAttributes(frontStart, frontEnd, start, end, parseData, parsedSegIndex, frontLeadingZeroStartIndex, leadingZeroStartIndex);
	}
	
	private static void assignAttributes(int start, int end, AddressParseData parseData, int parsedSegIndex, int leadingZeroStartIndex) {
		parseData.setIndex(parsedSegIndex, 
				AddressParseData.KEY_UPPER_STR_DIGITS_INDEX, leadingZeroStartIndex,
				AddressParseData.KEY_LOWER_STR_DIGITS_INDEX, leadingZeroStartIndex,
				AddressParseData.KEY_UPPER_STR_START_INDEX, start,
				AddressParseData.KEY_LOWER_STR_START_INDEX, start,
				AddressParseData.KEY_UPPER_STR_END_INDEX, end,
				AddressParseData.KEY_LOWER_STR_END_INDEX, end);
	}
	
	private static void assignAttributes(int start, int end, AddressParseData parseData, int parsedSegIndex, int radix, int leadingZeroStartIndex) {
		parseData.setRadix(parsedSegIndex,
				AddressParseData.KEY_LOWER_RADIX, radix,
				AddressParseData.KEY_UPPER_RADIX, radix);
		assignAttributes(start, end, parseData, parsedSegIndex, leadingZeroStartIndex);
	}
	
	private static void assignSingleWildcardAttributes(CharSequence str, int start, int end, int digitsEnd, int numSingleWildcards, AddressParseData parseData, int parsedSegIndex, int radix, int leadingZeroStartIndex, AddressStringFormatParameters options) throws AddressStringException {
		if(!options.rangeOptions.allowsSingleWildcard()) {
			throw new AddressStringException(str, "ipaddress.error.no.single.wildcard");
		}
		for(int k = digitsEnd; k < end; k++) {
			if(str.charAt(k) != IPAddress.SEGMENT_SQL_SINGLE_WILDCARD) {
				throw new AddressStringException(str, "ipaddress.error.single.wildcard.order");
			}
		}
		parseData.setFlag(parsedSegIndex, AddressParseData.KEY_SINGLE_WILDCARD, true);
		assignAttributes(start, end, parseData, parsedSegIndex, radix, leadingZeroStartIndex);
	}

	private static void switchSingleWildcard10(long currentValueHex, CharSequence s, int start, int end, int numSingleWildcards, AddressParseData parseData, int parsedSegIndex, int leadingZeroStartIndex, AddressStringFormatParameters options) throws AddressStringException {
		int digitsEnd = end - numSingleWildcards;
		assignSingleWildcardAttributes(s, start, end, digitsEnd, numSingleWildcards, parseData, parsedSegIndex, 10, leadingZeroStartIndex, options);
		long lower;
		if(start < digitsEnd) { 
			lower = switchValue10(currentValueHex, digitsEnd - start);
		} else {
			lower = 0;
		}
		long upper;
		switch(numSingleWildcards) {
			case 1:
				lower *= 10;
				upper = lower + 9;
				break;
			case 2:
				lower *= 100;
				upper = lower + 99;
				break;
			case 3:
				lower *= 1000;
				upper = lower + 999;
				break;
			default:
				long power = (long) Math.pow(10, numSingleWildcards);
				lower *= power;
				upper = lower + power - 1;
		}
		parseData.setValue(parsedSegIndex,
				AddressParseData.KEY_LOWER, lower,
				AddressParseData.KEY_UPPER, upper);
	}

	private static void switchSingleWildcard8(long currentValueHex, CharSequence s, int start, int end, int numSingleWildcards, AddressParseData parseData, int parsedSegIndex, int leadingZeroStartIndex, AddressStringFormatParameters options) throws AddressStringException {
		int digitsEnd = end - numSingleWildcards;
		assignSingleWildcardAttributes(s, start, end, digitsEnd, numSingleWildcards, parseData, parsedSegIndex, 8, leadingZeroStartIndex, options);
		long lower, upper;
		if(start < digitsEnd) {
			lower = switchValue8(currentValueHex, digitsEnd - start);
		} else {
			lower = 0;
		}
		
		switch(numSingleWildcards) {
			case 1:
				lower <<= 3;
				upper = lower | 07;
				break;
			case 2:
				lower <<= 6;
				upper = lower | 077;
				break;
			case 3:
				lower <<= 9;
				upper = lower | 0777;
				break;
			default:
				int shift = numSingleWildcards * 3;
				lower <<= shift;
				upper = lower | ~(~0L << shift);
				break;
		}
		parseData.setValue(parsedSegIndex, 
				AddressParseData.KEY_LOWER, lower,
				AddressParseData.KEY_UPPER, upper);
	}
	
	private static void assignSingleWildcard16(long currentValueHex, CharSequence s, int start, int end, int numSingleWildcards, AddressParseData parseData, int parsedSegIndex, int leadingZeroStartIndex, AddressStringFormatParameters options) throws AddressStringException {
		int digitsEnd = end - numSingleWildcards;
		assignSingleWildcardAttributes(s, start, end, digitsEnd, numSingleWildcards, parseData, parsedSegIndex, 16, leadingZeroStartIndex, options);
		int shift = numSingleWildcards << 2;
		currentValueHex <<= shift;
		long upper = currentValueHex | ~(~0L << shift);
		parseData.setValue(parsedSegIndex, 
				AddressParseData.KEY_LOWER, currentValueHex,
				AddressParseData.KEY_UPPER, upper);
	}

	private static void parseSingleSegmentSingleWildcard16(long currentValueHex, CharSequence s, int start, int end, int numSingleWildcards, AddressParseData parseData, int parsedSegIndex, int leadingZeroStartIndex, AddressStringFormatParameters options) throws AddressStringException {
		int digitsEnd = end - numSingleWildcards;
		assignSingleWildcardAttributes(s, start, end, digitsEnd, numSingleWildcards, parseData, parsedSegIndex, 16, leadingZeroStartIndex, options);
		long upper, lower, extendedLower, extendedUpper;
		if(numSingleWildcards < LONG_HEX_DIGITS) {
			int midIndex = end - LONG_HEX_DIGITS;
			lower = parseLong16(s, midIndex, digitsEnd);
			int shift = numSingleWildcards << 2;
			lower <<= shift;
			upper = lower | ~(~0L << shift);
			extendedUpper = extendedLower = parseLong16(s, start, midIndex);
		} else if(numSingleWildcards == LONG_HEX_DIGITS) {
			lower = 0;
			upper = 0xffffffffffffffffL;
			extendedUpper = extendedLower = currentValueHex;
		} else {
			lower = 0;
			upper = 0xffffffffffffffffL;
			extendedLower = currentValueHex;
			int shift = (numSingleWildcards - LONG_HEX_DIGITS) << 2;
			extendedLower <<= shift;
			extendedUpper = extendedLower | ~(~0L << shift);
		}
		parseData.setValue(parsedSegIndex, 
				AddressParseData.KEY_LOWER, lower,
				AddressParseData.KEY_UPPER, upper,
				AddressParseData.KEY_EXTENDED_LOWER, extendedLower,
				AddressParseData.KEY_EXTENDED_UPPER, extendedUpper);
	}
	
	private static final long MAX_VALUES[] = new long[] {0, IPv4Address.MAX_VALUE_PER_SEGMENT, 0xffff, 0xffffff, 0xffffffffL};
	
	private static long getMaxIPv4Value(int segmentCount) {
		return MAX_VALUES[segmentCount];
	}
	
	private static int getStringPrefixCharCount(int radix) {
		if(radix == 10) {
			return 0;
		} else if(radix == 16) {
			return 2;
		}
		return 1;
	}

	private static final int MAX_IPv4_STRING_LEN[][] = new int[][] { //indices are [radix / 2][additionalSegments], and we handle radices 8, 10, 16
		{3, 6, 8, 11}, //no radix supplied we treat as octal, the longest
		{}, {}, {},
		{3, 6, 8, 11},//octal: 0377, 0177777, 077777777, 037777777777
		{IPv4AddressSegment.MAX_CHARS, 5, 8, 10},//decimal: 255, 65535, 16777215, 4294967295
		{}, {},
		{2, 4, 6, 8}//hex: 0xff, 0xffff, 0xffffff, 0xffffffff
	};
	
	private static int getMaxIPv4StringLength(int additionalSegmentsCovered, int radix) {
		try {
			return MAX_IPv4_STRING_LEN[radix >>> 1][additionalSegmentsCovered];
		} catch(ArrayIndexOutOfBoundsException e) {
			return 0;
		}
	}
	
	/**
	 * The digits were stored as a hex value, thix switches them to an octal value.
	 * 
	 * @param currentHexValue
	 * @param digitCount
	 * @return
	 */
	private static long switchValue8(long currentHexValue, int digitCount) {
		long result = 0x7 & currentHexValue;
		int shift = 0;
		while(--digitCount > 0) {
			shift += 3;
			currentHexValue >>>= 4;
			result |= (0x7 & currentHexValue) << shift;
		}
		return result;
	}
	
	private static int parse10(CharSequence s, int start, int end) {
		int charArray[] = chars;
		int result = charArray[s.charAt(start)];
		while (++start < end) {
			result = (result * 10) + charArray[s.charAt(start)];
		}
		return result;
	}
	
	private static long switchValue10(long currentHexValue, int digitCount) {
		long result = 0xf & currentHexValue;
		int factor = 1;
		while(--digitCount > 0) {
			factor *= 10;
			currentHexValue >>>= 4;
			result += (0xf & currentHexValue) * factor;
		}
		return result;
	}
	
	@SuppressWarnings("unused")
	private static long parseLong8(CharSequence s, int start, int end) {
		int charArray[] = chars;
		long result = charArray[s.charAt(start)];
		while (++start < end) {
			result = (result << 3) | charArray[s.charAt(start)];
       }
	   return result;
	}
	
	@SuppressWarnings("unused")
	private static long parseLong10(CharSequence s, int start, int end) {
		int charArray[] = chars;
		long result = charArray[s.charAt(start)];
		while (++start < end) {
			result = (result * 10) + charArray[s.charAt(start)];
		}
		return result;
	}
	
	private static long parseLong16(CharSequence s, int start, int end) {
		int charArray[] = chars;
		long result = charArray[s.charAt(start)];
		while (++start < end) {
			result = (result << 4) | charArray[s.charAt(start)];
		}
		return result;
	}
	
	static {
		BigInteger eightyFive = BigInteger.valueOf(85);
		BASE_85_POWERS[0] = BigInteger.ONE;
		for(int i = 1; i < BASE_85_POWERS.length; i++) {
			BASE_85_POWERS[i] = BASE_85_POWERS[i - 1].multiply(eightyFive);
		}
	}
	
	private static BigInteger parseBig85(CharSequence s, int start, int end) {
		int charArray[] = extendedChars;
		BigInteger result = BigInteger.ZERO;
		boolean last;
		do {
			int partialEnd, power;
			int left = end - start;
			if(last = (left <= 9)) {
				partialEnd = end;
				power = left;
			} else {
				partialEnd = start + 9;
				power = 9;
			}
			long partialResult = charArray[s.charAt(start)];
			while (++start < partialEnd) {
				int next = charArray[s.charAt(start)];
				partialResult = (partialResult * 85) + next;
			}
			result = result.multiply(BASE_85_POWERS[power]).add(BigInteger.valueOf(partialResult));
			start = partialEnd;
		} while(!last);
		return result;
	}
	
	//according to rfc 1035 or 952, a label must start with a letter, must end with a letter or digit, and must have in the middle a letter or digit or -
	//rfc 1123 relaxed that to allow labels to start with a digit, section 2.1 has a discussion on this.  It states that the highest level component name must be alphabetic - referring to .com or .net or whatever.
	//furthermore, the underscore has become generally acceptable, as indicated in rfc 2181
	//there is actually a distinction between host names and domain names.  a host name is a specific type of domain name identifying hosts.
	//hosts are not supposed to have the underscore.  
	
	//en.wikipedia.org/wiki/Domain_Name_System#Domain_name_syntax
	//en.wikipedia.org/wiki/Hostname#Restrictions_on_valid_host_names
	
	//max length is 63, cannot start or end with hyphen
	//strictly speaking, the underscore is not allowed anywhere, but it seems that rule is sometimes broken
	//also, underscores seem to be a part of dns names that are not part of host names, so we allow it here to be safe
	
	//networkadminkb.com/KB/a156/windows-2003-dns-and-the-underscore.aspx
	
	//It's a little confusing.  rfc 2181 https://www.ietf.org/rfc/rfc2181.txt in section 11 on name syntax says that any chars are allowed in dns.
	//However, it also says internet host names might have restrictions of their own, and this was defined in rfc 1035.  
	//rfc 1035 defines the restrictions on internet host names, in section 2.3.1 http://www.ietf.org/rfc/rfc1035.txt
	
	//So we will follow rfc 1035 and in addition allow the underscore.
	
	static ParsedHost validateHostImpl(HostName fromHost) throws HostNameException {
		final String str = fromHost.toString();
		HostNameParameters validationOptions = fromHost.getValidationOptions();
		return validateHost(fromHost, str, validationOptions);
	}
	
	private static ParsedHost validateHost(final HostName fromHost, final String str, HostNameParameters validationOptions) throws HostNameException {
		int addrLen = str.length();
		if(addrLen > MAX_HOST_LENGTH) {
			throw new HostNameException(str, "ipaddress.host.error.invalid.length");
		}
		int index, lastSeparatorIndex, qualifierIndex, isSpecialOnlyIndex;
		boolean segmentUppercase, isNotNormalized, squareBracketed, isAllDigits, isPossiblyIPv6, isPossiblyIPv4, tryIPv6, tryIPv4, isPrefixed, hasPortOrService, addressIsEmpty;
		isSpecialOnlyIndex = qualifierIndex = index = lastSeparatorIndex = -1;
		int labelCount = 0;
		int maxLocalLabels = 6;//should be at least 4 to avoid the array for ipv4 addresses
		int separatorIndices[] = null;
		boolean normalizedFlags[] = null;
		int sep0, sep1, sep2, sep3, sep4, sep5;
		boolean upper0, upper1, upper2, upper3, upper4, upper5;
		
		segmentUppercase = isNotNormalized = squareBracketed = tryIPv6 = tryIPv4 = isPrefixed = hasPortOrService = addressIsEmpty = false;
		isAllDigits = isPossiblyIPv6 = isPossiblyIPv4 = true;
		sep0 = sep1 = sep2 = sep3 = sep4 = sep5 = -1;
		upper0 = upper1 = upper2 = upper3 = upper4 = upper5 = false;
		
		while(++index <= addrLen) {
			char currentChar;
			//grab the character to evaluate
			if(index == addrLen) {
				if(index == 0) {
					addressIsEmpty = true;
					break;
				}
				boolean segmentCountMatchesIPv4 = 
						isPossiblyIPv4 && 
						(labelCount + 1 == IPv4Address.SEGMENT_COUNT) ||
						(labelCount + 1 < IPv4Address.SEGMENT_COUNT && isSpecialOnlyIndex >= 0) ||
						(labelCount + 1 < IPv4Address.SEGMENT_COUNT && validationOptions.addressOptions.getIPv4Parameters().inet_aton_joinedSegments) ||
						labelCount == 0 && validationOptions.addressOptions.allowSingleSegment;
				if(isAllDigits) {
					if(isPossiblyIPv4 && segmentCountMatchesIPv4) {
						tryIPv4 = true;
						break;
					}
					isPossiblyIPv4 = false;
					if(hasPortOrService && isPossiblyIPv6) {//isPossiblyIPv6 is already false if labelCount > 0
						//since it is all digits, it cannot be host, so we set tryIPv6 rather than just isPossiblyIPv6
						tryIPv6 = true;
						break;
					}
					throw new HostNameException(str, "ipaddress.host.error.invalid");
				}
				isPossiblyIPv4 &= segmentCountMatchesIPv4;
				currentChar = HostName.LABEL_SEPARATOR;
			} else {
				currentChar = str.charAt(index);
			}
			
			//check that character
			//we break out of the loop if we hit '[', '*', '%' (as zone or wildcard), or ':' that is not interpreted as port (and this is ipv6)
			//we exit the loop prematurely if we hit '/' or ':' interpreted as port
			if(currentChar >= 'a' && currentChar <= 'z') {
				if(currentChar > 'f') {
					isPossiblyIPv6 = false;
					isPossiblyIPv4 &= (currentChar == 'x' && validationOptions.addressOptions.getIPv4Parameters().inet_aton_hex);
				} else {
					isPossiblyIPv4 = false;
				}
				isAllDigits = false;
			} else if(currentChar >= '0' && currentChar <= '9') {
				//nothing to do
				continue;
			} else if(currentChar >= 'A' && currentChar <= 'Z') {
				if(currentChar > 'F') {
					isPossiblyIPv6 = false;
				}
				segmentUppercase = true;
				isAllDigits = isPossiblyIPv4 = false;
			} else if(currentChar == HostName.LABEL_SEPARATOR) {
				int len = index - lastSeparatorIndex - 1;
				if(len > MAX_LABEL_LENGTH) {
					throw new HostNameException(str, "ipaddress.error.segment.too.long");
				}
				if(len == 0) {
					throw new HostNameException(str, "ipaddress.host.error.segment.too.short");
				}
				if(labelCount < maxLocalLabels) {
					if(labelCount < 3) {
						if(labelCount == 0) {
							sep0 = index;
							upper0 = segmentUppercase;
						} else if(labelCount == 1) {
							sep1 = index;
							upper1 = segmentUppercase;
						} else {
							sep2 = index;
							upper2 = segmentUppercase;
						}
					} else {
						if(labelCount == 3) {
							sep3 = index;
							upper3 = segmentUppercase;
						} else if(labelCount == 4) {
							sep4 = index;
							upper4 = segmentUppercase;
						} else {
							sep5 = index;
							upper5 = segmentUppercase;
						}
					}
					labelCount++;
				} else if(labelCount == maxLocalLabels) {
					separatorIndices = new int[MAX_HOST_SEGMENTS + 1];
					separatorIndices[labelCount] = index;
					if(validationOptions.normalizeToLowercase) {
						normalizedFlags = new boolean[MAX_HOST_SEGMENTS + 1];
						normalizedFlags[labelCount] = !segmentUppercase;
						isNotNormalized |= segmentUppercase;
					}
					labelCount++;	
				} else {
					separatorIndices[labelCount] = index;
					if(normalizedFlags != null) {
						normalizedFlags[labelCount] = !segmentUppercase;
						isNotNormalized |= segmentUppercase;
					}
					if(++labelCount > MAX_HOST_SEGMENTS) {
						throw new HostNameException(str, "ipaddress.host.error.too.many.segments");
					}
				}
				lastSeparatorIndex = index;
				segmentUppercase = false;//this is per segment so reset it
				isPossiblyIPv6 &= (index == addrLen);//A '.' means not ipv6 (if we see ':' we jump out of loop so mixed address not possible), but for single segment we end up here even without a '.' character in the string
			} else if(currentChar == '_') {//this is not supported in host names but is supported in domain names, see discussion in Host class
				isAllDigits = false;
			} else if(currentChar == '-') {
				//host name segments cannot end with '-'
				if(index == lastSeparatorIndex + 1 || index == addrLen - 1 || str.charAt(index + 1) == HostName.LABEL_SEPARATOR) {
					throw new HostNameException(str, index);
				}
				isAllDigits = false;
			} else if(currentChar == HostName.IPV6_START_BRACKET) {
				if(index == 0 && labelCount == 0 && addrLen > 2) {
					squareBracketed = true;
					break;
				}
				throw new HostNameException(str, index);
			} else if(currentChar == IPAddress.PREFIX_LEN_SEPARATOR) {
				isPrefixed = true;
				qualifierIndex = index + 1;
				addrLen = index;
				isNotNormalized = true;
				index--;
			} else {
				boolean b = false;
				if(currentChar == IPAddress.SEGMENT_WILDCARD || (b = (currentChar == IPAddress.SEGMENT_SQL_WILDCARD))) {
					IPAddressStringParameters addressOptions = validationOptions.addressOptions;
					if(b && addressOptions.getIPv6Parameters().allowZone) {//if we allow zones, we treat '%' as a zone and not as a wildcard
						if(isPossiblyIPv6 && labelCount < IPv6Address.SEGMENT_COUNT) {
							tryIPv6 = true;
							isPossiblyIPv4 = false;
							break;
						}
						throw new HostNameException(str, index);
					} else {
						if(isPossiblyIPv4 && addressOptions.getIPv4Parameters().rangeOptions.allowsWildcard()) {
							if(isSpecialOnlyIndex < 0) {
								isSpecialOnlyIndex = index;
							}
						} else {
							isPossiblyIPv4 = false;
						}
						if(isPossiblyIPv6 && addressOptions.getIPv6Parameters().rangeOptions.allowsWildcard()) {
							if(isSpecialOnlyIndex < 0) {
								isSpecialOnlyIndex = index;
							}
						} else {
							if(!isPossiblyIPv4) {
								//needs to be either ipv4 or ipv6
								throw new HostNameException(str, index);
							}
							isPossiblyIPv6 = false;
						}
					}
					isAllDigits = false;
				} else if(currentChar == IPv6Address.SEGMENT_SEPARATOR) {//also might denote a port
					if(validationOptions.allowPort || validationOptions.allowService) {
						hasPortOrService = true;
						qualifierIndex = index + 1;
						addrLen = index;//causes loop to terminate, but only after handling the last segment
						isNotNormalized = true;
						index--;
					} else {
						isPossiblyIPv4 = false;
						if(isPossiblyIPv6) {
							tryIPv6 = true;
							break;
						}
						throw new HostNameException(str, index);
					}
				} else if(currentChar == IPAddress.ALTERNATIVE_RANGE_SEPARATOR) {
					isAllDigits = false;
				} else {
					throw new HostNameException(str, index);
				}
			}
		}
		
		/*
		1. squareBracketed: [ addr ] 
		2. tryIPv4 || tryIPv6: this is a string with characters that invalidate it as a host but it still may in fact be an address
			This includes ipv6 strings, ipv4/ipv6 strings with '*', or all dot/digit strings like 1.2.3.4 that are 4 segments
		3. isPossiblyIPv4: this is a string with digits, - and _ characters and the number of separators matches ipv4.  Such strings can also be valid hosts.  
		  The range options flag (controlling whether we allow '-' or '_' in addresses) for ipv4 can control whether it is treated as host or address.
		  It also includes "" empty addresses.
		  isPossiblyIPv6: something like f:: or f:1, the former IPv6 and the latter a host "f" with port 1.  Such strings can be valid addresses or hosts.
		  If it parses as an address, we do not treat as host.
		*/
		IPAddressStringParameters addressOptions = validationOptions.addressOptions;
		try {
			boolean isIPAddress  = squareBracketed || tryIPv4 || tryIPv6;
			if(!validationOptions.allowIPAddress) {
				if(isIPAddress) {
					throw new HostNameException(str, "ipaddress.host.error.ipaddress");
				}
			} else if(isIPAddress || isPossiblyIPv4 || isPossiblyIPv6) {
				try {
					ParsedIPAddress pa = new ParsedIPAddress(fromHost, str, addressOptions);
					ParsedHostIdentifierStringQualifier addrQualifier = null;
					ParsedHostIdentifierStringQualifier hostQualifier = ParsedHost.NO_QUALIFIER;
					if(squareBracketed) {
						//Note: 
						//Firstly, we need to find the address end which is denoted by the end bracket
						//Secondly, while zones appear inside bracket, prefix or port appears outside, according to rfc 4038
						//So we keep track of the boolean endsWithPrefix to differentiate.
						int endIndex = addrLen - 1;
						boolean endsWithQualifier = (str.charAt(endIndex) != HostName.IPV6_END_BRACKET);
						if(endsWithQualifier) {
							while(str.charAt(--endIndex) != HostName.IPV6_END_BRACKET) {
								if(endIndex == 1) {
									throw new HostNameException(str, "ipaddress.host.error.bracketed.missing.end");
								}
							}
						}
						int startIndex = 1;
						if(str.startsWith(HostIdentifierStringValidator.SMTP_IPV6_IDENTIFIER, 1)) {
							//SMTP rfc 2821 allows [IPv6:ipv6address]
							startIndex = 6;
						} else {
							/* RFC 3986 section 3.2.2
							  	host = IP-literal / IPv4address / reg-name
	      						IP-literal = "[" ( IPv6address / IPvFuture  ) "]"
	      						IPvFuture  = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
	      					If a URI containing an IP-literal that starts with "v" (case-insensitive),
	   						indicating that the version flag is present, is dereferenced by an application that does not know the meaning of that version flag,
	   						then the application should return an appropriate error for "address mechanism not supported".
							 */
							char firstChar = str.charAt(1);
							if(firstChar == IPvFUTURE || firstChar == IPvFUTURE_UPPERCASE) {
								throw new HostNameException(str, "ipaddress.host.error.invalid.mechanism");
							}
						}
						validateIPAddress(addressOptions, str, startIndex, endIndex, pa, false);
						if(endsWithQualifier) {
							//here we check what is in the qualifier that follows the bracket: prefix/mask or port?
							//if prefix/mask, we supply the qualifier to the address, otherwise we supply it to the host
							int prefixIndex = endIndex + 1;
							char prefixChar = str.charAt(prefixIndex);
							if(prefixChar == IPAddress.PREFIX_LEN_SEPARATOR) {
								isPrefixed = true;
							} else if(prefixChar == HostName.PORT_SEPARATOR) {
								hasPortOrService = true;
							} else {
								throw new HostNameException(str, prefixIndex);
							}
							qualifierIndex = prefixIndex + 1;//skip the ']/'
							endIndex = str.length();
							AddressParseData addressParseData = pa.getAddressParseData();
							ParsedHostIdentifierStringQualifier parsedHostQualifier = 
									parseHostNameQualifier(
											str,
											addressOptions,
											validationOptions,
											isPrefixed,
											hasPortOrService,
											addressParseData.isProvidingEmpty(),
											qualifierIndex,
											endIndex,
											pa.getProviderIPVersion());
							int insideBracketsQualifierIndex = pa.getQualifierIndex();
							if(pa.isZoned() && str.charAt(insideBracketsQualifierIndex) == '2' && 
									str.charAt(insideBracketsQualifierIndex + 1) == '5') {
								//handle %25 from rfc 6874
								insideBracketsQualifierIndex += 2;
							}
							addrQualifier = parseHostAddressQualifier(str, addressOptions, null, pa.hasPrefixSeparator(), false, pa, insideBracketsQualifierIndex, prefixIndex - 1);
							if(isPrefixed) {
								//since we have an address, we apply the prefix to the address rather than to the host
								//rather than use the prefix as a host qualifier, we treat it as an address qualifier and leave the host qualifier as NO_QUALIFIER
								//also, keep in mind you can combine prefix with zone like fe80::%2/64, see https://tools.ietf.org/html/rfc4007#section-11.7 
								if(addrQualifier == ParsedHost.NO_QUALIFIER) {
									addrQualifier = parsedHostQualifier;
								} else {
									Integer addPrefLength = addrQualifier.getEquivalentPrefixLength();
									if(addPrefLength != null) {
										Integer hostPrefLength = parsedHostQualifier.getEquivalentPrefixLength();
										if(hostPrefLength != null && addPrefLength.intValue() != hostPrefLength.intValue()) {
											throw new HostNameException(str, "ipaddress.host.error.bracketed.conflicting.prefix.length");
										}
									}
									IPAddress one = addrQualifier.getMask();
									if(one != null) {
										IPAddress two = parsedHostQualifier.getMask();
										if(two != null && !one.equals(two)) {
											throw new HostNameException(str, "ipaddress.host.error.bracketed.conflicting.mask");
										}
									}
									addrQualifier.mergePrefix(parsedHostQualifier);
								}
							} else {
								hostQualifier = parsedHostQualifier;
							}
						} else {
							qualifierIndex = pa.getQualifierIndex();
							isPrefixed = pa.hasPrefixSeparator();
							hasPortOrService = false;
							if(pa.isZoned() && str.charAt(qualifierIndex) == '2' && 
									str.charAt(qualifierIndex + 1) == '5') {
								//handle %25 from rfc 6874
								qualifierIndex += 2;
							}
							addrQualifier = parseHostAddressQualifier(str, addressOptions, validationOptions, isPrefixed, hasPortOrService, pa, qualifierIndex, endIndex);
						}
						//SMTP rfc 2821 allows [ipv4address]
						IPVersion version = pa.getProviderIPVersion();
						if(version != IPVersion.IPV6 && !validationOptions.allowBracketedIPv4) {
							throw new HostNameException(str, "ipaddress.host.error.bracketed.not.ipv6");
						}
					} else { //not square-bracketed
						/*
						there are cases where it can be ipv4 or ipv6, but not many
						any address with a '.' in it cannot be ipv6 at this point (if we hit a ':' first we would have jumped out of the loop)
						any address with a ':' has gone through tests to see if up until that point it could match an ipv4 address or an ipv6 address
						it can only be ipv4 if it has right number of segments, and only decimal digits.
						it can only be ipv6 if it has only hex digits.
						so when can it be both?  if it looks like *: at the start, so that it has the right number of segments for ipv4 but does not have a '.' invalidating ipv6
						so in that case we might have either something like *:1 for it to be ipv4 (ambiguous is treated as ipv4) or *:f:: to be ipv6
						So we validate the potential port (or ipv6 segment) to determine which one and then go from there
						Also, if it is single segment address that is all decimal digits.
						 */
								
						//We start by checking if there is potentially a port or service
						//if IPv6, we may need to try a :x as a port or service and as a trailing segment
						boolean firstTrySucceeded = false;
						boolean hasAddressPortOrService = false;
						int addressQualifierIndex = -1;
						boolean isPotentiallyIPv6 = isPossiblyIPv6 || tryIPv6;
						if(isPotentiallyIPv6) {
							//find the last port separator, currently we point to the first one with qualifierIndex
							//note that the service we find here could be the ipv4 part of either an ipv6 address or ipv6 mask like this 1:2:3:4:5:6:1.2.3.4 or 1:2:3:4:5:6:1.2.3.4/1:2:3:4:5:6:1.2.3.4
							if(!isPrefixed && (validationOptions.allowPort || validationOptions.allowService)) {
								for(int j = str.length() - 1; j >= 0; j--) {
									char c = str.charAt(j);
									if(c == IPv6Address.SEGMENT_SEPARATOR) {
										hasAddressPortOrService = true;
										addressQualifierIndex = j + 1;
									} else if((c >= '0' && c <= '9') ||
											(c >= 'A' && c <= 'Z') ||
											(c >= 'a' && c <= 'z') ||
											(c == '-') ||
											(c == Address.SEGMENT_WILDCARD)) {
										//see validateHostNamePort for more details on valid ports and service names
										continue;
									}
									break;
								}
							}
						} else {
							hasAddressPortOrService = hasPortOrService;
							addressQualifierIndex = qualifierIndex;
						}
						int endIndex;
						if(hasAddressPortOrService) {
							try {
								//validate the port
								ParsedHostIdentifierStringQualifier hostPortQualifier = hostQualifier = parsePortOrService(str, null, validationOptions, addressQualifierIndex, str.length());
								if(isPotentiallyIPv6) {
									//here it can be either a port or part of an IPv6 address, like this: fe80::6a05:caff:fe3:123
									boolean expectPort = validationOptions.expectPort;
									try {
										if(expectPort) {
											//try with port first, then try as IPv6 no port
											endIndex = addressQualifierIndex - 1;
										} else {
											//try as IPv6 with no port first, try with port second
											endIndex = str.length();
											hostQualifier = ParsedHost.NO_QUALIFIER;
										}
										//first try
										validateIPAddress(addressOptions, str, 0, endIndex, pa, false);
										//since no square brackets, we parse as an address (this can affect how zones are parsed).
										//Also, an address cannot end with a single ':' like a port, so we cannot take a shortcut here and parse for port, we must strip it off first (hence no host parameters passed)
										addrQualifier = parseAddressQualifier(str, addressOptions, null, pa, endIndex);
										firstTrySucceeded = true;
									} catch(AddressStringException e) {
										//whatever we tried first has failed, try the second option below
										pa = new ParsedIPAddress(fromHost, str, addressOptions);
										if(expectPort) {
											hostQualifier = ParsedHost.NO_QUALIFIER;
											endIndex = str.length();
										} else {
											hostQualifier = hostPortQualifier;
											endIndex = addressQualifierIndex - 1;
										}
									}
								} else {
									endIndex = addressQualifierIndex - 1;
								}
							} catch(AddressStringException e) {
								//certainly not IPv4 since it doesn't qualify as port
								if(!isPotentiallyIPv6) {
									//not IPv6 either, so throw (caught below)
									throw e;
								}
								hostQualifier = ParsedHost.NO_QUALIFIER;
								endIndex = str.length();
							}
						} else {
							endIndex = str.length();
						}
						if(!firstTrySucceeded) {
							validateIPAddress(addressOptions, str, 0, endIndex, pa, false);
							//since no square brackets, we parse as an address (this can affect how zones are parsed)
							//Also, an address cannot end with a single ':' like a port, so we cannot take a shortcut here and parse for port, we must strip it off first (hence no host parameters passed)
							addrQualifier = parseAddressQualifier(str, addressOptions, null, pa, endIndex);
						}
					}
					IPAddressProvider provider = chooseProvider(fromHost, str, addressOptions, pa, addrQualifier);
					return new ParsedHost(str, provider, hostQualifier);
				} catch(AddressStringException e) {
					if(isIPAddress) {
						throw e;
					} //else fall though and evaluate as a host
				}
			}
			ParsedHostIdentifierStringQualifier qualifier = 
					parseHostNameQualifier(
							str,
							addressOptions,
							validationOptions,
							isPrefixed,
							hasPortOrService,
							addressIsEmpty,
							qualifierIndex,
							str.length(),
							null);
			ParsedHost parsedHost;
			if(addressIsEmpty) {
				if(!validationOptions.allowEmpty) {
					throw new HostNameException(str, "ipaddress.host.error.empty");
				}
				if(qualifier == ParsedHost.NO_QUALIFIER) {
					parsedHost = DEFAULT_EMPTY_HOST;
				} else {
					parsedHost = new ParsedHost(str, EMPTY_INDICES, null, qualifier);
				}
			} else {
				if(labelCount <= maxLocalLabels) {
					separatorIndices = new int[maxLocalLabels = labelCount];
					if(validationOptions.normalizeToLowercase) {
						normalizedFlags = new boolean[labelCount];
					}
				} else if(labelCount != separatorIndices.length) {
					int trimmedSeparatorIndices[] = new int[labelCount];
					System.arraycopy(separatorIndices, maxLocalLabels, trimmedSeparatorIndices, maxLocalLabels, labelCount - maxLocalLabels);
					separatorIndices = trimmedSeparatorIndices;
					if(normalizedFlags != null) {
						boolean trimmedNormalizedFlags[] = new boolean[labelCount];
						System.arraycopy(normalizedFlags, maxLocalLabels, trimmedNormalizedFlags, maxLocalLabels, labelCount - maxLocalLabels);
						normalizedFlags = trimmedNormalizedFlags;
					}
				}
				for(int i = 0; i < maxLocalLabels; i++) {
					int nextSep;
					boolean isUpper;
					if(i < 2) {
						if(i == 0) {
							nextSep = sep0;
							isUpper = upper0;
						} else {
							nextSep = sep1;
							isUpper = upper1;
						}
					} else if(i < 4) {
						if(i == 2) {
							nextSep = sep2;
							isUpper = upper2;
						} else {
							nextSep = sep3;
							isUpper = upper3;
						}
					} else if (i == 4) {
						nextSep = sep4;
						isUpper = upper4;
					} else {
						nextSep = sep5;
						isUpper = upper5;
					}
					separatorIndices[i] = nextSep;
					if(normalizedFlags != null) {
						normalizedFlags[i] = !isUpper;
						isNotNormalized |= isUpper;
					}
				}
				//We support a.b.com/24:80 (prefix and port combo)
				//or just port, or a service where-ever a port can appear
				//A prefix with port can mean a subnet of addresses using the same port everywhere (the subnet being the prefix block of the resolved address), 
				//or just denote the prefix length of the resolved address along with a port
				
				//here we check what is in the qualifier that follows the bracket: prefix/mask or port?
				//if prefix/mask, we supply the qualifier to the address, otherwise we supply it to the host
				//also, it is possible the address has a zone
				ParsedHostIdentifierStringQualifier addrQualifier, hostQualifier;
				if(isPrefixed) {
					addrQualifier = qualifier;
					hostQualifier = ParsedHost.NO_QUALIFIER;
				} else {
					hostQualifier = qualifier;
					addrQualifier = ParsedHost.NO_QUALIFIER;
				}
				EmbeddedAddress addr = checkSpecialHosts(str, addrLen, addrQualifier);
				AddressStringException embeddedException = null;
				if(isSpecialOnlyIndex >= 0 && (addr == null || (embeddedException = addr.addressStringException) != null)) {
					if(embeddedException != null) {
						throw new HostNameException(str, isSpecialOnlyIndex, embeddedException);
					}
					throw new HostNameException(str, isSpecialOnlyIndex);
				}
				parsedHost = new ParsedHost(str, separatorIndices, normalizedFlags, addr == null ? qualifier : hostQualifier, addr);
				if(!isNotNormalized && addr == null) {
					parsedHost.host = str;
				}
			}
			return parsedHost;
		} catch(AddressStringException e) {
			throw new HostNameException(str, e, "ipaddress.host.error.invalid");
		}
	}
	
	private static EmbeddedAddress checkSpecialHosts(String str, int addrLen, ParsedHostIdentifierStringQualifier hostQualifier) {
		EmbeddedAddress emb = null;
		try {
			String suffix = IPv6Address.UNC_SUFFIX;
			//note that by using addrLen we are omitting any terminating prefix
			int suffixStartIndex;
			if(addrLen > suffix.length() && //get the address for the UNC IPv6 host
					str.regionMatches(true, suffixStartIndex = addrLen - suffix.length(), suffix, 0, suffix.length())) {
				StringBuilder builder = new StringBuilder(str.substring(0, suffixStartIndex));
				for(int i = 0; i < builder.length(); i++) {
					char c = builder.charAt(i);
					if(c == IPv6Address.UNC_SEGMENT_SEPARATOR) {
						builder.setCharAt(i, IPv6Address.SEGMENT_SEPARATOR);
					} else if(c == IPv6Address.UNC_RANGE_SEPARATOR) {
						builder.setCharAt(i, IPv6Address.RANGE_SEPARATOR);
					}  else if(c == IPv6Address.UNC_ZONE_SEPARATOR) {
						builder.setCharAt(i, IPv6Address.ZONE_SEPARATOR);
					}
				}
				emb = new EmbeddedAddress();
				emb.isUNCIPv6Literal = true;
				IPAddressStringParameters params = DEFAULT_UNC_OPTS;
				ParsedIPAddress pa = new ParsedIPAddress(null, str, params);
				validateIPAddress(params, builder, 0, builder.length(), pa, false);
				ParsedHostIdentifierStringQualifier qual;
				ParsedHostIdentifierStringQualifier addrQualifier = parseAddressQualifier(builder, DEFAULT_UNC_OPTS, null, pa, builder.length());
				if(addrQualifier == ParsedHost.NO_QUALIFIER) {
					qual = hostQualifier;
				} else if(hostQualifier == ParsedHost.NO_QUALIFIER) {
					qual = addrQualifier;
				} else {
					//only prefix qualifiers and the NO_QUALIFIER are cached, so merging is OK
					//in the case we can have only a zone qualifier
					addrQualifier.mergePrefix(hostQualifier);
					qual = addrQualifier;
				}
				IPAddressProvider provider = chooseProvider(null, builder, params, pa, qual);
				emb.addressProvider = provider;
			}
			//Note: could support bitstring labels and support subnets in them, however they appear to be generally unused in the real world
			//rfc 2673
			//arpa: https://www.ibm.com/support/knowledgecenter/SSLTBW_1.13.0/com.ibm.zos.r13.halz002/f1a1b3b1220.htm
			//Also, support partial dns lookups and map then to the associated subnet with prefix length, which I think we may 
			//already do for ipv4 but not for ipv6, ipv4 uses the prefix notation d.c.b.a/x but ipv6 uses fewer nibbles
			//on the ipv6 side, would just need to add the proper number of zeros and the prefix length
			String suffix3 = IPv6Address.REVERSE_DNS_SUFFIX_DEPRECATED;
			if(addrLen > suffix3.length()) {
				suffix = IPv4Address.REVERSE_DNS_SUFFIX;
				String suffix2 = IPv6Address.REVERSE_DNS_SUFFIX;
				boolean isIPv4;
				if(	(isIPv4 = str.regionMatches(true, suffixStartIndex = addrLen - suffix.length(), suffix, 0, suffix.length())) ||
					(	(addrLen > suffix2.length() && str.regionMatches(true, suffixStartIndex = addrLen - suffix2.length(), suffix2, 0, suffix2.length())) ||
						(addrLen > suffix3.length() && str.regionMatches(true, suffixStartIndex = addrLen - suffix3.length(), suffix3, 0, suffix3.length()))
					)) {
					emb = new EmbeddedAddress();
					emb.isReverseDNS = true;
					CharSequence sequence;
					IPAddressStringParameters params;
					if(isIPv4) {
						sequence = convertReverseDNSIPv4(str, suffixStartIndex);
						params = REVERSE_DNS_IPV4_OPTS;
					} else {
						sequence = convertReverseDNSIPv6(str, suffixStartIndex);
						params = REVERSE_DNS_IPV6_OPTS;
					}
					ParsedIPAddress pa = new ParsedIPAddress(null, sequence, params);
					validateIPAddress(params, sequence, 0, sequence.length(), pa, false);
					IPAddressProvider provider = chooseProvider(null, sequence, params, pa, hostQualifier != null ? hostQualifier : ParsedHost.NO_QUALIFIER);
					emb.addressProvider = provider;
				}
			}
//			//handle TLD host https://tools.ietf.org/html/draft-osamu-v6ops-ipv4-literal-in-url-02
//			//https://www.ietf.org/proceedings/87/slides/slides-87-v6ops-6.pdf
//			suffix = ".v4";
//			if(addrLen > suffix.length() && 
//					str.regionMatches(true, suffixStartIndex = addrLen - suffix.length(), suffix, 0, suffix.length())) {
//				//not an rfc, so let's leave it
//			}
		} catch (AddressStringException e) {
			emb.addressStringException = e;
		}
		return emb;
	}

	//123.2.3.4 is 4.3.2.123.in-addr.arpa.
	
	private static CharSequence convertReverseDNSIPv4(String str, int suffixStartIndex) throws AddressStringException {
		StringBuilder builder = new StringBuilder(suffixStartIndex);
		int segCount = 0;
		int j = suffixStartIndex;
		for(int i = suffixStartIndex - 1; i > 0; i--) {
			char c1 = str.charAt(i);
			if(c1 == IPv4Address.SEGMENT_SEPARATOR) {
				if(j - i <= 1) {
					throw new AddressStringException(str, i);
				}
				for(int k = i + 1; k < j; k++) {
					builder.append(str.charAt(k));
				}
				builder.append(c1);
				j = i;
				segCount++;
			}
		}
		for(int k = 0; k < j; k++) {
			builder.append(str.charAt(k));
		}
		if(segCount + 1 != IPv4Address.SEGMENT_COUNT) {
			throw new AddressStringException(str, 0);
		}
		return builder;
	}
	
	//4321:0:1:2:3:4:567:89ab would be b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.IP6.ARPA
	
	private static CharSequence convertReverseDNSIPv6(String str, int suffixStartIndex) throws AddressStringException {
		StringBuilder builder = new StringBuilder(suffixStartIndex);
		StringBuilder low = new StringBuilder();
		StringBuilder high = new StringBuilder();
		int segCount = 0;
		for(int i = suffixStartIndex - 1; i >= 0; ) {
			boolean isRange = false;
			for(int j = 0; j < 4; j++) {
				char c1 = str.charAt(i--);
				if(i >= 0) {
					char c2 = str.charAt(i--);
					if(c2 == IPv4Address.SEGMENT_SEPARATOR) {
						if(c1 == IPAddress.SEGMENT_WILDCARD) {
							isRange = true;
							low.append('0');
							high.append('f');
						} else {
							if(isRange) {
								throw new AddressStringException(str, i + 1);
							}
							low.append(c1);
							high.append(c1);
						}
					} else if(c2 == IPAddress.RANGE_SEPARATOR) {
						high.append(c1);
						if(i >= 1) {
							c2 = str.charAt(i--);
							low.append(c2);
							boolean isFullRange = (c2 == '0' && c1 == 'f');
							if(isRange && !isFullRange) {
								throw new AddressStringException(str, i + 1);
							}
							c2 = str.charAt(i--);
							if(c2 != IPv4Address.SEGMENT_SEPARATOR) {
								throw new AddressStringException(str, i + 1);
							}
						} else {
							throw new AddressStringException(str, i);
						}
						isRange = true;
					} else {
						throw new AddressStringException(str, i + 1);
					}
				} else if(j < 3) {
					throw new AddressStringException(str, i + 1);
				} else {
					if(c1 == IPAddress.SEGMENT_WILDCARD) {
						isRange = true;
						low.append('0');
						high.append('f');
					} else {
						if(isRange) {
							throw new AddressStringException(str, 0);
						}
						low.append(c1);
						high.append(c1);
					}
				}
			}
			segCount++;
			if(builder.length() > 0) {
				builder.append(IPv6Address.SEGMENT_SEPARATOR);
			}
			builder.append(low);
			if(isRange) {
				builder.append(IPAddress.RANGE_SEPARATOR).append(high);
			}
			low.setLength(0);
			high.setLength(0);
		}
		if(segCount != IPv6Address.SEGMENT_COUNT) {
			throw new AddressStringException(str, 0);
		}
		return builder;
	}
}
