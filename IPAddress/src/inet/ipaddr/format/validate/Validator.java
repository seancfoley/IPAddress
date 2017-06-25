/*
 * Copyright 2017 Sean C Foley
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
import inet.ipaddr.format.AddressLargeDivision;
import inet.ipaddr.format.validate.IPAddressProvider.AllCreator;
import inet.ipaddr.format.validate.IPAddressProvider.MaskCreator;
import inet.ipaddr.format.validate.IPAddressProvider.ParsedAddressProvider;
import inet.ipaddr.format.validate.ParsedHost.EmbeddedAddress;
import inet.ipaddr.format.validate.ParsedIPAddress.IPAddressParseData;
import inet.ipaddr.format.validate.ParsedMACAddress.MACAddressParseData;
import inet.ipaddr.format.validate.ParsedMACAddress.MACAddressParseData.MACFormat;
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
		char[] extendedDigits = AddressLargeDivision.EXTENDED_DIGITS;
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
		return validateAddressImpl(fromString);
	}

	@Override
	public MACAddressProvider validateAddress(MACAddressString fromString) throws AddressStringException {
		String str = fromString.toString();
		MACAddressStringParameters validationOptions = fromString.getValidationOptions();
		MACAddressParseData macAddressParseData = new MACAddressParseData();
		validateMACAddress(validationOptions, str, 0, str.length(), macAddressParseData);
		AddressParseData addressParseData = macAddressParseData.addressParseData;
		if(addressParseData.isEmpty) {
			return MACAddressProvider.EMPTY_PROVIDER;
		} else if(addressParseData.isAll) {
			AddressSize allAddresses = validationOptions.addressSize;
			return (allAddresses == AddressSize.EUI64) ? MACAddressProvider.ALL_EUI_64 : MACAddressProvider.ALL_MAC;
		} else {
			ParsedMACAddress parsedAddress = createParsedMACAddress(
					fromString,
					fromString.toString(),
					fromString.getValidationOptions(),
					macAddressParseData);
			return new MACAddressProvider(parsedAddress);
		}
	}
	
	static IPAddressProvider validateAddressImpl(IPAddressString fromString) throws AddressStringException {
		String str = fromString.toString();
		IPAddressStringParameters validationOptions = fromString.getValidationOptions();
		IPAddressParseData ipAddressParseData = new IPAddressParseData();
		validateIPAddress(validationOptions, str, 0, str.length(), ipAddressParseData);
		return createProvider(fromString, str, validationOptions, ipAddressParseData,
			parseQualifier(str, validationOptions, null, ipAddressParseData, str.length()));
	}
	
	private static void validateIPAddress(
			final IPAddressStringParameters validationOptions,
			final CharSequence str,
			final int strStartIndex,
			int strEndIndex,
			IPAddressParseData parseData) throws AddressStringException {
		validateIPAddress(validationOptions, str, strStartIndex, strEndIndex, parseData, false);
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
	
	private static ParsedMACAddress createParsedMACAddress(
			final MACAddressString originator,
			final String fullAddr,
			final MACAddressStringParameters validationOptions,
			final MACAddressParseData parseData) throws AddressStringException {
		if(parseData.format != null) {
			//note that too many segments is checked inside the general parsing method
			int segCount = parseData.addressParseData.segmentCount;
			if(parseData.format == MACFormat.DOTTED) {
				if(segCount <= MACAddress.MEDIA_ACCESS_CONTROL_DOTTED_SEGMENT_COUNT && validationOptions.addressSize != AddressSize.EUI64) {
					if(segCount != MACAddress.MEDIA_ACCESS_CONTROL_DOTTED_SEGMENT_COUNT && !parseData.addressParseData.anyWildcard) {
						throw new AddressStringException(fullAddr, "ipaddress.error.too.few.segments");
					}
				} else if(segCount < MACAddress.MEDIA_ACCESS_CONTROL_DOTTED_64_SEGMENT_COUNT && !parseData.addressParseData.anyWildcard) {
					throw new AddressStringException(fullAddr, "ipaddress.error.too.few.segments");
				} else {
					parseData.isExtended = true;
				}
			} else {
				if(segCount > 2) {
					if(segCount <= MACAddress.MEDIA_ACCESS_CONTROL_SEGMENT_COUNT && validationOptions.addressSize != AddressSize.EUI64) {
						if(segCount != MACAddress.MEDIA_ACCESS_CONTROL_SEGMENT_COUNT && !parseData.addressParseData.anyWildcard) {
							throw new AddressStringException(fullAddr, "ipaddress.error.too.few.segments");
						}
					} else if(segCount < MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT && !parseData.addressParseData.anyWildcard) {
						throw new AddressStringException(fullAddr, "ipaddress.error.too.few.segments");
					} else {
						parseData.isExtended = true;
					}
					if(parseData.format == MACFormat.DASHED) {
						int max = MACAddress.MAX_VALUE_PER_SEGMENT;
						int maxChars = MACAddressSegment.MAX_CHARS;
						for(int i = 0; i < segCount; i++) {
							checkMaxValues(
									fullAddr,
									parseData.addressParseData,
									i,
									validationOptions.getFormatParameters(),
									max,
									maxChars,
									maxChars);
						}
					}
				} else {
					if(parseData.format == MACFormat.DASHED) {
						//for single segment, we have already counted the exact number of hex digits
						//for double segment, we have already counted the exact number of hex digits in some cases and not others.
						//Basically, for address like a-b we have already counted the exact number of hex digits,
						//for addresses starting with a|b- or a-b| we have not,
						//but rather than figure out which are checked out which not it's just as quick to check them all here
						if(parseData.isDoubleSegment) {
							MACAddressStringFormatParameters params = validationOptions.getFormatParameters();
							AddressParseData data = parseData.addressParseData;
							checkMaxValues(fullAddr, data, 0, params, MAC_MAX_TRIPLE, MAC_DOUBLE_SEGMENT_DIGIT_COUNT, MAC_DOUBLE_SEGMENT_DIGIT_COUNT);
							if(parseData.isExtended) {
								checkMaxValues(fullAddr, data, 1, params, MAC_MAX_QUINTUPLE, MAC_EXTENDED_DOUBLE_SEGMENT_DIGIT_COUNT, MAC_EXTENDED_DOUBLE_SEGMENT_DIGIT_COUNT);
							} else {
								checkMaxValues(fullAddr, data, 1, params, MAC_MAX_TRIPLE, MAC_DOUBLE_SEGMENT_DIGIT_COUNT, MAC_DOUBLE_SEGMENT_DIGIT_COUNT);
							}
						}
					} else if(!parseData.addressParseData.anyWildcard) {
						throw new AddressStringException(fullAddr, "ipaddress.error.too.few.segments");
					}
					
					
					if(validationOptions.addressSize == AddressSize.EUI64) {
						parseData.isExtended = true;
					}
				}
			}
		} //else single segment
		ParsedMACAddress parsedAddress = new ParsedMACAddress(originator, fullAddr, parseData);
		return parsedAddress;
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
			parseData = macAddressParseData.addressParseData;
			isBase85 = false;
		} else {
			baseOptions = validationOptions;
			//later we set stringFormatParams when we know what ip version we have
			stringFormatParams = null;
			parseData = ipAddressParseData.addressParseData;
			ipv6SpecificOptions = validationOptions.getIPv6Parameters();
			isBase85 = ipv6SpecificOptions.allowBase85;
			ipv4SpecificOptions = validationOptions.getIPv4Parameters();
		}
		
		int index = strStartIndex;
		
		//per segment variables
		int lastSeparatorIndex, digitCount, leadingZeroCount, rangeWildcardIndex, hexDelimiterIndex, singleWildcardCount, wildcardCount;
		int frontDigitCount, frontLeadingZeroCount, frontWildcardCount, frontSingleWildcardCount, frontHexDelimiterIndex;
		boolean notOctal, notDecimal, uppercase, isSingleIPv6Hex, isSingleSegment, isDoubleSegment;
		boolean frontNotOctal, frontNotDecimal, frontUppercase, frontIsStandardRange;
		boolean firstSegmentDashedRange, countedCharacters, countingCharsLater;
		int extendedCharacterIndex, extendedRangeWildcardIndex;
		boolean atEnd;
		
		frontDigitCount = frontLeadingZeroCount = frontSingleWildcardCount = digitCount = leadingZeroCount = singleWildcardCount = wildcardCount = frontWildcardCount = 0;
		extendedCharacterIndex = extendedRangeWildcardIndex = lastSeparatorIndex = rangeWildcardIndex = hexDelimiterIndex = frontHexDelimiterIndex = -1;
		frontIsStandardRange = countingCharsLater = countedCharacters = atEnd = firstSegmentDashedRange = frontNotOctal = frontNotDecimal = frontUppercase = notOctal = notDecimal = uppercase = isSingleIPv6Hex = isSingleSegment = isDoubleSegment = false;

		while(index < strEndIndex || (atEnd = (index == strEndIndex))) {
			char currentChar;
			if(atEnd) {
				parseData.addressEndIndex = index;
				int totalDigits = leadingZeroCount + digitCount;
				boolean isSegmented = isMac ? macFormat != null : ipAddressParseData.ipVersion != null;
				if(isSegmented) {
					if(isMac) {
						currentChar = macFormat.getSeparator();
						isDoubleSegment = macAddressParseData.isDoubleSegment = (parseData.segmentCount == 1 && currentChar == Address.RANGE_SEPARATOR);
						if(isDoubleSegment) {
							macAddressParseData.isExtended = (totalDigits == MAC_EXTENDED_DOUBLE_SEGMENT_DIGIT_COUNT);
						}
					} else {
						//current char is either . or : to handle last segment, unless we have double :: in which case we already handled last segment
						IPVersion version = ipAddressParseData.ipVersion;
						if(version.isIPv4()) {
							currentChar = IPv4Address.SEGMENT_SEPARATOR;
						} else { //ipv6
							if(index == lastSeparatorIndex + 1) {
								if(index == parseData.consecutiveSepIndex + 2) {
									//ends with ::, we've already parsed the last segment
									break;
								}
								throw new AddressStringException(str, "ipaddress.error.cannot.end.with.single.separator");
							} else if(ipAddressParseData.mixedParsedAddress != null) {
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
						if(!isMac && ipAddressParseData.isPrefixed) {
							if(!validationOptions.allowPrefixOnly) {
								throw new AddressStringException(str, "ipaddress.error.prefix.only");
							}
						} else if(!baseOptions.allowEmpty) {
							throw new AddressStringException(str, "ipaddress.error.empty");
						}
						parseData.isEmpty = true;
						break;
					} else if(wildcardCount == totalCharacterCount) {// "*"
						if(singleWildcardCount > 0 || rangeWildcardIndex >= 0 || leadingZeroCount > 0 || digitCount > 0 || hexDelimiterIndex >= 0) {//wildcards must appear alone
							throw new AddressStringException(str, index, true);
						}
						if(!baseOptions.allowAll) {
							throw new AddressStringException(str, "ipaddress.error.all");
						}
						parseData.anyWildcard = true;
						parseData.isAll = true;
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
							isDoubleSegment = macAddressParseData.isDoubleSegment = true;
							macAddressParseData.isExtended = (totalDigits == MAC_EXTENDED_DOUBLE_SEGMENT_DIGIT_COUNT);
							currentChar = MACAddress.DASH_SEGMENT_SEPARATOR;
							countedCharacters = true;
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
								parseData.isSingleSegment = isSingleSegment = true;
								macAddressParseData.isExtended = !is12Digits;
								currentChar = MACAddress.COLON_SEGMENT_SEPARATOR;
								countedCharacters = true;
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
							parseData.isSingleSegment = isSingleSegment = isSingleIPv6Hex = true;
							currentChar = IPv6Address.SEGMENT_SEPARATOR;
							countedCharacters = true;
						} else {
							if(isBase85) {
								if(extendedRangeWildcardIndex < 0) {
									if(totalCharacterCount == IPV6_BASE85_SINGLE_SEGMENT_DIGIT_COUNT) {
										if(!validationOptions.allowIPv6) {
											throw new AddressStringException(str, "ipaddress.error.ipv6");
										}
										ipAddressParseData.ipVersion = IPVersion.IPV6;
										BigInteger val = parseBig85(str, strStartIndex, strEndIndex);
										long value = val.and(LOW_BITS_MASK).longValue();
										BigInteger shift64 = val.shiftRight(Long.SIZE);
										long extendedValue = shift64.longValue();
										//note that even with the correct number of digits, we can have a value too large
										BigInteger shiftMore = shift64.shiftRight(Long.SIZE);
										if(!shiftMore.equals(BigInteger.ZERO)) {
											throw new AddressStringException(str, "ipaddress.error.address.too.large");
										}
										parseData.initSegmentData(1);
										parseData.segmentCount = 1;
										long vals[] = parseData.values[0];
										int indices[] = parseData.indices[0];
										assignAttributes(strStartIndex, strEndIndex, indices, IPv6Address.DEFAULT_TEXTUAL_RADIX, strStartIndex);
										vals[AddressParseData.LOWER_INDEX] = vals[AddressParseData.UPPER_INDEX] = value;
										vals[AddressParseData.EXTENDED_LOWER_INDEX] = vals[AddressParseData.EXTENDED_UPPER_INDEX] = extendedValue;
										ipAddressParseData.isBase85 = true;
										break;
									}
								} else {
									if(totalCharacterCount == (IPV6_BASE85_SINGLE_SEGMENT_DIGIT_COUNT << 1) + 1) {/* note that we already check that extendedRangeWildcardIndex is at index 20 */
										if(!validationOptions.allowIPv6) {
											throw new AddressStringException(str, "ipaddress.error.ipv6");
										}
										ipAddressParseData.ipVersion = IPVersion.IPV6;
										int frontEndIndex = strStartIndex + IPV6_BASE85_SINGLE_SEGMENT_DIGIT_COUNT;
										BigInteger val = parseBig85(str, strStartIndex, frontEndIndex);
										BigInteger val2 = parseBig85(str, frontEndIndex + 1, strEndIndex);
										long value = val.and(LOW_BITS_MASK).longValue();
										BigInteger shift64 = val.shiftRight(Long.SIZE);
										long extendedValue = shift64.longValue();
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
										parseData.initSegmentData(parseData.segmentCount = 1);
										long vals[] = parseData.values[0];
										int indices[] = parseData.indices[0];
										assignAttributes(strStartIndex, frontEndIndex, frontEndIndex + 1, strEndIndex, indices, strStartIndex, frontEndIndex + 1, IPv6Address.DEFAULT_TEXTUAL_RADIX, IPv6Address.DEFAULT_TEXTUAL_RADIX);
										vals[AddressParseData.LOWER_INDEX] = value;
										vals[AddressParseData.UPPER_INDEX] = value2;
										vals[AddressParseData.EXTENDED_LOWER_INDEX] = extendedValue;
										vals[AddressParseData.EXTENDED_UPPER_INDEX] = extendedValue2;
										ipAddressParseData.isBase85 = true;
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
			
			//evaluate the character
			if(currentChar >= '1' && currentChar <= '7') {
				++digitCount;
				++index;
			} else if(currentChar == '0') {
				if(digitCount > 0) {
					++digitCount;
				} else {
					++leadingZeroCount;
				}
				++index;
			} else if(currentChar == '8' || currentChar == '9') {
				++digitCount;
				++index;
				notOctal = true;
			} else if(currentChar >= 'a' && currentChar <= 'f') {
				++digitCount;
				++index;
				notOctal = notDecimal = true;
			} else if(currentChar >= 'A' && currentChar <= 'F') {
				++digitCount;
				++index;
				notOctal = notDecimal = uppercase = true;
			} else if(currentChar == IPv4Address.SEGMENT_SEPARATOR) {
				int segCount = parseData.segmentCount;
				if(!isMac && ipAddressParseData.ipVersion != null && ipAddressParseData.ipVersion.isIPv6()) {
					//we are not base 85, so throw if necessary
					if(extendedCharacterIndex >= 0) {
						throw new AddressStringException(str, extendedCharacterIndex);
					}
					isBase85 = false;
					//mixed IPv6 address like 1:2:3:4:5:6:1.2.3.4
					if(!ipv6SpecificOptions.allowMixed) {
						throw new AddressStringException(str, "ipaddress.error.no.mixed");
					}
					int totalSegmentCount = parseData.segmentCount + IPv6Address.MIXED_REPLACED_SEGMENT_COUNT;
					if(totalSegmentCount > IPv6Address.SEGMENT_COUNT) {
						throw new AddressStringException(str, "ipaddress.error.too.many.segments");
					}
					if(wildcardCount > 0) {
						parseData.anyWildcard = true;
					}
					boolean isNotExpandable = wildcardCount > 0 && parseData.consecutiveSepIndex < 0;
					if(isNotExpandable && 
							totalSegmentCount < IPv6Address.SEGMENT_COUNT && 
							ipv6SpecificOptions.allowWildcardedSeparator) {
						//the '*' is covering an additional ipv6 segment (eg 1:2:3:4:5:*.2.3.4, the * covers both an ipv4 and ipv6 segment)
						parseData.values[segCount][AddressParseData.UPPER_INDEX] = IPv6Address.MAX_VALUE_PER_SEGMENT;
						parseData.flags[segCount][AddressParseData.WILDCARD_INDEX] = true;
						parseData.segmentCount++;
					}
					IPAddressStringParameters mixedOptions = ipv6SpecificOptions.getMixedParameters();
					IPAddressParseData mixedAddressParseData = new IPAddressParseData();
					validateIPAddress(mixedOptions, str, lastSeparatorIndex + 1, strEndIndex, mixedAddressParseData, true);
					ipAddressParseData.mixedParsedAddress = createIPAddressProvider(null, str, mixedOptions, mixedAddressParseData, ParsedHost.NO_QUALIFIER);
					index = mixedAddressParseData.addressParseData.addressEndIndex;
				} else {
					//could be mac or ipv4, we handle either one
					int maxChars;
					if(isMac) {
						if(segCount == 0) {
							if(!macOptions.allowDotted) {
								throw new AddressStringException(str, "ipaddress.mac.error.format");
							}
							macAddressParseData.format = macFormat = MACFormat.DOTTED;
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
						ipAddressParseData.ipVersion = IPVersion.IPV4;
						stringFormatParams = ipv4SpecificOptions;
						if(segCount == 0) {
							parseData.initSegmentData(IPv4Address.SEGMENT_COUNT);
						} else if(segCount >= IPv4Address.SEGMENT_COUNT) {
							throw new AddressStringException(str, "ipaddress.error.ipv4.too.many.segments");
						}
						maxChars = getMaxIPv4StringLength(3, 8);
					}
					long vals[] = parseData.values[segCount];
					int indices[] = parseData.indices[segCount];
					boolean flags[] = parseData.flags[segCount];
					if(wildcardCount > 0) {
						if(!stringFormatParams.rangeOptions.allowsWildcard()) {
							throw new AddressStringException(str, "ipaddress.error.no.wildcard");
						}
						//wildcards must appear alone
						if(singleWildcardCount > 0 || rangeWildcardIndex >= 0 || leadingZeroCount > 0 || digitCount > 0 || hexDelimiterIndex >= 0) {
							throw new AddressStringException(str, index, true);
						}
						parseData.anyWildcard = true;
						flags[AddressParseData.WILDCARD_INDEX] = true;
						vals[AddressParseData.UPPER_INDEX] = isMac ? MACAddress.MAX_VALUE_PER_DOTTED_SEGMENT : IPv4Address.MAX_VALUE_PER_SEGMENT;
						int startIndex = index - wildcardCount;
						assignAttributes(startIndex, index, indices, startIndex);
					} else {
						long value = 0;
						boolean isStandard = false;
						int radix;
						int startIndex = index - digitCount;
						int leadingZeroStartIndex = startIndex - leadingZeroCount;
						int totalDigits = digitCount + leadingZeroCount;
						int endIndex = index;
						boolean isSingleWildcard;
						boolean isJustZero;
						if(digitCount == 0) {
							boolean noLeadingZeros = leadingZeroCount == 0;
							if(noLeadingZeros && rangeWildcardIndex >= 0 && hexDelimiterIndex < 0) {//we allow an empty range boundary to denote the max value
								if(isMac) {
									value = MACAddress.MAX_VALUE_PER_DOTTED_SEGMENT;
									radix = 16;
								} else {
									value = IPv4Address.MAX_VALUE_PER_SEGMENT;
									radix = 10;
								}
								isJustZero = false;
								isSingleWildcard = false;
							} else if(noLeadingZeros) {
								//starts with '.' or two consecutive '.'
								throw new AddressStringException(str, "ipaddress.error.empty.segment.at.index", index);
							} else {
								isSingleWildcard = false;
								isJustZero = true;
								startIndex--;
								digitCount++;
								leadingZeroCount--;
								boolean illegalLeadingZeros = leadingZeroCount > 0 && !stringFormatParams.allowLeadingZeros;
								if(hexDelimiterIndex >= 0) {
									if(isMac) {
										throw new AddressStringException(str, hexDelimiterIndex);
									}
									if(!ipv4SpecificOptions.inet_aton_hex) {
										throw new AddressStringException(str, "ipaddress.error.ipv4.segment.hex");
									}
									radix = 16;
								} else if(isMac) {
									if(illegalLeadingZeros) {
										throw new AddressStringException(str, "ipaddress.error.segment.leading.zeros");
									} else if(!stringFormatParams.allowUnlimitedLeadingZeros && totalDigits > maxChars) {
										throw new AddressStringException(str, "ipaddress.error.segment.too.long.at.index", leadingZeroStartIndex);
									} else if(!macSpecificOptions.allowShortSegments && totalDigits < 2) {
										throw new AddressStringException(str, "ipaddress.error.segment.too.short.at.index", leadingZeroStartIndex);
									}
									radix = 16;
								} else if(leadingZeroCount > 0 && ipv4SpecificOptions.inet_aton_octal) {
									radix = 8;
								} else {
									if(illegalLeadingZeros) {
										throw new AddressStringException(str, "ipaddress.error.segment.leading.zeros");
									}
									radix = 10;
								}
								flags[AddressParseData.STANDARD_STR_INDEX] = true;
								assignAttributes(startIndex, endIndex, indices, radix, leadingZeroStartIndex);
							}
						} else {
							//Note: we cannot do max value check on ipv4 until after all segments have been read due to inet_aton joined segments, 
							//although we can do a preliminary check here that is in fact needed to prevent overflow when calculating values later
							if(digitCount > maxChars) {
								throw new AddressStringException(str, "ipaddress.error.segment.too.long.at.index", leadingZeroStartIndex);
							}
							isJustZero = false;
							isSingleWildcard = singleWildcardCount > 0;
							if(isMac || hexDelimiterIndex >= 0) {
								if(isMac) {
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
								}
								radix = 16;
								if(isSingleWildcard) {
									if(rangeWildcardIndex >= 0) {
										throw new AddressStringException(str, index, true);
									}
									parseSingleWildcard16(str, startIndex, endIndex, singleWildcardCount, indices, vals, flags, leadingZeroStartIndex, stringFormatParams);
								} else {
									value = parseLong16(str, startIndex, endIndex);
								}
							} else {
								boolean isOctal = leadingZeroCount > 0 && ipv4SpecificOptions.inet_aton_octal;
								if(isOctal) {
									if(notOctal) {
										throw new AddressStringException(str, "ipaddress.error.ipv4.invalid.octal.digit");
									}
									radix = 8;
									if(isSingleWildcard) {
										if(rangeWildcardIndex >= 0) {
											throw new AddressStringException(str, index, true);
										}
										parseSingleWildcard8(str, startIndex, endIndex, singleWildcardCount, indices, vals, flags, leadingZeroStartIndex, stringFormatParams);
									} else {
										value = parseLong8(str, startIndex, endIndex);
									}
								} else {
									if(notDecimal) {
										throw new AddressStringException(str, "ipaddress.error.ipv4.invalid.decimal.digit");
									}
									if(leadingZeroCount > 0 && !stringFormatParams.allowLeadingZeros) {
										throw new AddressStringException(str, "ipaddress.error.segment.leading.zeros");
									}
									radix = 10;
									if(isSingleWildcard) {
										if(rangeWildcardIndex >= 0) {
											throw new AddressStringException(str, index, true);
										}
										parseSingleWildcard10(str, startIndex, endIndex, singleWildcardCount, indices, vals, flags, leadingZeroStartIndex, ipv4SpecificOptions);
									} else {
										value = parseLong10(str, startIndex, endIndex);
										isStandard = true;
									}
								}
							}
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
									} else if(!macSpecificOptions.allowShortSegments && totalDigits < 2) {
										throw new AddressStringException(str, "ipaddress.error.segment.too.short.at.index", frontLeadingZeroStartIndex);
									}
									if(!frontEmpty) {//we allow the front of a range to be empty in which case it is 0
										front = parseLong16(str, frontStartIndex, frontEndIndex);
									} else {
										front = 0;
									}
								} else if(!ipv4SpecificOptions.inet_aton_hex) {
									throw new AddressStringException(str, "ipaddress.error.ipv4.segment.hex");
								} else {
									if(!frontEmpty) {//we allow the front of a range to be empty in which case it is 0
										front = parseLong16(str, frontStartIndex, frontEndIndex);
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
									front = parseLong8(str, frontStartIndex, frontEndIndex);
									frontRadix = 8;
								} else {
									if(frontNotDecimal) {
										throw new AddressStringException(str, "ipaddress.error.ipv4.invalid.decimal.digit");
									}
									if(frontLeadingZeroCount == 0 && !frontEmpty) {
										flags[AddressParseData.STANDARD_STR_INDEX] = true; 
										if(isStandard && leadingZeroCount == 0) {
											flags[AddressParseData.STANDARD_RANGE_STR_INDEX] = true;
										}
									}
									if(!frontEmpty) {//we allow the front of a range to be empty in which case it is 0
										front = parseLong10(str, frontStartIndex, frontEndIndex);
									} else {
										front = 0;
									}
									frontRadix = 10;
								}
							}
							if(front > value) {
								throw new AddressStringException(str, "ipaddress.error.invalidRange");
							} //else we would have to flip the values and the indices and we would not set or flags[ParseData.STANDARD_RANGE_STR_INDEX]
							if(!isJustZero) {
								assignAttributes(frontStartIndex, frontEndIndex, startIndex, endIndex, indices, frontLeadingZeroStartIndex, leadingZeroStartIndex, frontRadix, radix);
								vals[AddressParseData.LOWER_INDEX] = front;
								vals[AddressParseData.UPPER_INDEX] = value;
							}
							frontDigitCount = frontLeadingZeroCount = frontWildcardCount = frontSingleWildcardCount = 0;
							frontNotOctal = frontNotDecimal = frontUppercase = false;
							frontHexDelimiterIndex = -1;
						} else if(!isSingleWildcard && !isJustZero) {
							if(isStandard) {
								flags[AddressParseData.STANDARD_STR_INDEX] = true; 
							}
							assignAttributes(startIndex, endIndex, indices, radix, leadingZeroStartIndex);
							vals[AddressParseData.LOWER_INDEX] = vals[AddressParseData.UPPER_INDEX] = value;
						}	
					}
					parseData.segmentCount++;
					lastSeparatorIndex = index;
					digitCount = singleWildcardCount = wildcardCount = leadingZeroCount = 0;
					hexDelimiterIndex = rangeWildcardIndex = -1;
					notOctal = notDecimal = uppercase = false;
					++index;
				}
			} else {
				boolean isRangeChar, isDashedRangeChar, endOfSegment, isSpace, isZoneChar;
				isSpace = isRangeChar = isDashedRangeChar = isZoneChar = false;
				
				//this is the case for all IPv6 and MAC segments, as well as the front range of all segments IPv4, IPv6, and MAC
				//they are in the same case because the range character - is the same as one of the separators - for MAC, 
				//so further work is required to distinguish between the front of IPv6/IPv4/MAC range and MAC segment
				//we also handle IPv6 segment and MAC segment in the same place to avoid code duplication
				if((endOfSegment = (currentChar == IPv6Address.SEGMENT_SEPARATOR)) || 
						(isRangeChar = (currentChar == Address.RANGE_SEPARATOR)) ||
						(isMac &&
								(isDashedRangeChar = (currentChar == MACAddress.DASHED_SEGMENT_RANGE_SEPARATOR)) ||
								(endOfSegment = isSpace = (currentChar == MACAddress.SPACE_SEGMENT_SEPARATOR)))) {
					/*
					 There are 3 cases here, A, B and C.
					 A - we have two MAC segments a-b- 
					 B - we have the front of a range segment, either a-b which is MAC or IPV6,  or a|b or a<space>b which is MAC
					 C - we have a single segment, either a MAC segment a- or an IPv6 or MAC segment a:
					 */
					if(!endOfSegment) {
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
						if(isRangeChar || isDashedRangeChar) {
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
										macAddressParseData.format = macFormat = MACFormat.DASHED;
										countingCharsLater = true;
										parseData.initSegmentData(MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT);
										long vals[] = parseData.values[0];
										boolean flags[] = parseData.flags[0];
										int indices[] = parseData.indices[0];
										if(frontWildcardCount > 0) {
											if(!stringFormatParams.rangeOptions.allowsWildcard()) {
												throw new AddressStringException(str, "ipaddress.error.no.wildcard");
											}
											if(frontSingleWildcardCount > 0 || frontLeadingZeroCount > 0 || frontDigitCount > 0 || frontHexDelimiterIndex >= 0) {//wildcards must appear alone
												throw new AddressStringException(str, rangeWildcardIndex, true);
											}
											parseData.anyWildcard = true;
											flags[AddressParseData.WILDCARD_INDEX] = true;
											if(isDoubleSegment || digitCount + leadingZeroCount == MAC_DOUBLE_SEGMENT_DIGIT_COUNT) {
												//even when not already identified as a double segment address, which is something we can see
												//only when we reach the end of the address, we may have a-b| where a is * and b is a 6 digit value.
												//Here we are considering the max value of a.
												//If b is 6 digits, we need to consider the max value of * as if we know already it will be double segment.
												//We can do this because the max values will be checked after the address has been parsed,
												//so even if a-b| ends up being a full address a-b|c-d-e-f-a and not a-b|c,
												//the fact that we have 6 digits here will invalidate the first address,
												//so we can safely assume that this address must be a double segment a-b|c even before we have seen that.
												vals[AddressParseData.UPPER_INDEX] = MAC_MAX_TRIPLE;
											} else {
												vals[AddressParseData.UPPER_INDEX] = MACAddress.MAX_VALUE_PER_SEGMENT;	
											}
											int startIndex = rangeWildcardIndex - frontWildcardCount;
											assignAttributes(startIndex, rangeWildcardIndex, indices, startIndex);
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
												parseSingleWildcard16(str, startIndex, endIndex, singleWildcardCount, indices, vals, flags, leadingZeroStartIndex, stringFormatParams);
											} else {
												value = parseLong16(str, startIndex, endIndex);
												if(!uppercase) {
													flags[AddressParseData.STANDARD_STR_INDEX] = true;
												}
												assignAttributes(startIndex, endIndex, indices, MACAddress.DEFAULT_TEXTUAL_RADIX, leadingZeroStartIndex);
												vals[AddressParseData.LOWER_INDEX] = vals[AddressParseData.UPPER_INDEX] = value;
											}
											frontDigitCount = frontLeadingZeroCount = frontWildcardCount = frontSingleWildcardCount = 0;
											frontNotOctal = frontNotDecimal = frontUppercase = false;
											frontHexDelimiterIndex = rangeWildcardIndex = -1;
										}
										parseData.segmentCount++;
										//end of handling the first segment a- in a-b-
										//below we handle b- by setting endOfSegment here
										endOfSegment = isRangeChar;
									} else {//we will treat this as the front of a range
										if(isDashedRangeChar) {
											firstSegmentDashedRange = true;
										} else {
											endOfSegment = firstSegmentDashedRange;
										}
									}
								} else {
									if(macFormat == MACFormat.DASHED) {
										endOfSegment = isRangeChar;
									} else {
										if(isDashedRangeChar) {
											throw new AddressStringException(str, index);
										}
									}
								}
							} 
						} 
						if(!endOfSegment) {
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
									leadingZeroCount = digitCount = 0;
									notOctal = notDecimal = uppercase = false;
									hexDelimiterIndex = -1;
									wildcardCount = singleWildcardCount = 0;
								}
							}
							++index;
						}
					}
					//now we know if we are looking at the end of a segment, so we handle that now
					if(endOfSegment) { //either MAC segment a- or a: or 'a ', or IPv6 a:
						//case C, an ipv6 or mac segment
						if(hexDelimiterIndex >= 0 && !isSingleSegment) {
							throw new AddressStringException(str, hexDelimiterIndex);
						}
						int segCount = parseData.segmentCount;
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
										macAddressParseData.format = macFormat = MACFormat.DASHED;
										countingCharsLater = true;
									} else {
										macAddressParseData.format = macFormat = (isSpace ? MACFormat.SPACE_DELIMITED : MACFormat.COLON_DELIMITED);						
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
								if(ipAddressParseData.ipVersion == null || ipAddressParseData.ipVersion.isIPv4()) {
									throw new AddressStringException(str, "ipaddress.error.ipv6.separator");
								}
							}
							if(!validationOptions.allowIPv6) {
								throw new AddressStringException(str, "ipaddress.error.ipv6");
							}
							ipAddressParseData.ipVersion = IPVersion.IPV6;
							stringFormatParams = ipv6SpecificOptions;
							maxChars = IPv6AddressSegment.MAX_CHARS;//will be ignored for single segment due to countedCharacters and countingCharsLater boolean
						}
						long vals[] = parseData.values[segCount];
						boolean flags[] = parseData.flags[segCount];
						int indices[] = parseData.indices[segCount];
						if(wildcardCount > 0) {
							if(!stringFormatParams.rangeOptions.allowsWildcard()) {
								throw new AddressStringException(str, "ipaddress.error.no.wildcard");
							}
							if(singleWildcardCount > 0 || rangeWildcardIndex >= 0 || leadingZeroCount > 0 || digitCount > 0) {//wildcards must appear alone
								throw new AddressStringException(str, index, true);
							}
							parseData.anyWildcard = true;
							flags[AddressParseData.WILDCARD_INDEX] = true;
							vals[AddressParseData.UPPER_INDEX] = isMac ? (isDoubleSegment ? MAC_MAX_TRIPLE : MACAddress.MAX_VALUE_PER_SEGMENT) : IPv6Address.MAX_VALUE_PER_SEGMENT;
							int startIndex = index - wildcardCount;
							assignAttributes(startIndex, index, indices, startIndex);
							parseData.segmentCount++;
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
								if(parseData.consecutiveSepIndex >= 0) {
									throw new AddressStringException(str, "ipaddress.error.ipv6.ambiguous");
								}
								parseData.consecutiveSepIndex = index - 1;
								assignAttributes(index, index, indices, index);
								parseData.segmentCount++;
							} else {
								if(!stringFormatParams.allowLeadingZeros && leadingZeroCount > 0) {
									throw new AddressStringException(str, "ipaddress.error.segment.leading.zeros");
								}
								long value, extendedValue;
								value = extendedValue = 0;
								boolean isStandard = false;
								int startIndex = index - digitCount;
								int totalDigits = digitCount + leadingZeroCount;
								int leadingZeroStartIndex = startIndex - leadingZeroCount;
								int endIndex = index;
								boolean checkCharCounts = !(countedCharacters || countingCharsLater);
								if(checkCharCounts && !stringFormatParams.allowUnlimitedLeadingZeros && totalDigits > maxChars) {
									throw new AddressStringException(str, "ipaddress.error.segment.too.long.at.index", leadingZeroStartIndex);
								} else if(isMac && !macSpecificOptions.allowShortSegments && totalDigits < 2) {
									throw new AddressStringException(str, "ipaddress.error.segment.too.short.at.index", leadingZeroStartIndex);
								}
								boolean isJustZero;
								if(digitCount == 0) {
									if(rangeWildcardIndex >= 0 && leadingZeroCount == 0) {//we allow an empty range boundary to denote the max value
										value = isMac ? MACAddress.MAX_VALUE_PER_SEGMENT : IPv6Address.MAX_VALUE_PER_SEGMENT;
										isJustZero = false;
									} else {
										//note we know there is a zero as we have already checked for empty segments so here we know leadingZeroCount is non-zero
										startIndex--;
										digitCount++;
										leadingZeroCount--;
										isJustZero = true;
										flags[AddressParseData.STANDARD_STR_INDEX] = true; 
										assignAttributes(startIndex, endIndex, indices, leadingZeroStartIndex);
									}
								} else if(checkCharCounts && digitCount > maxChars) {
									throw new AddressStringException(str, "ipaddress.error.segment.too.long.at.index", leadingZeroStartIndex);
								} else if(singleWildcardCount > 0) {
									if(rangeWildcardIndex >= 0) {
										throw new AddressStringException(str, index, true);
									}
									isJustZero = false;
									if(isSingleIPv6Hex) {//We need this special call here because single ipv6 hex is 128 bits and cannot fit into a long
										parseSingleSegmentSingleWildcard16(str, startIndex, endIndex, singleWildcardCount, indices, vals, flags, leadingZeroStartIndex, stringFormatParams);
									} else {
										parseSingleWildcard16(str, startIndex, endIndex, singleWildcardCount, indices, vals, flags, leadingZeroStartIndex, stringFormatParams);
									}
								} else {
									isJustZero = false;
									if(isSingleIPv6Hex) { //We need this special call here because single ipv6 hex is 128 bits and cannot fit into a long
										int midIndex = endIndex - 16;
										if(startIndex < midIndex) {
											extendedValue = parseLong16(str, startIndex, midIndex);
											value = parseLong16(str, midIndex, endIndex);
										} else {
											value = parseLong16(str, startIndex, endIndex);
										}
									} else {
										value = parseLong16(str, startIndex, endIndex);
									}
									isStandard = !uppercase;
								} //else we need do nothing as we know digitCount == 0 means we have only 0 characters
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
									if(isSingleIPv6Hex) {//We need this special call here because single ipv6 hex is 128 bits and cannot fit into a long
										frontEmpty = false;
										int frontMidIndex = frontEndIndex - 16;
										extendedFront = parseLong16(str, frontStartIndex, frontMidIndex);
										front = parseLong16(str, frontMidIndex, frontEndIndex);
									} else {
										frontEmpty = frontStartIndex == frontEndIndex;
										if(!frontEmpty) {
											front = parseLong16(str, frontStartIndex, frontEndIndex);
										} else {
											front = 0;
										}
										extendedFront = 0;
										if(front > value) {
											throw new AddressStringException(str, "ipaddress.error.invalidRange");
										} //else we would have to flip the values and the indices and we would not set or flags[ParseData.STANDARD_RANGE_STR_INDEX]
									}
									if(!isJustZero) {
										if(!frontUppercase && frontLeadingZeroCount == 0 && !frontEmpty) {
											flags[AddressParseData.STANDARD_STR_INDEX] = true;
											if(isStandard && leadingZeroCount == 0 && frontIsStandardRange) {
												flags[AddressParseData.STANDARD_RANGE_STR_INDEX] = true;
											}
										}
										assignAttributes(frontStartIndex, frontEndIndex, startIndex, endIndex, indices, frontLeadingZeroStartIndex, leadingZeroStartIndex, IPv6Address.DEFAULT_TEXTUAL_RADIX, IPv6Address.DEFAULT_TEXTUAL_RADIX);
										vals[AddressParseData.LOWER_INDEX] = front;
										vals[AddressParseData.UPPER_INDEX] = value;
										if(isSingleIPv6Hex) {//We need this special call here because single ipv6 hex is 128 bits and cannot fit into a long
											vals[AddressParseData.EXTENDED_LOWER_INDEX] = extendedFront;
											vals[AddressParseData.EXTENDED_UPPER_INDEX] = extendedValue;
										}
									}
									frontDigitCount = frontLeadingZeroCount = frontWildcardCount = frontSingleWildcardCount = 0;
									frontNotOctal = frontNotDecimal = frontUppercase = false;
									frontHexDelimiterIndex = -1;
								} else if(singleWildcardCount == 0 && !isJustZero) {
									if(isStandard) {
										flags[AddressParseData.STANDARD_STR_INDEX] = true;
									}
									assignAttributes(startIndex, endIndex, indices, IPv6Address.DEFAULT_TEXTUAL_RADIX /* same as MAC, so no problem */, leadingZeroStartIndex);
									vals[AddressParseData.LOWER_INDEX] = vals[AddressParseData.UPPER_INDEX] = value;
									if(isSingleIPv6Hex) {//We need this special call here because single ipv6 hex is 128 bits and cannot fit into a long
										vals[AddressParseData.EXTENDED_LOWER_INDEX] = vals[AddressParseData.EXTENDED_UPPER_INDEX] = extendedValue;
									}
									
								}
								parseData.segmentCount++;
							}
						}
						lastSeparatorIndex = index;
						hexDelimiterIndex = rangeWildcardIndex = -1;
						digitCount = singleWildcardCount = wildcardCount = leadingZeroCount = 0;
						notOctal = notDecimal = uppercase = false;
						++index;
					}
				} else if(currentChar == IPAddress.PREFIX_LEN_SEPARATOR) {
					//we are not base 85, so throw if necessary
					if(isMac) {
						throw new AddressStringException(str, index);
					}
					ipAddressParseData.isPrefixed = true;
					strEndIndex = index;
					ipAddressParseData.qualifierIndex = index + 1;
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
							((parseData.segmentCount > 0 && (isEmbeddedIPv4 || ipAddressParseData.ipVersion == IPVersion.IPV6) /* at end of IPv6 regular or mixed */) || 
									(leadingZeroCount + digitCount == 32 && (rangeWildcardIndex < 0 || frontLeadingZeroCount + frontDigitCount == 32) /* at end of ipv6 single segment */) || 
									wildcardCount == index /* all wildcards so far */)
							) {
						//we are not base 85, so throw if necessary
						if(extendedCharacterIndex >= 0) {
							throw new AddressStringException(str, extendedCharacterIndex);
						}
						isBase85 = false;
						ipAddressParseData.isZoned = true;
						strEndIndex = index;
						ipAddressParseData.qualifierIndex = index + 1;
					} else {
						++wildcardCount;
						++index;
					}
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
							//++digitCount;
						} else {
							throw new AddressStringException(str, index, true);
						}
					} else {
						hexDelimiterIndex = index;
						leadingZeroCount = 0;
					}
					++index;
				} else if(currentChar == AddressLargeDivision.EXTENDED_DIGITS_RANGE_SEPARATOR) {
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
						ipAddressParseData.isZoned = ipAddressParseData.isBase85Zoned = true;
						strEndIndex = index;
						ipAddressParseData.qualifierIndex = index + 1;
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
		//return parseData;
	}
	
	private static IPAddressProvider createProvider(
			final HostIdentifierString originator,
			//final HostName fromHost,
			//final IPAddressString fromString,
			final CharSequence fullAddr,
			final IPAddressStringParameters validationOptions,
			final IPAddressParseData parseData,
			final ParsedHostIdentifierStringQualifier qualifier) throws AddressStringException {
		IPVersion version = parseData.ipVersion;
		if(version == null) {
			version = qualifier.inferVersion(validationOptions);
			IPVersion optionsVersion = validationOptions.inferVersion();
			if(version == null) {
				parseData.ipVersion = version = optionsVersion;
			} else {
				if(optionsVersion != null && !version.equals(optionsVersion)) {
					throw new AddressStringException(fullAddr, version == IPVersion.IPV6 ? "ipaddress.error.ipv6" : "ipaddress.error.ipv4");
				}
			}
			if(parseData.addressParseData.isEmpty) {
				if(qualifier.getNetworkPrefixLength() != null) {
					return new MaskCreator(qualifier, version);
				} else {
					//Note: we do not support loopback with zone, it seems the loopback is never associated with a link-local zone
					if(validationOptions.emptyIsLoopback) {
						return IPAddressProvider.LOOPBACK_CREATOR;
					}
					return IPAddressProvider.EMPTY_PROVIDER;
				}
			} else { //isAll
				if(qualifier == ParsedHost.NO_QUALIFIER && version == null) {
					return IPAddressProvider.ALL_ADDRESSES_CREATOR;
				}
				return new AllCreator(qualifier, version, originator);
			}
		} else {
			if(parseData.isZoned && parseData.ipVersion.isIPv4()) {
				throw new AddressStringException(fullAddr, "ipaddress.error.only.ipv6.has.zone");
			}
			ParsedIPAddress valueCreator = createIPAddressProvider(originator, fullAddr, validationOptions, parseData, qualifier);
			return new ParsedAddressProvider(valueCreator);
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
		boolean flags[] = parseData.flags[segmentIndex];
		long values[] = parseData.values[segmentIndex];
		int indices[] = parseData.indices[segmentIndex];
		int lowerRadix = indices[AddressParseData.LOWER_RADIX_INDEX];
		if(flags[AddressParseData.SINGLE_WILDCARD_INDEX]) {
			if(values[AddressParseData.LOWER_INDEX] > maxValue) {
				throw new AddressStringException(fullAddr, "ipaddress.error.ipv4.segment.too.large");
			}
			if(values[AddressParseData.UPPER_INDEX] > maxValue) {
				values[AddressParseData.UPPER_INDEX] = maxValue;
			}
			if(!params.allowUnlimitedLeadingZeros) {
				if(indices[AddressParseData.LOWER_STR_END_INDEX] - indices[AddressParseData.LOWER_STR_DIGITS_INDEX] -  getStringPrefixCharCount(lowerRadix) > maxDigitCount) {
					throw new AddressStringException(fullAddr, "ipaddress.error.segment.too.long");
				}
			}
		} else {
			if(values[AddressParseData.UPPER_INDEX] > maxValue) {
				throw new AddressStringException(fullAddr, "ipaddress.error.ipv4.segment.too.large");
			}
			int upperRadix = indices[AddressParseData.UPPER_RADIX_INDEX];
			if(!params.allowUnlimitedLeadingZeros) {
				if(indices[AddressParseData.LOWER_STR_END_INDEX] - indices[AddressParseData.LOWER_STR_DIGITS_INDEX] - getStringPrefixCharCount(lowerRadix) > maxDigitCount) {
					throw new AddressStringException(fullAddr, "ipaddress.error.segment.too.long");
				}
				if(indices[AddressParseData.UPPER_STR_END_INDEX] - indices[AddressParseData.UPPER_STR_DIGITS_INDEX] - getStringPrefixCharCount(upperRadix) > maxUpperDigitCount) {
					throw new AddressStringException(fullAddr, "ipaddress.error.segment.too.long");
				}
			}
		}
	}

	private static ParsedIPAddress createIPAddressProvider(
			final HostIdentifierString originator,
			final CharSequence fullAddr,
			final IPAddressStringParameters validationOptions,
			final IPAddressParseData parseData,
			final ParsedHostIdentifierStringQualifier qualifier) throws AddressStringException {
		final int segCount = parseData.addressParseData.segmentCount;
		IPVersion version = parseData.ipVersion;
		if(version.isIPv4()) {
			int missingCount = IPv4Address.SEGMENT_COUNT - segCount;
			final IPv4AddressStringParameters ipv4Options = validationOptions.getIPv4Parameters();
			if(missingCount > 0 && !parseData.addressParseData.anyWildcard) {
				//single segments are handled in the parsing code with the allowSingleSegment setting
				if(segCount > 1 && !ipv4Options.inet_aton_joinedSegments) {
					throw new AddressStringException(fullAddr, "ipaddress.error.ipv4.too.few.segments");
				}
			}
			//here we check whether values are too large or strings too long
			long oneSegmentMax = getMaxIPv4Value(0);
			for(int i = 0; i < segCount; i++) {
				long max;
				int maxDigits, maxUpperDigits;
				int indices[] = parseData.addressParseData.indices[i];
				int lowerRadix = indices[AddressParseData.LOWER_RADIX_INDEX];
				int upperRadix = indices[AddressParseData.UPPER_RADIX_INDEX];
				if(i == segCount - 1 && missingCount > 0) {
					max = getMaxIPv4Value(missingCount);
					maxDigits = getMaxIPv4StringLength(missingCount, lowerRadix);
					maxUpperDigits = (upperRadix != lowerRadix) ? getMaxIPv4StringLength(missingCount, upperRadix) : maxDigits;
				} else {
					max = oneSegmentMax;
					maxDigits = getMaxIPv4StringLength(0, lowerRadix);
					maxUpperDigits = (upperRadix != lowerRadix) ? getMaxIPv4StringLength(0, upperRadix) : maxDigits;
				}
				checkMaxValues(
						fullAddr,
						parseData.addressParseData,
						i,
						ipv4Options,
						max,
						maxDigits,
						maxUpperDigits);
			}
		} else {
			int totalSegmentCount = segCount;
			if(parseData.mixedParsedAddress != null) {
				totalSegmentCount += IPv6Address.MIXED_REPLACED_SEGMENT_COUNT;
			}
			if(totalSegmentCount != 1 && totalSegmentCount < IPv6Address.SEGMENT_COUNT && !parseData.addressParseData.anyWildcard && !parseData.isCompressed()) {
				throw new AddressStringException(fullAddr, "ipaddress.error.too.few.segments");
			}
		}
		ParsedIPAddress valueCreator = new ParsedIPAddress(originator, fullAddr, parseData, version, qualifier);
		return valueCreator;
	}
	
	@Override
	public int validatePrefix(CharSequence fullAddr, IPVersion version) throws AddressStringException {
		return validatePrefixImpl(fullAddr, version);
	}

	static int validatePrefixImpl(CharSequence fullAddr, IPVersion version) throws AddressStringException {
		ParsedHostIdentifierStringQualifier qualifier = validatePrefix(fullAddr, DEFAULT_PREFIX_OPTIONS, 0, fullAddr.length(), version);
		if(qualifier == null) {
			throw new AddressStringException(fullAddr.toString(), "ipaddress.error.invalidCIDRPrefix");
		}
		return qualifier.getNetworkPrefixLength();
	}

	private static ParsedHostIdentifierStringQualifier validatePort(
			final CharSequence fullAddr,
			final HostNameParameters validationOptions,
			final int index,
			final int endIndex) throws AddressStringException {
		if(!validationOptions.allowPort) {
			throw new AddressStringException(fullAddr.toString(), "ipaddress.host.error.port");
		}
		boolean isPort = true;
		int digitCount = 0;
		for(int i = index; isPort && i < endIndex; i++) {
			char c = fullAddr.charAt(i);
			if(c >= '1' && c <= '9') {
				++digitCount;
			} else if(c == '0') {
				if(digitCount > 0) {
					++digitCount;
				}
			} else {
				isPort = false;
			}
		}
		if(!isPort || digitCount > 5) {
			throw new AddressStringException(fullAddr.toString(), "ipaddress.error.invalidPort");
		}
		int result = parse10(fullAddr, index, endIndex);
		if(result > 65535) {
			throw new AddressStringException(fullAddr.toString(), "ipaddress.error.invalidPort");
		}
		return new ParsedHostIdentifierStringQualifier(null, result);
	}
	
	private static ParsedHostIdentifierStringQualifier validatePrefix(
			final CharSequence fullAddr,
			final IPAddressStringParameters validationOptions,
			final int index,
			final int endIndex,
			final IPVersion ipVersion) throws AddressStringException {
		if(index == fullAddr.length()) {
			return null;
		}
		boolean isPrefix = true;
		int digitCount, leadingZeros;
		digitCount = leadingZeros = 0;
		for(int i = index; isPrefix && i < endIndex; i++) {
			char c = fullAddr.charAt(i);
			if(c >= '1' && c <= '9') {
				++digitCount;
			} else if(c == '0') {
				if(digitCount > 0) {
					++digitCount;
				} else {
					++leadingZeros;
				}
			} else {
				isPrefix = false;
			}
		}
		//we treat as a prefix if all the characters were digits, even if there were too many, unless the mask options allow for inet_aton single segment
		if(isPrefix) {
			boolean asIPv4 = (ipVersion != null && ipVersion.isIPv4());
			if(digitCount == 0) {
				//we know leadingZeroCount is > 0 since we have checked already if there were no characters at all
				leadingZeros--;
				digitCount++;
			}
			if(leadingZeros > 0) {
				if(asIPv4) {
					if(!validationOptions.getIPv4Parameters().allowPrefixLengthLeadingZeros) {
						throw new AddressStringException(fullAddr.toString(), "ipaddress.error.ipv4.prefix.leading.zeros");
					}
				} else {
					if(!validationOptions.getIPv6Parameters().allowPrefixLengthLeadingZeros) {
						throw new AddressStringException(fullAddr.toString(), "ipaddress.error.ipv6.prefix.leading.zeros");
					}
				}
			}
			boolean allowPrefixesBeyondAddressSize = (asIPv4 ? validationOptions.getIPv4Parameters() : validationOptions.getIPv6Parameters()).allowPrefixesBeyondAddressSize;
			//before we attempt to parse, ensure the string is a reasonable size
			if(!allowPrefixesBeyondAddressSize && digitCount > (asIPv4 ? 2 : 3)) {
				if(asIPv4 && validationOptions.allowSingleSegment) {
				//if(asIPv4 && validationOptions.getIPv4Parameters().inet_aton_joinedSegments && validationOptions.getIPv4Parameters().inet_aton_single_segment_mask) {
					return null; //treat it as single segment ipv4 mask (ie /xxx not a prefix of length xxx but the mask xxx
				}
				throw new AddressStringException(fullAddr.toString(), "ipaddress.error.prefixSize");
			}
			int result = parse10(fullAddr, index, endIndex);
			if(!allowPrefixesBeyondAddressSize && result > (asIPv4 ? IPv4Address.BIT_COUNT : IPv6Address.BIT_COUNT)) {
				if(asIPv4 && validationOptions.allowSingleSegment) {
				//if(asIPv4 && validationOptions.getIPv4Parameters().inet_aton_joinedSegments && validationOptions.getIPv4Parameters().inet_aton_single_segment_mask) {
					return null; //treat it as a single segment ipv4 mask
				}
				throw new AddressStringException(fullAddr.toString(), "ipaddress.error.prefixSize");
			}
			if(result < PREFIX_CACHE.length) {
				ParsedHostIdentifierStringQualifier qual = PREFIX_CACHE[result];
				if(qual == null) {
					qual = PREFIX_CACHE[result] = new ParsedHostIdentifierStringQualifier(result, null);
				}
				return qual;
			}
			return new ParsedHostIdentifierStringQualifier(result, null);
		}
		return null;
	}
	
	private static ParsedHostIdentifierStringQualifier parseQualifier(
			CharSequence fullAddr,
			IPAddressStringParameters validationOptions,
			final HostNameParameters hostValidationOptions,
			IPAddressParseData ipAddressParseData,
			int endIndex) throws AddressStringException {
		if(ipAddressParseData.isBase85Zoned && !ipAddressParseData.isBase85) {
			throw new AddressStringException(fullAddr, ipAddressParseData.qualifierIndex - 1);
		}
		return parseQualifier(
				fullAddr,
				validationOptions,
				hostValidationOptions,
				ipAddressParseData.isPrefixed,
				ipAddressParseData.isZoned,
				ipAddressParseData.hasPort,
				ipAddressParseData.addressParseData.isEmpty,
				ipAddressParseData.qualifierIndex,
				endIndex,
				ipAddressParseData.ipVersion);
	}
	
	private static ParsedHostIdentifierStringQualifier parseQualifier(
			CharSequence fullAddr,
			IPAddressStringParameters validationOptions,
			HostNameParameters hostValidationOptions,
			boolean isPrefixed,
			boolean hasPort,
			IPAddressParseData ipAddressParseData,
			int qualifierIndex,
			int endIndex) throws AddressStringException {
		return parseQualifier(
				fullAddr,
				validationOptions,
				hostValidationOptions,
				isPrefixed,
				ipAddressParseData.isZoned,
				hasPort,
				ipAddressParseData.addressParseData.isEmpty,
				qualifierIndex,
				endIndex,
				ipAddressParseData.ipVersion);
	}
			
	
	private static ParsedHostIdentifierStringQualifier parseQualifier(
			final CharSequence fullAddr,
			final IPAddressStringParameters validationOptions,
			final HostNameParameters hostValidationOptions,
			final boolean isPrefixed,
			final boolean isZoned,
			final boolean isPort,
			final boolean addressIsEmpty,
			final int index,
			final int endIndex,
			final IPVersion ipVersion) throws AddressStringException {
		if(isPrefixed) {
			if(validationOptions.allowPrefix) {
				ParsedHostIdentifierStringQualifier qualifier = validatePrefix(fullAddr, validationOptions, index, fullAddr.length(), ipVersion);
				if(qualifier != null) {
					return qualifier;
				}
			}
			if(addressIsEmpty) {
				//PREFIX_ONLY must have a prefix and not a mask - we don't allow /255.255.0.0
				throw new AddressStringException(fullAddr, "ipaddress.error.invalidCIDRPrefix");
			}
			if(validationOptions.allowMask) {
				try {
					//check for a mask
					//check if we need a new validation options for the mask
					IPAddressStringParameters maskOptions = toMaskOptions(validationOptions, ipVersion);
					IPAddressParseData ipAddressParseData = new IPAddressParseData();
					validateIPAddress(maskOptions, fullAddr, index, endIndex, ipAddressParseData);
					AddressParseData maskParseData = ipAddressParseData.addressParseData;
					if(maskParseData.isEmpty || maskParseData.isAll) {
						throw new AddressStringException(fullAddr, "ipaddress.error.invalidCIDRPrefixOrMask");
					}
					ParsedIPAddress maskAddress = createIPAddressProvider(null, fullAddr, maskOptions, ipAddressParseData, ParsedHost.NO_QUALIFIER);
					//ParsedAddress maskAddress = createAddressProvider(null, null, fullAddr, maskOptions, maskParseData, NO_QUALIFIER);
					if(maskParseData.addressEndIndex != fullAddr.length()) { // 1.2.3.4/ or 1.2.3.4// or 1.2.3.4/%
						throw new AddressStringException(fullAddr, "ipaddress.error.invalidCIDRPrefixOrMask");
					}
					IPVersion maskVersion = ipAddressParseData.ipVersion;
					if(maskVersion.isIPv4() && maskParseData.segmentCount == 1 && !maskParseData.anyWildcard && !validationOptions.getIPv4Parameters().inet_aton_single_segment_mask) {//1.2.3.4/33 where 33 is an aton_inet single segment address and not a prefix length
						throw new AddressStringException(fullAddr, "ipaddress.error.mask.single.segment");
					}
					if(ipVersion != null && (maskVersion.isIPv4() != ipVersion.isIPv4() || maskVersion.isIPv6() != ipVersion.isIPv6())) {
						//note that this also covers the cases of non-standard addresses in the mask, ie mask neither ipv4 or ipv6
						throw new AddressStringException(fullAddr, "ipaddress.error.ipMismatch");
					}
					return new ParsedHostIdentifierStringQualifier(maskAddress);
				} catch(AddressStringException e) {
					throw new AddressStringException(fullAddr, "ipaddress.error.invalidCIDRPrefixOrMask", e);
				}
			}
			throw new AddressStringException(fullAddr, "ipaddress.error.CIDRNotAllowed");
		} else if(isZoned) {
			if(addressIsEmpty) {
				throw new AddressStringException(fullAddr, "ipaddress.error.only.zone");
			}
			CharSequence zone = fullAddr.subSequence(index, endIndex);
			return new ParsedHostIdentifierStringQualifier(zone);
		} else if(isPort) {
			ParsedHostIdentifierStringQualifier qualifier = validatePort(fullAddr, hostValidationOptions, index, fullAddr.length());
			if(qualifier != null) {
				return qualifier;
			}
			throw new AddressStringException(fullAddr, "ipaddress.error.invalidPort");
		} else {
			return ParsedHost.NO_QUALIFIER;
		}
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
	
	private static void assignAttributes(int frontStart, int frontEnd, int start, int end, int indices[], int frontLeadingZeroStartIndex, int leadingZeroStartIndex) {
		indices[AddressParseData.LOWER_STR_DIGITS_INDEX] = frontLeadingZeroStartIndex;
		indices[AddressParseData.LOWER_STR_START_INDEX] = frontStart;
		indices[AddressParseData.LOWER_STR_END_INDEX] = frontEnd;
		indices[AddressParseData.UPPER_STR_DIGITS_INDEX] = leadingZeroStartIndex;
		indices[AddressParseData.UPPER_STR_START_INDEX] = start;
		indices[AddressParseData.UPPER_STR_END_INDEX] = end;
	}
	
	private static void assignAttributes(int frontStart, int frontEnd, int start, int end, int indices[], int frontLeadingZeroStartIndex, int leadingZeroStartIndex, int frontRadix, int radix) {
		indices[AddressParseData.LOWER_RADIX_INDEX] = frontRadix;
		indices[AddressParseData.UPPER_RADIX_INDEX] = radix;
		assignAttributes(frontStart, frontEnd, start, end, indices, frontLeadingZeroStartIndex, leadingZeroStartIndex);
	}
	
	private static void assignAttributes(int start, int end, int indices[], int leadingZeroStartIndex) {
		indices[AddressParseData.UPPER_STR_DIGITS_INDEX] = indices[AddressParseData.LOWER_STR_DIGITS_INDEX] = leadingZeroStartIndex;
		indices[AddressParseData.UPPER_STR_START_INDEX] = indices[AddressParseData.LOWER_STR_START_INDEX] = start;
		indices[AddressParseData.UPPER_STR_END_INDEX] = indices[AddressParseData.LOWER_STR_END_INDEX] = end;
	}
	
	private static void assignAttributes(int start, int end, int indices[], int radix, int leadingZeroStartIndex) {
		indices[AddressParseData.UPPER_RADIX_INDEX] = indices[AddressParseData.LOWER_RADIX_INDEX] = radix;
		assignAttributes(start, end, indices, leadingZeroStartIndex);
	}
	
	private static void assignSingleWildcardAttributes(CharSequence str, int start, int end, int digitsEnd, int numSingleWildcards, int indices[],  boolean flags[], int radix, int leadingZeroStartIndex, AddressStringFormatParameters options) throws AddressStringException {
		if(!options.rangeOptions.allowsSingleWildcard()) {
			throw new AddressStringException(str, "ipaddress.error.no.single.wildcard");
		}
		for(int k = digitsEnd; k < end; k++) {
			if(str.charAt(k) != IPAddress.SEGMENT_SQL_SINGLE_WILDCARD) {
				throw new AddressStringException(str, "ipaddress.error.single.wildcard.order");
			}
		}
		flags[AddressParseData.SINGLE_WILDCARD_INDEX] = true;
		assignAttributes(start, end, indices, radix, leadingZeroStartIndex);
	}
	
	private static void parseSingleWildcard10(CharSequence s, int start, int end, int numSingleWildcards, int indices[], long vals[],  boolean flags[], int leadingZeroStartIndex, AddressStringFormatParameters options) throws AddressStringException {
		int digitsEnd = end - numSingleWildcards;
		assignSingleWildcardAttributes(s, start, end, digitsEnd, numSingleWildcards, indices, flags, 10, leadingZeroStartIndex, options);
		long lower;
		if(start < digitsEnd) {
			lower = parseLong10(s, start, digitsEnd);
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
		vals[AddressParseData.LOWER_INDEX] = lower;
		vals[AddressParseData.UPPER_INDEX] = upper;
	}
	
	private static void parseSingleWildcard8(CharSequence s, int start, int end, int numSingleWildcards, int indices[], long vals[],  boolean flags[], int leadingZeroStartIndex, AddressStringFormatParameters options) throws AddressStringException {
		int digitsEnd = end - numSingleWildcards;
		assignSingleWildcardAttributes(s, start, end, digitsEnd, numSingleWildcards, indices, flags, 8, leadingZeroStartIndex, options);
		long lower = (start < digitsEnd) ? parseLong8(s, start, digitsEnd) : 0;
		long upper;
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
		vals[AddressParseData.LOWER_INDEX] = lower;
		vals[AddressParseData.UPPER_INDEX] = upper;
	}
	
	private static void parseSingleWildcard16(CharSequence s, int start, int end, int numSingleWildcards, int indices[], long vals[],  boolean flags[], int leadingZeroStartIndex, AddressStringFormatParameters options) throws AddressStringException {
		int digitsEnd = end - numSingleWildcards;
		assignSingleWildcardAttributes(s, start, end, digitsEnd, numSingleWildcards, indices, flags, 16, leadingZeroStartIndex, options);
		long lower = (start < digitsEnd) ? parseLong16(s, start, digitsEnd) : 0;
		int shift = numSingleWildcards << 2;
		lower <<= shift;
		long upper = lower | ~(~0L << shift);
		vals[AddressParseData.LOWER_INDEX] = lower;
		vals[AddressParseData.UPPER_INDEX] = upper;
	}

	private static void parseSingleSegmentSingleWildcard16(CharSequence s, int start, int end, int numSingleWildcards, int indices[], long vals[],  boolean flags[], int leadingZeroStartIndex, AddressStringFormatParameters options) throws AddressStringException {
		int digitsEnd = end - numSingleWildcards;
		assignSingleWildcardAttributes(s, start, end, digitsEnd, numSingleWildcards, indices, flags, 16, leadingZeroStartIndex, options);
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
			extendedUpper = extendedLower = parseLong16(s, start, digitsEnd);
		} else {
			lower = 0;
			upper = 0xffffffffffffffffL;
			extendedLower = parseLong16(s, start, digitsEnd);
			int shift = (numSingleWildcards - LONG_HEX_DIGITS) << 2;
			extendedLower <<= shift;
			extendedUpper = extendedLower | ~(~0L << shift);
		}
		vals[AddressParseData.LOWER_INDEX] = lower;
		vals[AddressParseData.UPPER_INDEX] = upper;
		vals[AddressParseData.EXTENDED_LOWER_INDEX] = extendedLower;
		vals[AddressParseData.EXTENDED_UPPER_INDEX] = extendedUpper;
	}
	
	private static long getMaxIPv4Value(int additionalSegmentsCovered) {
		if(additionalSegmentsCovered == 0) {
			return IPv4Address.MAX_VALUE_PER_SEGMENT;
		} else if(additionalSegmentsCovered == 1) {
			return 0xffff;
		} else if(additionalSegmentsCovered == 2) {
			return 0xffffff;
		}
		return 0xffffffffL;
	}
	
	private static int getStringPrefixCharCount(int radix) {
		if(radix == 10) {
			return 0;
		} else if(radix == 16) {
			return 2;
		}
		return 1;
	}
	
	private static int getMaxIPv4StringLength(int additionalSegmentsCovered, int radix) {
		if(radix == 10) {
			if(additionalSegmentsCovered == 0) {
				return IPv4AddressSegment.MAX_CHARS;//255
			} else if(additionalSegmentsCovered == 1) {
				return 5;//65535
			} else if(additionalSegmentsCovered == 2) {
				return 8;//16777215
			}
			return 10;//4294967295
		} else if(radix == 16) {
			if(additionalSegmentsCovered == 0) {
				return 2;//0xff
			} else if(additionalSegmentsCovered == 1) {
				return 4;//0xffff
			} else if(additionalSegmentsCovered == 2) {
				return 6;//0xffffff
			}
			return 8;//0xffffffffL
		}
		//radix is octal
		if(additionalSegmentsCovered == 0) {
			return 3;//0377
		} else if(additionalSegmentsCovered == 1) {
			return 6;//0177777
		} else if(additionalSegmentsCovered == 2) {
			return 8;//077777777
		}
		return 11;//037777777777
	}
	
	private static int parse8(CharSequence s, int start, int end) {
		int charArray[] = chars;
		int result = charArray[s.charAt(start)];
		while (++start < end) {
			result = (result << 3) | charArray[s.charAt(start)];
       }
	   return result;
	}
	
	private static long parseLong8(CharSequence s, int start, int end) {
		if(end - start <= 10) { //10 digits in octal fit into an integer
			return parse8(s, start, end);
		}
		int charArray[] = chars;
		long result = charArray[s.charAt(start)];
		while (++start < end) {
			result = (result << 3) | charArray[s.charAt(start)];
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
	
	private static long parseLong10(CharSequence s, int start, int end) {
		if(end - start <= 9) { //9 digits in decimal into an integer
			return parse10(s, start, end);
		}
		int charArray[] = chars;
		long result = charArray[s.charAt(start)];
		while (++start < end) {
			result = (result * 10) + charArray[s.charAt(start)];
		}
		return result;
	}
	
	private static int parse16(CharSequence s, int start, int end) {
		int charArray[] = chars;
		int result = charArray[s.charAt(start)];
		while (++start < end) {
			result = (result << 4) | charArray[s.charAt(start)];
		}
		return result;
	}
	
	private static long parseLong16(CharSequence s, int start, int end) {
		if(end - start <= 7) { //7 hex digits fit into an integer
			return parse16(s, start, end);
		}
		int charArray[] = chars;
		long result = charArray[s.charAt(start)];
		while (++start < end) {
			result = (result << 4) | charArray[s.charAt(start)];
		}
		return result;
	}
	
	private static final BigInteger BASE_85_POWERS[] = new BigInteger[10];
	private static final BigInteger LOW_BITS_MASK = BigInteger.valueOf(0xffffffffffffffffL);
	
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
		boolean segmentUppercase, isNotNormalized, squareBracketed, isAllDigits, isPossiblyIPv6, isPossiblyIPv4, tryIPv6, tryIPv4, isPrefixed, hasPort, addressIsEmpty;
		isSpecialOnlyIndex = qualifierIndex = index = lastSeparatorIndex = -1;
		int labelCount = 0;
		int maxLocalLabels = 6;//should be at least 4 to avoid the array for ipv4 addresses
		int separatorIndices[] = null;
		boolean normalizedFlags[] = null;
		int sep0, sep1, sep2, sep3, sep4, sep5;
		boolean upper0, upper1, upper2, upper3, upper4, upper5;
		
		segmentUppercase = isNotNormalized = squareBracketed = tryIPv6 = tryIPv4 = isPrefixed = hasPort = addressIsEmpty = false;
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
					if(hasPort && isPossiblyIPv6) {//isPossiblyIPv6 is already false if labelCount > 0
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
								throw new HostNameException(str, index);
							}
							isPossiblyIPv6 = false;
						}
					}
					isAllDigits = false;
				} else if(currentChar == IPv6Address.SEGMENT_SEPARATOR) {
					if(validationOptions.allowPort) {
						hasPort = true;
						qualifierIndex = index + 1;
						addrLen = index;
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
					IPAddressParseData ipAddressParseData = new IPAddressParseData();
					ParsedHostIdentifierStringQualifier addrQualifier;
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
							/*
							 RFC 3986 section 3.2.2
							  	host = IP-literal / IPv4address / reg-name
	      						IP-literal = "[" ( IPv6address / IPvFuture  ) "]"
	      						IPvFuture  = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
	      					If a URI containing an IP-literal that starts with "v" (case-insensitive),
	   						indicating that the version flag is present, is dereferenced by an application 
	   						that does not know the meaning of that version flag, then
	   						the application should return an appropriate error for "address mechanism not supported".
							 */
							char firstChar = str.charAt(1);
							if(firstChar == IPvFUTURE || firstChar == IPvFUTURE_UPPERCASE) {
								throw new HostNameException(str, "ipaddress.host.error.invalid.mechanism");
							}
						}
						validateIPAddress(addressOptions, str, startIndex, endIndex, ipAddressParseData);
						if(endsWithQualifier) {
							//here we check what is in the qualifier that follows the bracket: prefix/mask or port?
							//if prefix/mask, we supply the qualifier to the address, otherwise we supply it to the host
							int prefixIndex = endIndex + 1;
							char prefixChar = str.charAt(prefixIndex);
							if(prefixChar == IPAddress.PREFIX_LEN_SEPARATOR) {
								if(ipAddressParseData.isZoned) {
									throw new HostNameException(str, "ipaddress.error.zoneAndCIDRPrefix");
								}
								isPrefixed = true;
							} else {
								if(prefixChar == HostName.PORT_SEPARATOR) {
									hasPort = true;
								} else {
									throw new HostNameException(str, prefixIndex);
								}
							}
							qualifierIndex = prefixIndex + 1;//skip the ']/'
							endIndex = str.length();
							ParsedHostIdentifierStringQualifier parsedQualifier = parseQualifier(str, addressOptions, validationOptions, isPrefixed, false, hasPort, ipAddressParseData.addressParseData.isEmpty, qualifierIndex, endIndex, ipAddressParseData.ipVersion);
							if(isPrefixed) {
								addrQualifier = parsedQualifier;
							} else {
								hostQualifier = parsedQualifier;
								//there could be a zone, so get it
								addrQualifier = parseQualifier(str, addressOptions, null, false, false, ipAddressParseData, ipAddressParseData.qualifierIndex, prefixIndex - 1);
							}
						} else {
							qualifierIndex = ipAddressParseData.qualifierIndex;
							isPrefixed = ipAddressParseData.isPrefixed;
							hasPort = ipAddressParseData.hasPort;
							if(ipAddressParseData.isZoned && str.charAt(ipAddressParseData.qualifierIndex) == '2' && 
									str.charAt(ipAddressParseData.qualifierIndex + 1) == '5') {
								//handle %25 from rfc 6874
								qualifierIndex += 2;
							}
							addrQualifier = parseQualifier(str, addressOptions, validationOptions, isPrefixed, hasPort, ipAddressParseData, qualifierIndex, endIndex);
						}
						//SMTP rfc 2821 allows [ipv4address]
						IPVersion version = ipAddressParseData.ipVersion;
						if(version != IPVersion.IPV6 && !validationOptions.allowBracketedIPv4) {
							throw new HostNameException(str, "ipaddress.host.error.bracketed.not.ipv6");
						}
					} else {
						/*
						there are cases where it can be ipv4 or ipv6, but they are rare
						any address with a '.' in it cannot be ipv6 at this point (if we hit a ':' first we would have jumped out of the loop)
						any address with a ':' has gone through tests to see if up until that point it could match an ipv4 address or an ipv6 address
						it can only be ipv4 if it has right number of segments, and only decimal digits.
						it can only be ipv6 if it has only hex digits.
						so when can it be both?  if it looks like *: at the start, so that it has the right number of segments for ipv4 but does not have a '.' invalidating ipv6
						so in that case we might have either something like *:1 for it to be ipv4 (ambiguous is treated as ipv4) or *:f:: to be ipv6
						So we validate the potential port to determine which one and then go from there
						 */
						boolean isPotentiallyIPv4 = isPossiblyIPv4 || tryIPv4; //tryIPv4 is typically something like 1.2.3.4 or with '*'
						boolean isPotentiallyIPv6 = isPossiblyIPv6 || tryIPv6; //tryIPv6 is typically something with ':' or '*'
						int endIndex;
						if(isPotentiallyIPv4) {
							//validate the port
							if(!hasPort) {
								for(int j = index; j < addrLen; j++) {
									char c = str.charAt(j);
									if(c == IPv6Address.SEGMENT_SEPARATOR) {
										qualifierIndex = j + 1;
										hasPort = true;
									} 
								}
							}
							if(hasPort) {
								try {
									hostQualifier = validatePort(str, validationOptions, qualifierIndex, str.length());
									//validates as port, we have ipv4
									endIndex = qualifierIndex - 1;
								} catch(AddressStringException e) {
									if(isPotentiallyIPv6) {
										hostQualifier = ParsedHost.NO_QUALIFIER;
										endIndex = str.length();
									} else {
										throw e;
									}
								}
							} else {
								endIndex = str.length();
							}
						} else {
							endIndex = str.length();
						}
						validateIPAddress(addressOptions, str, 0, endIndex, ipAddressParseData);
						addrQualifier = parseQualifier(str, addressOptions, validationOptions, ipAddressParseData, endIndex);
					}
					IPAddressProvider provider = createProvider(fromHost, str, addressOptions, ipAddressParseData, addrQualifier);
					return new ParsedHost(str, provider, hostQualifier);
				} catch(AddressStringException e) {
					if(isIPAddress) {
						throw e;
					} //else fall though and evaluate as a host
				}
			}
			ParsedHostIdentifierStringQualifier qualifier = parseQualifier(str, addressOptions, validationOptions, isPrefixed, false, hasPort, addressIsEmpty, qualifierIndex, str.length(), null);
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
				
				//here we check what is in the qualifier that follows the bracket: prefix/mask or port?
				//if prefix/mask, we supply the qualifier to the address, otherwise we supply it to the host
				//int the case of port, it is possible the address has a zone
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
					switch(c) {
						case IPv6Address.UNC_SEGMENT_SEPARATOR:
							builder.setCharAt(i, IPv6Address.SEGMENT_SEPARATOR);
							break;
						case IPv6Address.UNC_RANGE_SEPARATOR:
							builder.setCharAt(i, IPv6Address.RANGE_SEPARATOR);
							break;
						case IPv6Address.UNC_ZONE_SEPARATOR:
							builder.setCharAt(i, IPv6Address.ZONE_SEPARATOR);
							break;
						default:
					}
				}
				emb = new EmbeddedAddress();
				emb.isUNCIPv6Literal = true;
				IPAddressParseData ipAddressParseData = new IPAddressParseData();
				IPAddressStringParameters params = DEFAULT_UNC_OPTS;
				validateIPAddress(params, builder, 0, builder.length(), ipAddressParseData);
				IPAddressProvider provider = createProvider(null, builder, params, ipAddressParseData,
					//this is the qualifier for the address, which is not the same as the qualifier for the host name
					(hostQualifier != null && hostQualifier != ParsedHost.NO_QUALIFIER) ? hostQualifier :
						parseQualifier(builder, DEFAULT_UNC_OPTS, null, ipAddressParseData, builder.length()));
				emb.addressProvider = provider;
			}
			//TODO later? support bitstring labels and support subnets
			//rfc 2673
			//arpa: https://www.ibm.com/support/knowledgecenter/SSLTBW_1.13.0/com.ibm.zos.r13.halz002/f1a1b3b1220.htm
			//Also, support partial dns lookups and map then to the associated subnet with prefix length, which I think we may 
			//already do for ipv4 but not for ipv6, ipv4 uses hte prefix notation d.c.b.a/x but ipv6 uses fewer nibbles
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
					if(isIPv4) {
						//unlike IPv6, we parse first then reverse the segments
						IPAddressParseData ipAddressParseData = new IPAddressParseData();
						IPAddressStringParameters params = REVERSE_DNS_IPV4_OPTS;
						validateIPAddress(params, str, 0, suffixStartIndex, ipAddressParseData);
						ipAddressParseData.reverseSegments();
						IPAddressProvider provider = createProvider(null, str, params, ipAddressParseData, hostQualifier != null ? hostQualifier : ParsedHost.NO_QUALIFIER);
						emb.addressProvider = provider;
					} else {
						CharSequence sequence = convertReverseDNSIPv6(str, suffixStartIndex);
						IPAddressParseData ipAddressParseData = new IPAddressParseData();
						IPAddressStringParameters params = REVERSE_DNS_IPV6_OPTS;
						validateIPAddress(params, sequence, 0, sequence.length(), ipAddressParseData);
						IPAddressProvider provider = createProvider(null, sequence, params, ipAddressParseData, hostQualifier != null ? hostQualifier : ParsedHost.NO_QUALIFIER);
						emb.addressProvider = provider;
					}
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
		if(segCount != 8) {
			throw new AddressStringException(str, 0);
		}
		return builder;
	}
}
