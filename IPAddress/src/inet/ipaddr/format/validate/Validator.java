package inet.ipaddr.format.validate;

import inet.ipaddr.HostName;
import inet.ipaddr.HostNameException;
import inet.ipaddr.HostNameParameters;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.IPAddressStringException;
import inet.ipaddr.IPAddressStringParameters;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressStringParameters.IPVersionAddressStringParameters;
import inet.ipaddr.IPAddressStringParameters.RangeParameters;
import inet.ipaddr.format.validate.AddressProvider.AllCreator;
import inet.ipaddr.format.validate.AddressProvider.MaskCreator;
import inet.ipaddr.format.validate.AddressProvider.ParsedAddressProvider;
import inet.ipaddr.format.validate.ParsedAddress.ParseData;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv4.IPv4AddressSegment;
import inet.ipaddr.ipv4.IPv4AddressStringParameters;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.ipv6.IPv6AddressSegment;
import inet.ipaddr.ipv6.IPv6AddressStringParameters;

/**
 * Validates host strings, address strings, and prefix lengths.
 * 
 * @author sfoley
 *
 */
public class Validator implements HostIdentifierStringValidator {
	
	private static final int chars[] = new int[128]; static {
		int charArray[] = chars;
		int i = 0;
		for(char c = '0'; i < 10; i++, c++) {
			charArray[c] = i;
		}
		for(char c = 'a', c2 = 'A'; i < 16; i++, c++, c2++) {
			charArray[c] = charArray[c2] = i;
		}
	}

	private static final int MAX_HOST_LENGTH = 253;
	private static final int MAX_HOST_SEGMENTS = 127;
	private static final int MAX_LABEL_LENGTH = 63;
	
	private static final int EMPTY_INDICES[] = new int[0];
	private static final ParsedAddressQualifier PREFIX_CACHE[] = new ParsedAddressQualifier[IPv6Address.BIT_COUNT + 1];
	private static final ParsedAddressQualifier NO_QUALIFIER = new ParsedAddressQualifier();
	private static final ParsedHost DEFAULT_EMPTY_HOST = new ParsedHost("", EMPTY_INDICES, null, NO_QUALIFIER);
	private static final IPAddressStringParameters DEFAULT_PREFIX_OPTIONS = new IPAddressStringParameters.Builder().toParams();

	public static final HostIdentifierStringValidator VALIDATOR = new Validator();
	
	/**
	 * Singleton - this class has no state
	 */
	private Validator() {}

	@Override
	public ParsedHost validateHost(HostName fromHost) throws HostNameException {
		return validateHostImpl(fromHost);
	}

	@Override
	public AddressProvider validateAddress(IPAddressString fromString) throws IPAddressStringException {
		return validateAddressImpl(fromString);
	}

	@Override
	public int validatePrefix(CharSequence fullAddr, IPVersion version) throws IPAddressStringException {
		return validatePrefixImpl(fullAddr, version);
	}
	
	static AddressProvider validateAddressImpl(IPAddressString fromString) throws IPAddressStringException {
		String str = fromString.toString();
		IPAddressStringParameters validationOptions = fromString.getValidationOptions();
		ParseData parseData = validateAddress(validationOptions, str, 0, str.length());
		return createProvider(
				null,
				fromString,
				str,
				validationOptions,
				parseData,
				parseQualifier(str,
						validationOptions,
						parseData.isPrefixed,
						parseData.isZoned,
						parseData.isEmpty,
						parseData.qualifierIndex,
						str.length(),
						parseData.ipVersion));
	}
	
	private static ParseData validateAddress(
			final IPAddressStringParameters validationOptions,
			final String str,
			final int strStartIndex,
			int strEndIndex) throws IPAddressStringException {
		ParseData parseData = new ParseData();
		final IPv6AddressStringParameters ipv6Options = validationOptions.getIPv6Parameters();
		final IPv4AddressStringParameters ipv4Options = validationOptions.getIPv4Parameters();
		
		int index = strStartIndex;
		
		//per segment variables
		int lastSeparatorIndex = -1, digitCount = 0, leadingZeroCount = 0, rangeWildcardIndex = -1, singleWildcardCount = 0, wildcardCount = 0;
		boolean notOctal = false, notDecimal = false, uppercase = false,  isIPv4Hex = false;
		int frontDigitCount = 0, frontLeadingZeroCount = 0;
		boolean frontNotOctal = false, frontNotDecimal = false, frontUppercase = false,  frontIsIPv4Hex = false;

		while(index <= strEndIndex) {
			char currentChar;
			if(index == strEndIndex) {
				parseData.addressEndIndex = index;
				//current char is either . or : to handle last segment, unless we have double :: in which case we already handled last segment
				IPVersion version = parseData.ipVersion;
				if(version != null) {
					if(version.isIPv4()) {
						currentChar = IPv4Address.SEGMENT_SEPARATOR;
					} else { //ipv6
						if(index == lastSeparatorIndex + 1) {
							if(index == parseData.consecutiveIPv6SepIndex + 2) {
								//ends with ::, we've already parsed the last segment
								break;
							}
							throw new IPAddressStringException(str, "ipaddress.error.cannot.end.with.single.separator");
						} else if(parseData.mixedParsedAddress != null) {
							//no need to parse the last segment, since it is mixed we already have
							break;
						} else {
							currentChar = IPv6Address.SEGMENT_SEPARATOR;
						}
					} 
				} else {
					//no segment separator so far and segmentCount is 0
					//it could be all addresses like "*", ipv4 single segment like 12345 , empty "", or prefix only like /64
					if(index == strStartIndex) {
						//it is prefix-only or ""
						parseData.isEmpty = true;
						break;
					} else if(wildcardCount > 0) {// "*"
						if(singleWildcardCount > 0 || rangeWildcardIndex >= 0 || leadingZeroCount > 0 || digitCount > 0 || isIPv4Hex) {//wildcards must appear alone
							throw new IPAddressStringException(str, index, true);
						}
						parseData.anyWildcard = true;
						parseData.isAll = true;
						break;
					}
					//it is ipv4 single segment like 4294967295 which is equivalent to 255.255.255.255
					currentChar = IPv4Address.SEGMENT_SEPARATOR;
				}
			} else {
				currentChar = str.charAt(index);
			}
			
			//evaluate the character
			if(currentChar >= '1' && currentChar <= '9') {
				++digitCount;
				++index;
				notOctal |= currentChar >= '8';
			} else if(currentChar >= 'a' && currentChar <= 'f') {
				++digitCount;
				++index;
				notOctal = notDecimal = true;
			} else if(currentChar == '0') {
				if(digitCount > 0) {
					++digitCount;
				} else {
					++leadingZeroCount;
				}
				++index;
			} else if(currentChar == IPv4Address.SEGMENT_SEPARATOR) {
				if(parseData.ipVersion != null && parseData.ipVersion.isIPv6()) {
					//mixed address like 1:2:3:4:5:6:1.2.3.4
					int segCount = parseData.segmentCount;
					if(!ipv6Options.allowMixed) {
						throw new IPAddressStringException(str, "ipaddress.error.no.mixed");
					}
					int totalSegmentCount = parseData.segmentCount + IPv6Address.MIXED_REPLACED_SEGMENT_COUNT;
					if(totalSegmentCount > IPv6Address.SEGMENT_COUNT) {
						throw new IPAddressStringException(str, "ipaddress.error.ipv6.too.many.segments");
					}
					if(wildcardCount > 0) {
						parseData.anyWildcard = true;
					}
					boolean isNotExpandable = wildcardCount > 0 && parseData.consecutiveIPv6SepIndex < 0;
					if(isNotExpandable && 
							totalSegmentCount < IPv6Address.SEGMENT_COUNT && 
							ipv6Options.allowWildcardedSeparator) {
						//the '*' is covering an additional ipv6 segment (eg 1:2:3:4:5:*.2.3.4, the * covers both an ipv4 and ipv6 segment)
						parseData.values[segCount][ParseData.UPPER_INDEX] = IPv6Address.MAX_VALUE_PER_SEGMENT;
						parseData.flags[segCount][ParseData.WILDCARD_INDEX] = true;
						parseData.segmentCount++;
					}
					IPAddressStringParameters mixedOptions = ipv6Options.getMixedParameters();
					ParseData mixedParseData = validateAddress(mixedOptions, str, lastSeparatorIndex + 1, strEndIndex);
					parseData.mixedParsedAddress = createAddressProvider(null, null, str, mixedOptions, mixedParseData, NO_QUALIFIER);
					index = mixedParseData.addressEndIndex;
				} else {
					//end of an ipv4 segment
					parseData.ipVersion = IPVersion.IPV4;
					int segCount = parseData.segmentCount;
					if(segCount == 0) {
						parseData.initSegmentData(IPv4Address.SEGMENT_COUNT);
					} else if(segCount >= IPv4Address.SEGMENT_COUNT) {
						throw new IPAddressStringException(str, "ipaddress.error.ipv4.too.many.segments");
					}
					long vals[] = parseData.values[segCount];
					int indices[] = parseData.indices[segCount];
					boolean flags[] = parseData.flags[segCount];
					if(wildcardCount > 0) {
						if(!ipv4Options.rangeOptions.allowsWildcard()) {
							throw new IPAddressStringException(str, "ipaddress.error.no.wildcard");
						}
						if(singleWildcardCount > 0 || rangeWildcardIndex >= 0 || leadingZeroCount > 0 || digitCount > 0 || isIPv4Hex) {//wildcards must appear alone
							throw new IPAddressStringException(str, index, true);
						}
						parseData.anyWildcard = true;
						flags[ParseData.WILDCARD_INDEX] = true;
						vals[ParseData.UPPER_INDEX] = IPv4Address.MAX_VALUE_PER_SEGMENT;
						int startIndex = index - wildcardCount;
						assignAttributes(startIndex, index, indices, startIndex);
					} else {
						if(leadingZeroCount > 0 && !ipv4Options.allowLeadingZeros && !ipv4Options.inet_aton_octal) {
							throw new IPAddressStringException(str, "ipaddress.error.ipv4.segment.leading.zeros");
						}
						long value = 0;
						boolean isStandard = false;
						int radix;
						int startIndex = index - digitCount;
						int leadingZeroStartIndex = startIndex - leadingZeroCount;
						int endIndex = index;
						boolean isSingleWildcard;
						boolean isJustZero;
						int maxChars = getMaxIPv4StringLength(3, 8);
						if(digitCount == 0) {
							if(leadingZeroCount == 0) {
								//starts with '.' or two consecutive '.'
								throw new IPAddressStringException(str, "ipaddress.error.ipv4.empty.segment");
							}
							isSingleWildcard = false;
							isJustZero = true;
							startIndex--;
							digitCount++;
							leadingZeroCount--;
							if(isIPv4Hex) {
								if(!ipv4Options.inet_aton_hex) {
									throw new IPAddressStringException(str, "ipaddress.error.ipv4.segment.hex");
								}
								radix = 16;
							} else if(leadingZeroCount > 0 && !ipv4Options.allowLeadingZeros && ipv4Options.inet_aton_octal) {
								radix = 8;
							} else {
								radix = 10;
							}
							flags[ParseData.STANDARD_STR_INDEX] = true;
							assignAttributes(startIndex, endIndex, indices, radix, leadingZeroStartIndex);
						} else {
							//Note: we cannot do max value check on ipv4 until after all segments have been read due to inet_aton joined segments, 
							//although we can do a preliminary check here that is in fact needed to prevent overflow when calculating values later
							if(digitCount > maxChars + leadingZeroCount) { 
								throw new IPAddressStringException(str, "ipaddress.error.ipv4.segment.too.long");
							}
							isJustZero = false;
							isSingleWildcard = singleWildcardCount > 0;
							if(isIPv4Hex) {
								if(!ipv4Options.inet_aton_hex) {
									throw new IPAddressStringException(str, "ipaddress.error.ipv4.segment.hex");
								}
								radix = 16;
								if(isSingleWildcard) {
									if(rangeWildcardIndex >= 0) {
										throw new IPAddressStringException(str, index, true);
									}
									parseSingleWildcard16(str, startIndex, endIndex, singleWildcardCount, indices, vals, flags, leadingZeroStartIndex, ipv4Options);
								} else {
									value = parseLong16(str, startIndex, endIndex);
								}
							} else {
								boolean isOctal = leadingZeroCount > 0 && ipv4Options.inet_aton_octal;
								if(isOctal) {
									if(notOctal) {
										throw new IPAddressStringException(str, "ipaddress.error.ipv4.invalid.octal.digit");
									}
									radix = 8;
									if(isSingleWildcard) {
										if(rangeWildcardIndex >= 0) {
											throw new IPAddressStringException(str, index, true);
										}
										parseSingleWildcard8(str, startIndex, endIndex, singleWildcardCount, indices, vals, flags, leadingZeroStartIndex, ipv4Options);
									} else {
										value = parseLong8(str, startIndex, endIndex);
									}
								} else {
									if(notDecimal) {
										throw new IPAddressStringException(str, "ipaddress.error.ipv4.invalid.decimal.digit");
									}
									radix = 10;
									if(isSingleWildcard) {
										if(rangeWildcardIndex >= 0) {
											throw new IPAddressStringException(str, index, true);
										}
										parseSingleWildcard10(str, startIndex, endIndex, singleWildcardCount, indices, vals, flags, leadingZeroStartIndex, ipv4Options);
									} else {
										value = parseLong10(str, startIndex, endIndex);
										isStandard = true;
									}
								}
							}
						}
						if(rangeWildcardIndex >= 0) {
							if(!ipv4Options.rangeOptions.allowsRangeSeparator()) {
								throw new IPAddressStringException(str, "ipaddress.error.no.range");
							} else if(!ipv4Options.allowLeadingZeros && frontLeadingZeroCount > 0) {
								throw new IPAddressStringException(str, "ipaddress.error.ipv4.segment.leading.zeros");
							} else if(frontDigitCount > maxChars + frontLeadingZeroCount) { 
								throw new IPAddressStringException(str, "ipaddress.error.ipv4.segment.too.long");
							}
							
							int frontRadix;
							long front;
							int frontStartIndex = rangeWildcardIndex - frontDigitCount, frontEndIndex = rangeWildcardIndex;
							int frontLeadingZeroStartIndex = frontStartIndex - frontLeadingZeroCount;
							if(frontIsIPv4Hex) {
								if(!ipv4Options.inet_aton_hex) {
									throw new IPAddressStringException(str, "ipaddress.error.ipv4.segment.hex");
								}
								front = parseLong16(str, frontStartIndex, frontEndIndex);
								frontRadix = 16;
							} else { 
								boolean frontIsOctal = frontLeadingZeroCount > 0 && !frontIsIPv4Hex && ipv4Options.inet_aton_octal;
								if(frontIsOctal) {
									if(frontNotOctal) {
										throw new IPAddressStringException(str, "ipaddress.error.ipv4.invalid.octal.digit");
									}
									front = parseLong8(str, frontStartIndex, frontEndIndex);
									frontRadix = 8;
								} else {
									if(frontNotDecimal) {
										throw new IPAddressStringException(str, "ipaddress.error.ipv4.invalid.decimal.digit");
									}
									if(frontLeadingZeroCount == 0) {
										flags[ParseData.STANDARD_STR_INDEX] = true; 
										if(isStandard && leadingZeroCount == 0) {
											flags[ParseData.STANDARD_RANGE_STR_INDEX] = true;
										}
									}
									front = parseLong10(str, frontStartIndex, frontEndIndex);
									frontRadix = 10;
								}
							}
							if(front > value) {
								throw new IPAddressStringException(str, "ipaddress.error.invalidRange");
							} //else we would have to flip the values and the indices and we would not set or flags[ParseData.STANDARD_RANGE_STR_INDEX]
							if(!isJustZero) {
								assignAttributes(frontStartIndex, frontEndIndex, startIndex, endIndex, indices, frontLeadingZeroStartIndex, leadingZeroStartIndex, frontRadix, radix);
								vals[ParseData.LOWER_INDEX] = front;
								vals[ParseData.UPPER_INDEX] = value;
							}
							frontDigitCount = frontLeadingZeroCount = 0;
							frontNotOctal = frontNotDecimal = frontUppercase = frontIsIPv4Hex = false;
						} else if(!isSingleWildcard && !isJustZero) {
							if(isStandard) {
								flags[ParseData.STANDARD_STR_INDEX] = true; 
							}
							assignAttributes(startIndex, endIndex, indices, radix, leadingZeroStartIndex);
							vals[ParseData.LOWER_INDEX] = vals[ParseData.UPPER_INDEX] = value;
						}	
					}
					parseData.segmentCount++;
					lastSeparatorIndex = index;
					digitCount = singleWildcardCount = wildcardCount = leadingZeroCount = 0;
					rangeWildcardIndex = -1;
					notOctal = notDecimal = uppercase = isIPv4Hex = false;
					++index;
				}
			} else if(currentChar == IPv6Address.SEGMENT_SEPARATOR) {
				//end of an ipv6 segment
				if(parseData.ipVersion != null && parseData.ipVersion.isIPv4()) {
					throw new IPAddressStringException(str, "ipaddress.error.ipv6.separator");
				}
				if(isIPv4Hex) {
					throw new IPAddressStringException(str,"ipaddress.error.ipv6.character");
				}
				parseData.ipVersion = IPVersion.IPV6;
				int segCount = parseData.segmentCount;
				if(segCount == 0) {
					parseData.initSegmentData(IPv6Address.SEGMENT_COUNT);
				} else if(segCount >= IPv6Address.SEGMENT_COUNT) {
					throw new IPAddressStringException(str, "ipaddress.error.ipv6.too.many.segments");
				}
				long vals[] = parseData.values[segCount];
				boolean flags[] = parseData.flags[segCount];
				int indices[] = parseData.indices[segCount];
				if(wildcardCount > 0) {
					if(!ipv6Options.rangeOptions.allowsWildcard()) {
						throw new IPAddressStringException(str, "ipaddress.error.no.wildcard");
					}
					if(singleWildcardCount > 0 || rangeWildcardIndex >= 0 || leadingZeroCount > 0 || digitCount > 0) {//wildcards must appear alone
						throw new IPAddressStringException(str, index, true);
					}
					parseData.anyWildcard = true;
					flags[ParseData.WILDCARD_INDEX] = true;
					vals[ParseData.UPPER_INDEX] = IPv6Address.MAX_VALUE_PER_SEGMENT;
					int startIndex = index - wildcardCount;
					assignAttributes(startIndex, index, indices, startIndex);
					parseData.segmentCount++;
				} else {
					if(index == strStartIndex) {
						if(index + 1 == strEndIndex) {
							throw new IPAddressStringException(str, "ipaddress.error.ipv6.too.few.segments");
						}
						if(str.charAt(index + 1) != IPv6Address.SEGMENT_SEPARATOR) {
							throw new IPAddressStringException(str, "ipaddress.error.ipv6.cannot.start.with.single.separator");
						}
						//no segment, so we do not increment segmentCount
					} else if(index == lastSeparatorIndex + 1) {
						if(parseData.consecutiveIPv6SepIndex >= 0) {
							throw new IPAddressStringException(str, "ipaddress.error.ipv6.ambiguous");
						}
						parseData.consecutiveIPv6SepIndex = index - 1;
						assignAttributes(index, index, indices, index);
						parseData.segmentCount++;
					} else {
						if(!ipv6Options.allowLeadingZeros && leadingZeroCount > 0) {
							throw new IPAddressStringException(str, "ipaddress.error.ipv6.segment.leading.zeros");
						}
						if(digitCount > IPv6AddressSegment.MAX_CHARS) {
							throw new IPAddressStringException(str, "ipaddress.error.ipv6.segment.too.long");
						}
						long value = 0;
						boolean isStandard = false;
						int startIndex = index - digitCount;
						int leadingZeroStartIndex = startIndex - leadingZeroCount;
						int endIndex = index;
						if(!ipv6Options.allowUnlimitedLeadingZeros && endIndex - leadingZeroStartIndex > IPv6AddressSegment.MAX_CHARS) {
							throw new IPAddressStringException(str, "ipaddress.error.ipv6.segment.too.long");
						}
						boolean isJustZero = false;
						if(digitCount == 0) {
							//note we know there is a zero as we have already checked for empty segments so we know leadingZeroCount is non-zero when digitCount is zero
							startIndex--;
							digitCount++;
							leadingZeroCount--;
							isJustZero = true;
							flags[ParseData.STANDARD_STR_INDEX] = true; 
							assignAttributes(startIndex, endIndex, indices, leadingZeroStartIndex);
						} else if(digitCount > IPv6AddressSegment.MAX_CHARS) {
							throw new IPAddressStringException(str, "ipaddress.error.ipv6.segment.too.long");
						} else if(singleWildcardCount > 0) {
							if(rangeWildcardIndex >= 0) {
								throw new IPAddressStringException(str, index, true);
							}
							parseSingleWildcard16(str, startIndex, endIndex, singleWildcardCount, indices, vals, flags, leadingZeroStartIndex, ipv6Options);
						} else {
							value = parseLong16(str, startIndex, endIndex);
							isStandard = !uppercase;
						} //else we need do nothing as we know digitCount == 0 means we have only 0 characters
						if(rangeWildcardIndex >= 0) {
							if(!ipv6Options.rangeOptions.allowsRangeSeparator()) {
								throw new IPAddressStringException(str, "ipaddress.error.no.range");
							} else if(frontIsIPv4Hex) {
								throw new IPAddressStringException(str, index, false);
							} else if(!ipv6Options.allowLeadingZeros && frontLeadingZeroCount > 0) {
								throw new IPAddressStringException(str, "ipaddress.error.ipv6.segment.leading.zeros");
							} else if(frontDigitCount > IPv6AddressSegment.MAX_CHARS) {
								throw new IPAddressStringException(str, "ipaddress.error.ipv6.segment.too.long");
							}
							int frontStartIndex = rangeWildcardIndex - frontDigitCount, frontEndIndex = rangeWildcardIndex;
							int frontLeadingZeroStartIndex = frontStartIndex - frontLeadingZeroCount;
							if(!ipv6Options.allowUnlimitedLeadingZeros && frontEndIndex - frontLeadingZeroStartIndex > IPv6AddressSegment.MAX_CHARS) {
								throw new IPAddressStringException(str, "ipaddress.error.ipv6.segment.too.long");
							}
							long front = parseLong16(str, frontStartIndex, frontEndIndex);
							if(front > value) {
								throw new IPAddressStringException(str, "ipaddress.error.invalidRange");
							} //else we would have to flip the values and the indices and we would not set or flags[ParseData.STANDARD_RANGE_STR_INDEX]
							if(!isJustZero) {
								if(frontLeadingZeroCount == 0 && !frontUppercase) {
									flags[ParseData.STANDARD_STR_INDEX] = true;
									if(isStandard && leadingZeroCount == 0) {
										flags[ParseData.STANDARD_RANGE_STR_INDEX] = true;
									}
								}
								assignAttributes(frontStartIndex, frontEndIndex, startIndex, endIndex, indices, frontLeadingZeroStartIndex, leadingZeroStartIndex, IPv6Address.DEFAULT_TEXTUAL_RADIX, IPv6Address.DEFAULT_TEXTUAL_RADIX);
								vals[ParseData.LOWER_INDEX] = front;
								vals[ParseData.UPPER_INDEX] = value;
							}
							frontDigitCount = frontLeadingZeroCount = 0;
							frontNotOctal = frontNotDecimal = frontUppercase = frontIsIPv4Hex = false;
						} else if(singleWildcardCount == 0 && !isJustZero) {
							if(isStandard) {
								flags[ParseData.STANDARD_STR_INDEX] = true;
							}
							assignAttributes(startIndex, endIndex, indices, IPv6Address.DEFAULT_TEXTUAL_RADIX, leadingZeroStartIndex);
							vals[ParseData.LOWER_INDEX] = vals[ParseData.UPPER_INDEX] = value;
						}
						parseData.segmentCount++;
					}
				}
				lastSeparatorIndex = index;
				rangeWildcardIndex = -1;
				digitCount = singleWildcardCount = wildcardCount = leadingZeroCount = 0;
				notOctal = notDecimal = uppercase = isIPv4Hex = false;
				++index;
			} else if(currentChar >= 'A' && currentChar <= 'F') {
				++digitCount;
				++index;
				notOctal = notDecimal = uppercase = true;
			} else if(currentChar == IPAddress.PREFIX_LEN_SEPARATOR) {
				parseData.isPrefixed = true;
				strEndIndex = index;
				parseData.qualifierIndex = index + 1;
			} else {
				boolean b = false;
				if(currentChar == IPAddress.SEGMENT_WILDCARD || (b = (currentChar == IPAddress.SEGMENT_SQL_WILDCARD))) {
					if(b && ipv6Options.allowZone) { //the zone character % is also the SQL wildcard, we so cannot support both at the same time
						parseData.isZoned = true;
						strEndIndex = index;
						parseData.qualifierIndex = index + 1;
					} else {
						++wildcardCount;
						++index;
					}
				} else if(currentChar == IPAddress.RANGE_SEPARATOR) {
					if(rangeWildcardIndex >= 0) {
						throw new IPAddressStringException(str, index, true);
					}
					rangeWildcardIndex = index;
					frontDigitCount = digitCount;
					frontLeadingZeroCount = leadingZeroCount;
					if(frontDigitCount == 0) {
						if(frontLeadingZeroCount == 0) {
							throw new IPAddressStringException(str, "ipaddress.error.empty.start.of.range");
						}
						frontDigitCount++;
						frontLeadingZeroCount--;
					}
					frontNotOctal = notOctal;
					frontNotDecimal = notDecimal;
					frontUppercase = uppercase;
					frontIsIPv4Hex = isIPv4Hex;	
					leadingZeroCount = digitCount = 0;
					notOctal = notDecimal = uppercase = isIPv4Hex = false;
					++index;
				} else if(currentChar == IPAddress.SEGMENT_SQL_SINGLE_WILDCARD) {
					++digitCount;
					++index;
					++singleWildcardCount;
				} else if(currentChar == 'x') {
					if(digitCount > 0 || leadingZeroCount != 1 || isIPv4Hex || singleWildcardCount > 0) {
						throw new IPAddressStringException(str, index, true);
					}
					isIPv4Hex = true;
					leadingZeroCount = 0;
					++index;
				} else {
					//invalid char
					throw new IPAddressStringException(str, index, false);
				}
			}
		}
		return parseData;
	}
	
	private static AddressProvider createProvider(
			final HostName fromHost,
			final IPAddressString fromString,
			final String fullAddr,
			final IPAddressStringParameters validationOptions,
			final ParseData parseData,
			final ParsedAddressQualifier qualifier) throws IPAddressStringException {
		if(parseData.ipVersion == null) {
			IPVersion version = qualifier.inferVersion(validationOptions);
			if(parseData.isEmpty) {
				if(qualifier.getNetworkPrefixLength() != null) {
					if(validationOptions.allowPrefixOnly) {
						return new MaskCreator(qualifier, version);
					}
					throw new IPAddressStringException(fullAddr, "ipaddress.error.prefix.only");
				} else {
					if(!validationOptions.allowEmpty) {
						throw new IPAddressStringException(fullAddr, "ipaddress.error.empty");
					}
					if(validationOptions.emptyIsLoopback) {
						return AddressProvider.LOOPBACK_CREATOR;
					}
					return AddressProvider.EMPTY_PROVIDER;
				}
			} else { //isAll
				if(validationOptions.allowAll) {
					if(qualifier == NO_QUALIFIER && version == null) {
						return AddressProvider.ALL_ADDRESSES_CREATOR;
					}
					return new AllCreator(qualifier, version, fromHost, fromString);
				}
				throw new IPAddressStringException(fullAddr, "ipaddress.error.all");
			}
		} else {
			ParsedAddress valueCreator = createAddressProvider(fromHost, fromString, fullAddr, validationOptions, parseData, qualifier);
			return new ParsedAddressProvider(valueCreator);
		}
	}

	private static ParsedAddress createAddressProvider(
			final HostName fromHost,
			final IPAddressString fromString,
			final String fullAddr,
			final IPAddressStringParameters validationOptions,
			final ParseData parseData,
			final ParsedAddressQualifier qualifier) throws IPAddressStringException {
		final int segCount = parseData.segmentCount;
		IPVersion version = parseData.ipVersion;
		if(version.isIPv4()) {
			int missingCount = IPv4Address.SEGMENT_COUNT - segCount;
			final IPv4AddressStringParameters ipv4Options = validationOptions.getIPv4Parameters();
			if(missingCount > 0 && !parseData.anyWildcard && !ipv4Options.inet_aton_joinedSegments) {
				throw new IPAddressStringException(fullAddr, "ipaddress.error.ipv4.too.few.segments");
			}
			//here we check whether values are too large or strings too long
			long oneSegmentMax = getMaxIPv4Value(0);
			for(int i = 0; i < segCount; i++) {
				long max;
				if(i == segCount - 1 && missingCount > 0) {
					max = getMaxIPv4Value(missingCount);
				} else {
					max = oneSegmentMax;
				}
				boolean flags[] = parseData.flags[i];
				long values[] = parseData.values[i];
				int indices[] = parseData.indices[i];
				int lowerRadix = indices[ParseData.LOWER_RADIX_INDEX];
				int maxDigits = getMaxIPv4StringLength(missingCount, lowerRadix);
				if(flags[ParseData.SINGLE_WILDCARD_INDEX]) {
					if(values[ParseData.LOWER_INDEX] > max) {
						throw new IPAddressStringException(fullAddr, "ipaddress.error.ipv4.segment.too.large");
					}
					if(values[ParseData.UPPER_INDEX] > max) {
						values[ParseData.UPPER_INDEX] = max;
					}
					if(!ipv4Options.allowUnlimitedLeadingZeros) {
						if(indices[ParseData.LOWER_STR_END_INDEX] - indices[ParseData.LOWER_STR_DIGITS_INDEX] -  getStringPrefixCharCount(lowerRadix) > maxDigits) {
							throw new IPAddressStringException(fullAddr, "ipaddress.error.ipv4.segment.too.long");
						}
					}
				} else {
					if(values[ParseData.UPPER_INDEX] > max) {
						throw new IPAddressStringException(fullAddr, "ipaddress.error.ipv4.segment.too.large");
					}
					int upperRadix = indices[ParseData.UPPER_RADIX_INDEX];
					int maxUpperDigits = getMaxIPv4StringLength(missingCount, upperRadix);
					if(!ipv4Options.allowUnlimitedLeadingZeros) {
						if(indices[ParseData.LOWER_STR_END_INDEX] - indices[ParseData.LOWER_STR_DIGITS_INDEX] - getStringPrefixCharCount(lowerRadix) > maxDigits) {
							throw new IPAddressStringException(fullAddr, "ipaddress.error.ipv4.segment.too.long");
						}
						if(indices[ParseData.UPPER_STR_END_INDEX] - indices[ParseData.UPPER_STR_DIGITS_INDEX] - getStringPrefixCharCount(upperRadix) > maxUpperDigits) {
							throw new IPAddressStringException(fullAddr, "ipaddress.error.ipv4.segment.too.long");
						}
					}
				}
			}
		} else {
			int totalSegmentCount = segCount;
			if(parseData.mixedParsedAddress != null) {
				totalSegmentCount += IPv6Address.MIXED_REPLACED_SEGMENT_COUNT;
			}
			if(totalSegmentCount < IPv6Address.SEGMENT_COUNT && !parseData.anyWildcard && !parseData.isCompressed()) {
				throw new IPAddressStringException(fullAddr, "ipaddress.error.ipv6.too.few.segments");
			}
		}
		ParsedAddress valueCreator = new ParsedAddress(fromHost, fromString, fullAddr, parseData, version, qualifier);
		return valueCreator;
	}
	
	static int validatePrefixImpl(CharSequence fullAddr, IPVersion version) throws IPAddressStringException {
		ParsedAddressQualifier qualifier = validatePrefix(fullAddr, DEFAULT_PREFIX_OPTIONS, 0, fullAddr.length(), version);
		if(qualifier == null) {
			throw new IPAddressStringException(fullAddr.toString(), "ipaddress.error.invalidCIDRPrefix");
		}
		return qualifier.getNetworkPrefixLength();
	}

	private static ParsedAddressQualifier validatePrefix(
			final CharSequence fullAddr,
			final IPAddressStringParameters validationOptions,
			final int index,
			final int endIndex,
			final IPVersion ipVersion) throws IPAddressStringException {
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
						throw new IPAddressStringException(fullAddr.toString(), "ipaddress.error.ipv4.prefix.leading.zeros");
					}
				} else {
					if(!validationOptions.getIPv6Parameters().allowPrefixLengthLeadingZeros) {
						throw new IPAddressStringException(fullAddr.toString(), "ipaddress.error.ipv6.prefix.leading.zeros");
					}
				}
			}
			boolean allowPrefixesBeyondAddressSize = (asIPv4 ? validationOptions.getIPv4Parameters() : validationOptions.getIPv6Parameters()).allowPrefixesBeyondAddressSize;
			//before we attempt to parse, ensure the string is a reasonable size
			if(!allowPrefixesBeyondAddressSize && digitCount > (asIPv4 ? 2 : 3)) {
				if(asIPv4 && validationOptions.getIPv4Parameters().inet_aton_joinedSegments && validationOptions.getIPv4Parameters().inet_aton_single_segment_mask) {
					return null; //treat it as single segment ipv4
				}
				throw new IPAddressStringException(fullAddr.toString(), "ipaddress.error.prefixSize");
			}
			int result = parse10(fullAddr, index, endIndex);
			if(!allowPrefixesBeyondAddressSize && result > (asIPv4 ? IPv4Address.BIT_COUNT : IPv6Address.BIT_COUNT)) {
				if(asIPv4 && validationOptions.getIPv4Parameters().inet_aton_joinedSegments && validationOptions.getIPv4Parameters().inet_aton_single_segment_mask) {
					return null; //treat it as a single segment ipv4 mask
				}
				throw new IPAddressStringException(fullAddr.toString(), "ipaddress.error.prefixSize");
			}
			if(result < PREFIX_CACHE.length) {
				ParsedAddressQualifier qual = PREFIX_CACHE[result];
				if(qual == null) {
					qual = PREFIX_CACHE[result] = new ParsedAddressQualifier(result);
				}
				return qual;
			}
			return new ParsedAddressQualifier(result);
		}
		return null;
	}
	
	private static ParsedAddressQualifier parseQualifier(
			final String fullAddr,
			final IPAddressStringParameters validationOptions,
			final boolean isPrefixed,
			final boolean isZoned,
			final boolean addressIsEmpty,
			final int index,
			final int endIndex,
			final IPVersion ipVersion) throws IPAddressStringException {
		if(isPrefixed) {
			if(validationOptions.allowPrefix) {
				ParsedAddressQualifier qualifier = validatePrefix(fullAddr, validationOptions, index, fullAddr.length(), ipVersion);
				if(qualifier != null) {
					return qualifier;
				}
			}
			if(addressIsEmpty) {
				//PREFIX_ONLY must have a prefix and not a mask - we don't allow /255.255.0.0
				throw new IPAddressStringException(fullAddr, "ipaddress.error.invalidCIDRPrefix");
			}
			if(validationOptions.allowMask) {
				try {
					//check for a mask
					//check if we need a new validation options for the mask
					IPAddressStringParameters maskOptions = toMaskOptions(validationOptions, ipVersion);
					ParseData maskParseData = validateAddress(maskOptions, fullAddr, index, endIndex);
					
					if(maskParseData.isEmpty || maskParseData.isAll) {
						throw new IPAddressStringException(fullAddr, "ipaddress.error.invalidCIDRPrefixOrMask");
					}
					ParsedAddress maskAddress = createAddressProvider(null, null, fullAddr, maskOptions, maskParseData, NO_QUALIFIER);
					if(maskParseData.addressEndIndex != fullAddr.length()) { // 1.2.3.4/ or 1.2.3.4// or 1.2.3.4/%
						throw new IPAddressStringException(fullAddr, "ipaddress.error.invalidCIDRPrefixOrMask");
					}
					IPVersion maskVersion = maskParseData.ipVersion;
					if(maskVersion.isIPv4() && maskParseData.segmentCount == 1 && !maskParseData.anyWildcard && !validationOptions.getIPv4Parameters().inet_aton_single_segment_mask) {//1.2.3.4/33 where 33 is an aton_inet single segment address and not a prefix length
						throw new IPAddressStringException(fullAddr, "ipaddress.error.mask.single.segment");
					}
					if(ipVersion != null && (maskVersion.isIPv4() != ipVersion.isIPv4() || maskVersion.isIPv6() != ipVersion.isIPv6())) {
						//note that this also covers the cases of non-standard addresses in the mask, ie mask neither ipv4 or ipv6
						throw new IPAddressStringException(fullAddr, "ipaddress.error.ipMismatch");
					}
					return new ParsedAddressQualifier(maskAddress);
				} catch(IPAddressStringException e) {
					throw new IPAddressStringException(fullAddr, "ipaddress.error.invalidCIDRPrefixOrMask", e);
				}
			}
			throw new IPAddressStringException(fullAddr, "ipaddress.error.CIDRNotAllowed");
		} else if(isZoned) {
			if(addressIsEmpty) {
				throw new IPAddressStringException(fullAddr, "ipaddress.error.only.zone");
			}
			String zone = fullAddr.substring(index, endIndex);
			return new ParsedAddressQualifier(zone);
		} else {
			return NO_QUALIFIER;
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
		indices[ParseData.LOWER_STR_DIGITS_INDEX] = frontLeadingZeroStartIndex;
		indices[ParseData.LOWER_STR_START_INDEX] = frontStart;
		indices[ParseData.LOWER_STR_END_INDEX] = frontEnd;
		indices[ParseData.UPPER_STR_DIGITS_INDEX] = leadingZeroStartIndex;
		indices[ParseData.UPPER_STR_START_INDEX] = start;
		indices[ParseData.UPPER_STR_END_INDEX] = end;
	}
	
	private static void assignAttributes(int frontStart, int frontEnd, int start, int end, int indices[], int frontLeadingZeroStartIndex, int leadingZeroStartIndex, int frontRadix, int radix) {
		indices[ParseData.LOWER_RADIX_INDEX] = frontRadix;
		indices[ParseData.UPPER_RADIX_INDEX] = radix;
		assignAttributes(frontStart, frontEnd, start, end, indices, frontLeadingZeroStartIndex, leadingZeroStartIndex);
	}
	
	private static void assignAttributes(int start, int end, int indices[], int leadingZeroStartIndex) {
		indices[ParseData.UPPER_STR_DIGITS_INDEX] = indices[ParseData.LOWER_STR_DIGITS_INDEX] = leadingZeroStartIndex;
		indices[ParseData.UPPER_STR_START_INDEX] = indices[ParseData.LOWER_STR_START_INDEX] = start;
		indices[ParseData.UPPER_STR_END_INDEX] = indices[ParseData.LOWER_STR_END_INDEX] = end;
	}
	
	private static void assignAttributes(int start, int end, int indices[], int radix, int leadingZeroStartIndex) {
		indices[ParseData.UPPER_RADIX_INDEX] = indices[ParseData.LOWER_RADIX_INDEX] = radix;
		assignAttributes(start, end, indices, leadingZeroStartIndex);
	}
	
	private static void assignSingleWildcardAttributes(String str, int start, int end, int digitsEnd, int numSingleWildcards, int indices[],  boolean flags[], int radix, int leadingZeroStartIndex, IPVersionAddressStringParameters options) throws IPAddressStringException {
		if(!options.rangeOptions.allowsSingleWildcard()) {
			throw new IPAddressStringException(str, "ipaddress.error.no.single.wildcard");
		}
		for(int k = digitsEnd; k < end; k++) {
			if(str.charAt(k) != IPAddress.SEGMENT_SQL_SINGLE_WILDCARD) {
				throw new IPAddressStringException(str, "ipaddress.error.single.wildcard.order");
			}
		}
		flags[ParseData.SINGLE_WILDCARD_INDEX] = true;
		assignAttributes(start, end, indices, radix, leadingZeroStartIndex);
	}
	
	private static void parseSingleWildcard10(String s, int start, int end, int numSingleWildcards, int indices[], long vals[],  boolean flags[], int leadingZeroStartIndex, IPVersionAddressStringParameters options) throws IPAddressStringException {
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
		vals[ParseData.LOWER_INDEX] = lower;
		vals[ParseData.UPPER_INDEX] = upper;
	}
	
	private static void parseSingleWildcard8(String s, int start, int end, int numSingleWildcards, int indices[], long vals[],  boolean flags[], int leadingZeroStartIndex, IPVersionAddressStringParameters options) throws IPAddressStringException {
		int digitsEnd = end - numSingleWildcards;
		assignSingleWildcardAttributes(s, start, end, digitsEnd, numSingleWildcards, indices, flags, 8, leadingZeroStartIndex, options);
		long lower;
		if(start < digitsEnd) {
			lower = parseLong8(s, start, digitsEnd);
		} else {
			lower = 0;
		}
		long upper;
		switch(numSingleWildcards) {
			case 1:
				lower <<= 3;
				upper = lower + 07;
				break;
			case 2:
				lower <<= 6;
				upper = lower + 077;
				break;
			case 3:
				lower <<= 9;
				upper = lower + 0777;
				break;
			default:
				long power = (long) Math.pow(8, numSingleWildcards);
				lower *= power;
				upper = lower + ((power * 8) - 1);
		}
		vals[ParseData.LOWER_INDEX] = lower;
		vals[ParseData.UPPER_INDEX] = upper;
	}
	
	private static void parseSingleWildcard16(String s, int start, int end, int numSingleWildcards, int indices[], long vals[],  boolean flags[], int leadingZeroStartIndex, IPVersionAddressStringParameters options) throws IPAddressStringException {
		int digitsEnd = end - numSingleWildcards;
		assignSingleWildcardAttributes(s, start, end, digitsEnd, numSingleWildcards, indices, flags, 16, leadingZeroStartIndex, options);
		long lower;
		if(start < digitsEnd) {
			lower = parseLong16(s, start, digitsEnd);
		} else {
			lower = 0;
		}
		long upper;
		switch(numSingleWildcards) {
			case 1:
				lower <<= 4;
				upper = lower + 0xf;
				break;
			case 2:
				lower <<= 8;
				upper = lower + 0xff;
				break;
			case 3:
				lower <<= 12;
				upper = lower + 0xfff;
				break;
			case 4:
				lower <<= 16;
				upper = lower + 0xffff;
				break;
			default:
				long power = (long) Math.pow(16, numSingleWildcards);
				lower *= power;
				upper = lower + power - 1;
		}
		vals[ParseData.LOWER_INDEX] = lower;
		vals[ParseData.UPPER_INDEX] = upper;
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
			result = (result << 3) + charArray[s.charAt(start)];
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
			result = (result << 3) + charArray[s.charAt(start)];
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
			result = (result << 4) + charArray[s.charAt(start)];
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
			result = (result << 4) + charArray[s.charAt(start)];
		}
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
		int index, lastSeparatorIndex, labelCount = 0;
		boolean segmentUppercase = false, isNotNormalized = false, squareBracketed = false,
				isAllDigits = true, isPossiblyIPv6 = true, isPossiblyIPv4 = true, tryIPv6 = false, tryIPv4 = false, isPrefixed = false, addressIsEmpty = false;
		index = lastSeparatorIndex = -1;
		int maxLocalLabels = 6;//should be at least 4 to avoid the array for ipv4 addresses
		int separatorIndices[] = null;
		boolean normalizedFlags[] = null;
		int sep0, sep1, sep2, sep3, sep4, sep5;
		sep0 = sep1 = sep2 = sep3 = sep4 = sep5 = -1;
		boolean upper0, upper1, upper2, upper3, upper4, upper5;
		upper0 = upper1 = upper2 = upper3 = upper4 = upper5 = false;
		int qualifierIndex = -1;
		while(++index <= addrLen) {
			char currentChar;
			//grab the character to evaluate
			if(index == addrLen) {
				if(index == 0) {
					addressIsEmpty = true;
					break;
				}
				boolean segmentCountMatches = (labelCount + 1 == IPv4Address.SEGMENT_COUNT) ||
						(labelCount + 1 < IPv4Address.SEGMENT_COUNT && validationOptions.addressOptions.getIPv4Parameters().inet_aton_joinedSegments);
				if(isAllDigits) {
					if(segmentCountMatches) {
						tryIPv4 = true;
						break;
					}
					throw new HostNameException(str, "ipaddress.host.error.invalid");
				}
				isPossiblyIPv4 &= segmentCountMatches;
				currentChar = HostName.LABEL_SEPARATOR;
			} else {
				currentChar = str.charAt(index);
			}
			
			//check that character
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
					throw new HostNameException(str, "ipaddress.host.error.segment.too.long");
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
				segmentUppercase = false;
			} else if(currentChar == '_') {//this is not supported in host names but is supported in domain names, see discussion in Host class
				isAllDigits = false;
			} else if(currentChar == '-') {
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
							break;
						}
					} else {
						if(isPossiblyIPv4 && labelCount < IPv4Address.SEGMENT_COUNT && addressOptions.getIPv4Parameters().rangeOptions.allowsWildcard()) {
							tryIPv4 = true;
							break;
						} else if(isPossiblyIPv6 && 
								labelCount < IPv6Address.SEGMENT_COUNT && 
								addressOptions.getIPv6Parameters().rangeOptions.allowsWildcard()) {
							tryIPv6 = true;
							break;
						}
					}
					throw new HostNameException(str, index);
				} else if(currentChar == IPv6Address.SEGMENT_SEPARATOR && 
						labelCount < IPv6Address.SEGMENT_COUNT) {
					if(isPossiblyIPv6) {
						tryIPv6 = true;
						break;
					}
					throw new HostNameException(str, index);
				} else {
					throw new HostNameException(str, index);
				}
			}
		}

		//1. squareBracketed: [ addr ] 
		//2. tryIPv4 || tryIPv6: this is a string with characters that invalidate it as a host but it still may in fact be an address
		//	This includes ipv6 strings (as dictated by the presence of a ':'), ipv4/ipv6 strings with '*', or all dot/digit strings like 1.2.3.4 that are 4 segments
		//3. isPossiblyIPv4: this is a string with digits, - and _ characters and the number of separators matches ipv4.  Such strings can also be valid hosts.  It also includes "" empty addresses.
		//	If it parses as an address, we do not treat as host.  The range options flag (controlling whether we allow '-' or '_' in addresses) for ipv4 can control whether it is treated as host or address.
		
		try {
			boolean isIPAddress  = squareBracketed || tryIPv4 || tryIPv6;
			if(!validationOptions.allowIPAddress) {
				if(isIPAddress) {
					throw new HostNameException(str, "ipaddress.host.error.ipaddress");
				}
			} else if(isIPAddress || isPossiblyIPv4) {
				try {
					ParseData addressData;
					ParsedAddressQualifier qualifier;
					IPAddressStringParameters addressOptions = validationOptions.addressOptions;
					if(squareBracketed) {
						//Note: 
						//Firstly, we need to find the address end which is denoted by the end bracket
						//Secondly, while zones appear inside bracket, prefix appears outside, according to rfc 4038
						//So we keep track of the boolean endsWithBracket to indicate prefix appearing outside of the bracket
						int endIndex = addrLen - 1;
						boolean endsWithPrefix = str.charAt(endIndex) != HostName.IPV6_END_BRACKET;
						if(endsWithPrefix) {
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
						}
						addressData = validateAddress(addressOptions, str, startIndex, endIndex);
						if(endsWithPrefix) {
							if(addressData.addressEndIndex != endIndex || addressData.isZoned) {
								throw new HostNameException(str, "ipaddress.error.zoneAndCIDRPrefix");
							}
							int prefixIndex = endIndex + 1;
							if(str.charAt(prefixIndex)  != IPAddress.PREFIX_LEN_SEPARATOR) {
								throw new HostNameException(str, prefixIndex);
							}
							qualifierIndex = prefixIndex + 1;//skip the ']/'
							endIndex = addrLen;
							isPrefixed = true;
						} else {
							qualifierIndex = addressData.qualifierIndex;
							isPrefixed = addressData.isPrefixed;
							if(addressData.isZoned && str.charAt(addressData.qualifierIndex) == '2' && str.charAt(addressData.qualifierIndex + 1) == '5') {
								//handle %25 from rfc 6874
								qualifierIndex += 2;
							}
						}
						//SMTP rfc 2821 allows [ipv4address]
						IPVersion version = addressData.ipVersion;
						if(version != IPVersion.IPV6 && !validationOptions.allowBracketedIPv4) {
							throw new HostNameException(str, "ipaddress.host.error.bracketed.not.ipv6");
						}
						qualifier = parseQualifier(str, validationOptions.addressOptions, isPrefixed, addressData.isZoned, addressData.isEmpty, qualifierIndex, endIndex, version);
					} else {
						int endIndex = str.length();
						addressData = validateAddress(addressOptions, str, 0, endIndex);
						qualifier = parseQualifier(str, addressOptions, addressData.isPrefixed, addressData.isZoned, addressData.isEmpty, addressData.qualifierIndex, endIndex, addressData.ipVersion);
					}
					AddressProvider provider = createProvider(fromHost, null, str, addressOptions, addressData, qualifier);
					return new ParsedHost(str, provider);
				} catch(IPAddressStringException e) {
					if(isIPAddress) {
						throw e;
					} //else fall though and evaluate as a host
				}
			}
			
			
			ParsedAddressQualifier qualifier = parseQualifier(str, validationOptions.addressOptions, isPrefixed, false, addressIsEmpty, qualifierIndex, str.length(), null);
			ParsedHost parsedHost;
			if(addressIsEmpty) {
				if(!validationOptions.allowEmpty) {
					throw new HostNameException(str, "ipaddress.host.error.empty");
				}
				if(qualifier == NO_QUALIFIER) {
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
				parsedHost = new ParsedHost(str, separatorIndices, normalizedFlags, qualifier);
				if(!isNotNormalized) {
					parsedHost.host = str;
				}
			}
			return parsedHost;
		} catch(IPAddressStringException e) {
			throw new HostNameException(str, e, "ipaddress.host.error.invalid");
		}
	}
}
