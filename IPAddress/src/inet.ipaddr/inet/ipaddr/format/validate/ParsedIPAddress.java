/*
 * Copyright 2018 Sean C Foley
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

import java.io.Serializable;
import java.util.Objects;

import inet.ipaddr.Address;
import inet.ipaddr.AddressNetwork.AddressSegmentCreator;
import inet.ipaddr.AddressNetwork.PrefixConfiguration;
import inet.ipaddr.HostIdentifierString;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressNetwork;
import inet.ipaddr.IPAddressSection;
import inet.ipaddr.IPAddressSegment;
import inet.ipaddr.IPAddressStringParameters;
import inet.ipaddr.IncompatibleAddressException;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv4.IPv4AddressNetwork.IPv4AddressCreator;
import inet.ipaddr.ipv4.IPv4AddressSection;
import inet.ipaddr.ipv4.IPv4AddressSegment;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.ipv6.IPv6AddressNetwork.IPv6AddressCreator;
import inet.ipaddr.ipv6.IPv6AddressSection;
import inet.ipaddr.ipv6.IPv6AddressSegment;

/**
 * The result from parsing a valid address string.  This can be converted into an {@link IPv4Address} or {@link IPv6Address} instance.
 * 
 * @author sfoley
 *
 */
public class ParsedIPAddress extends IPAddressParseData implements IPAddressProvider {

	private static final long serialVersionUID = 4L;

	static class CachedIPAddresses<T extends IPAddress> implements Serializable {
		
		private static final long serialVersionUID = 4L;
		
		//address is 1.2.0.0/16 and hostAddress is 1.2.3.4 for the string 1.2.3.4/16
		protected T address, hostAddress;
		
		CachedIPAddresses() {}

		public CachedIPAddresses(T address) {
			this(address, address);
		}
		
		public CachedIPAddresses(T address, T hostAddress) {
			this.address = address;
			this.hostAddress = hostAddress;
		}
		
		public T getAddress() {
			return address;
		}
		
		public T getHostAddress() {
			return hostAddress;
		}
	}
	
	abstract class IPAddresses<T extends IPAddress, R extends IPAddressSection> extends CachedIPAddresses<T> {

		private static final long serialVersionUID = 4L;
		
		private final R section, hostSection;

		IPAddresses(R section, R hostSection) {
			this.section = section;
			this.hostSection = hostSection;
		}

		abstract ParsedAddressCreator<T, R, ?, ?> getCreator();
		
		@Override
		public T getAddress() {
			if(address == null) {
				address = getCreator().createAddressInternal(section, getQualifier().getZone(), originator);
			}
			return address;
		}
		
		@Override
		public T getHostAddress() {
			if(hostSection == null) {
				return getAddress();
			}
			if(hostAddress == null) {
				hostAddress = getCreator().createAddressInternal(hostSection, getQualifier().getZone(), null);
			}
			return hostAddress;
		}
		
		R getSection() {
			return section;
		}
	}
	
	private final IPAddressStringParameters options;
	private final HostIdentifierString originator;
	
	private CachedIPAddresses<?> values;
	private Boolean skipContains;

	ParsedIPAddress(
			HostIdentifierString from, 
			CharSequence addressString,
			IPAddressStringParameters options) {
		super(addressString);
		this.options = options;
		this.originator = from;
	}
	
	private IPv6AddressCreator getIPv6AddressCreator() {
		return getParameters().getIPv6Parameters().getNetwork().getAddressCreator();
	}
	
	private IPv4AddressCreator getIPv4AddressCreator() {
		return getParameters().getIPv4Parameters().getNetwork().getAddressCreator();
	}
	
	@Override
	public boolean isProvidingIPAddress() {
		return true;
	}
	
	@Override
	public IPAddressProvider.IPType getType() {
		return IPType.from(getProviderIPVersion());
	}
	
	@Override
	public IPAddressStringParameters getParameters() {
		return options;
	}
	
	private CachedIPAddresses<?> getCachedAddresses()  {
		CachedIPAddresses<?> val = values;
		if(val == null) {
			synchronized(this) {
				val = values;
				if(val == null) {
					values = val = createAddresses();
					releaseSegmentData();
				}
			}
		}
		return val;
	}
	
	@Override
	public IPAddress getProviderHostAddress()  {
		return getCachedAddresses().getHostAddress();
	}
	
	@Override
	public IPAddress getProviderAddress()  {
		return getCachedAddresses().getAddress();
	}
	
	@Override
	public IPAddress getProviderAddress(IPVersion version) {
		IPVersion thisVersion = getProviderIPVersion();
		if(!version.equals(thisVersion)) {
			return null;
		}
		return getProviderAddress();
	}
	
	private boolean skipContains() {
		Boolean result = skipContains;
		if(result != null) {
			return result;
		}
		AddressParseData parseData = getAddressParseData();
		int segmentCount = parseData.getSegmentCount();
		
		// first we must excluded cases where the segments line up differently than standard, although we do not exclude ipv6 compressed
		if(isProvidingIPv4()) {
			if(segmentCount != IPv4Address.SEGMENT_COUNT) { // accounts for is_inet_aton_joined, singleSegment and wildcard segments
				skipContains = Boolean.TRUE;
				return true;
			}
		} else {
			if(isProvidingMixedIPv6() || (segmentCount != IPv6Address.SEGMENT_COUNT && !isCompressed())) { // accounts for single segment and wildcard segments
				skipContains = Boolean.TRUE;
				return true;
			}
		}
		
		// exclude non-standard masks which will modify segment values from their parsed values
		IPAddress mask = getQualifier().getMask();
		if(mask != null && mask.getBlockMaskPrefixLength(true) == null) { // handles non-standard masks
			skipContains = Boolean.TRUE;
			return true;
		}
		skipContains = Boolean.FALSE;
		return false;
	}

	@Override
	public int providerHashCode() {
		IPAddress value = getProviderAddress();
		if(value != null) {
			return value.hashCode();
		}
		return Objects.hashCode(getType());
	}

	@Override
	public Boolean contains(String other) {
		AddressParseData parseData = getAddressParseData();
		int segmentData[] = parseData.getSegmentData(); //grab this field for thread safety, other threads can make it disappear
		if(segmentData == null) {
			return null;
		}
		if(skipContains()) {
			return null;
		}
		Integer pref = getProviderNetworkPrefixLength();
		IPAddressStringParameters options = getParameters();
		IPAddressNetwork<? extends IPAddress, ?, ?, ?, ?> network = (isProvidingIPv4() ? options.getIPv4Parameters() : options.getIPv6Parameters()).getNetwork();
		if(pref != null && !isPrefixSubnet(pref, network, segmentData)) {
			// this algorithm only works to check that the non-prefix host portion is valid,
			// it does not attempt to check containment of the host or match the host,
			// it depends on the host being full range in the containing address
			return null;
		}
		if(has_inet_aton_value || hasIPv4LeadingZeros) {
			//you need to skip inet_aton completely because it can screw up where prefix matches up with digits
			//you need to skip ipv4 leading zeros because addresses like 01.02.03.04 can change value depending on the validation options (octal or decimal)
			return null;
		}
		return matchesPrefix(other, segmentData);
	}
	
	@Override
	public Boolean prefixEquals(String other) {
		AddressParseData parseData = getAddressParseData();
		int segmentData[] = parseData.getSegmentData(); //grab this field for thread safety, other threads can make it disappear
		if(segmentData == null) {
			return null;
		}
		if(skipContains()) {
			return null;
		}
		if(has_inet_aton_value || hasIPv4LeadingZeros) {
			//you need to skip inet_aton completely because it can screw up where prefix matches up with digits
			//you need to skip ipv4 leading zeros because addresses like 01.02.03.04 can change value depending on the validation options (octal or decimal)
			return null;
		}
		return matchesPrefix(other, segmentData);
	}
	
	private Boolean matchesPrefix(String other, int segmentData[]) {
		AddressParseData parseData = getAddressParseData();
		Integer pref = getProviderNetworkPrefixLength();
		int expectedCount;
		boolean compressedAlready = false;
		boolean networkSegIsCompressed = false;
		boolean isIPv4 = isProvidingIPv4();
		boolean prefixIsMidSegment;
		int prefixEndCharIndex, remainingSegsCharIndex, networkSegIndex, networkSegCharIndex, networkSegsCount, adjustment; // prefixEndCharIndex points to separator following prefixed seg if whole seg is prefixed, remainingSegsCharIndex points to next digit
		remainingSegsCharIndex = networkSegCharIndex = networkSegIndex = networkSegsCount = adjustment = 0;
		int otherLen = other.length();
		if(pref == null) {
			expectedCount = isIPv4 ? IPv4Address.SEGMENT_COUNT : IPv6Address.SEGMENT_COUNT;
			networkSegIndex = expectedCount - 1;
			prefixEndCharIndex = getIndex(networkSegIndex, AddressParseData.KEY_UPPER_STR_END_INDEX, segmentData);
			if(otherLen > prefixEndCharIndex) {
				return null;
			}
			prefixIsMidSegment = false;
		} else if(pref == 0) {
			prefixIsMidSegment = false;
			expectedCount = isIPv4 ? IPv4Address.SEGMENT_COUNT : IPv6Address.SEGMENT_COUNT;
			prefixEndCharIndex = 0;
		} else {
			// If other has a prefix, then we end up returning false when we look at the end of the other string to ensure the other string his valid
			if(isIPv4) {
				expectedCount = IPv4Address.SEGMENT_COUNT;
				int bitsPerSegment = IPv4Address.BITS_PER_SEGMENT;
				int bytesPerSegment = IPv4Address.BYTES_PER_SEGMENT;
				networkSegIndex = ParsedAddressGrouping.getNetworkSegmentIndex(pref, bytesPerSegment, bitsPerSegment);
				prefixEndCharIndex = getIndex(networkSegIndex, AddressParseData.KEY_UPPER_STR_END_INDEX, segmentData);
				
				// changing the lowest bit:
				// can only change the lowest decimal digit too (even odd never crosses boundary 9 to 10
				// changing second lowest bit:
				// can change the second lowest decimal, an example is 0x60-0x64 is 96-100
				// in fact, that examples shows you can change all three decimal digits by changing the two lowest bits
				// so this means you can only make an adjustment if the seg prefix is 7, anything less and the whole segment can change
				Integer segPrefLength = ParsedAddressGrouping.getPrefixedSegmentPrefixLength(bitsPerSegment, pref, networkSegIndex);
				if(segPrefLength == IPv4Address.BITS_PER_SEGMENT - 1) {
					prefixIsMidSegment = true;
					adjustment = 1;
					remainingSegsCharIndex = getIndex(networkSegIndex, AddressParseData.KEY_UPPER_STR_START_INDEX, segmentData);
					prefixEndCharIndex--;
					networkSegsCount = networkSegIndex;
					networkSegCharIndex = getIndex(networkSegIndex, AddressParseData.KEY_LOWER_STR_START_INDEX, segmentData);
				} else {
					prefixIsMidSegment = segPrefLength != bitsPerSegment;
					networkSegsCount = networkSegIndex + 1;
					remainingSegsCharIndex = prefixEndCharIndex + 1;
					if(prefixIsMidSegment) {
						networkSegCharIndex = getIndex(networkSegIndex, AddressParseData.KEY_LOWER_STR_START_INDEX, segmentData);
					}
				}
			} else {
				expectedCount = IPv6Address.SEGMENT_COUNT;
				int bitsPerSegment = IPv6Address.BITS_PER_SEGMENT;
				int bytesPerSegment = IPv6Address.BYTES_PER_SEGMENT;
				networkSegIndex = ParsedAddressGrouping.getNetworkSegmentIndex(pref, bytesPerSegment, bitsPerSegment);
				int missingSegmentCount = IPv6Address.SEGMENT_COUNT - parseData.getSegmentCount();
				int compressedSegIndex = getConsecutiveSeparatorSegmentIndex();
				compressedAlready = compressedSegIndex <= networkSegIndex;//any part of network prefix is compressed
				networkSegIsCompressed = compressedAlready && compressedSegIndex + missingSegmentCount >= networkSegIndex;//the segment with the prefix boundary is compressed		
				Integer segPrefLength = ParsedAddressGrouping.getPrefixedSegmentPrefixLength(bitsPerSegment, pref, networkSegIndex);
				if(networkSegIsCompressed) {
					prefixIsMidSegment = segPrefLength != bitsPerSegment;
					networkSegsCount = networkSegIndex + 1;
					prefixEndCharIndex = getIndex(compressedSegIndex, AddressParseData.KEY_UPPER_STR_END_INDEX, segmentData) + 1; //to include all zeros in prefix we must include both seps, in other cases we include no seps at alls
					if (prefixIsMidSegment && compressedSegIndex > 0) {
						networkSegCharIndex = getIndex(compressedSegIndex, AddressParseData.KEY_LOWER_STR_START_INDEX, segmentData);
					}
					remainingSegsCharIndex = prefixEndCharIndex + 1;
				} else {
					int actualNetworkSegIndex;
					if(compressedSegIndex < networkSegIndex) {
						actualNetworkSegIndex = networkSegIndex - missingSegmentCount;
					} else {
						actualNetworkSegIndex = networkSegIndex;
					}
					prefixEndCharIndex = getIndex(actualNetworkSegIndex, AddressParseData.KEY_UPPER_STR_END_INDEX, segmentData);
					adjustment = IPv6AddressSegment.MAX_CHARS - ((segPrefLength + 3) >> 2); // divide by IPv6AddressSegment.BITS_PER_CHAR
					if(adjustment > 0) {
						prefixIsMidSegment = true;
						remainingSegsCharIndex = getIndex(actualNetworkSegIndex, AddressParseData.KEY_UPPER_STR_START_INDEX, segmentData);
						if(remainingSegsCharIndex + adjustment > prefixEndCharIndex) {
							adjustment = prefixEndCharIndex - remainingSegsCharIndex;
						}
						prefixEndCharIndex -= adjustment;
						networkSegsCount = networkSegIndex;
						networkSegCharIndex = getIndex(actualNetworkSegIndex, AddressParseData.KEY_LOWER_STR_START_INDEX, segmentData);
					} else {
						prefixIsMidSegment = segPrefLength != bitsPerSegment;
						networkSegsCount = actualNetworkSegIndex + 1;
						remainingSegsCharIndex = prefixEndCharIndex + 1;
						if(prefixIsMidSegment) {
							networkSegCharIndex = getIndex(actualNetworkSegIndex, AddressParseData.KEY_LOWER_STR_START_INDEX, segmentData);
						}
					}
				}
			}
		}
		CharSequence str = this.str;
		int otherSegmentCount = 0;
		boolean currentSegHasNonZeroDigits = false;
		for(int i = 0; i < prefixEndCharIndex; i++) {
			char c = str.charAt(i);
			char otherChar;
			if(i < otherLen) {
				otherChar = other.charAt(i);
			} else {
				otherChar = 0;
			}
			if(c != otherChar) {
				if(c >= '1' && c <= '9') {
				} else if(c >= 'a' && c <= 'f') {
				} else if(c >= 'A' && c <= 'F') {
					char adjustedChar = (char) (c - ('A' - 'a'));
					if(c == adjustedChar) {
						continue;
					}
				} else if(c <= Address.RANGE_SEPARATOR && c >= Address.SEGMENT_SQL_WILDCARD) {
					if(c == Address.SEGMENT_WILDCARD || c == Address.RANGE_SEPARATOR || c == Address.SEGMENT_SQL_WILDCARD) {
						return null;
					}
				} else if(c == Address.SEGMENT_SQL_SINGLE_WILDCARD) {
					return null;
				}
				
				if(otherChar >= 'A' && otherChar <= 'F') {
					char adjustedChar = (char) (otherChar - ('A' - 'a'));
					if(otherChar == adjustedChar) {
						continue;
					}
				} 
				
				if(prefixIsMidSegment && (i >= networkSegCharIndex || networkSegCharIndex == 1)) {
					// when prefix is not on seg boundary, we can have the same prefix without matching digits
					// the host part can change the digits of the network part, particulqrly for ipv4
					// this is true for ipv6 too when you consider host and network part of each digit
					// this is also true when the digit count in the segments do not match,
					// also note that f: and fabc: match prefix of 4 by string chars, but prefix does not match due to difference in digits in each segment
					// So, in general, when mismatch of prefix chars we cannot conclude mistmatch of prefix unless we are comparing entire segments (ie prefix is on seg boundary)
					return null;
				}
				
				if(hasRange(otherSegmentCount)) {
					return null;
				}

				if(otherChar >= '1' && otherChar <= '9') {
				} else if(otherChar >= 'a' && otherChar <= 'f') {
				} else {
					if(otherChar <= Address.RANGE_SEPARATOR && otherChar >= Address.SEGMENT_SQL_WILDCARD) {
						if(otherChar == Address.SEGMENT_WILDCARD || otherChar == Address.RANGE_SEPARATOR || otherChar == Address.SEGMENT_SQL_WILDCARD) {
							return null;
						}
					} else if(otherChar == Address.SEGMENT_SQL_SINGLE_WILDCARD) {
						return null;
					}
					
					if(!currentSegHasNonZeroDigits) {
						//we know that this address has no ipv4 leading zeros, we abort this method in such cases.
						//However, we do want to handle all the following cases and return null for each.
						//We do not handle differing numbers of leading zeros
						//We do not handle ipv6 compression in different places
						//So we want to handle segments that start like all of these cases:
						
						//other 01
						//this  1
						
						//other 00
						//this  1
						
						//other 00
						//this  :
						
						//other 0:
						//this  :
						
						//other 00
						//this  0:
						
						//other :
						//this  0
						
						//Those should all return null since they might in fact represent matching segments.
						//However, the following should return FALSE when there are no leading zeros and no compression:
						
						//other 0.
						//this  1
						
						//other 1
						//this  0.
						
						//other 0:
						//this  1
						
						//other 1
						//this  0:
						
						//So in summary, we first check that we have not matched non-zero values first (ie digitCount must be 0)
						//All the null cases involve one or the other starting with 0.
						//If the other is an ipv6 segment separator, return null.
						//Otherwise, if the zero is not the end of segment, we have leading zeros which we do not handle here, so we return null.
						//Otherwise, return false.  This is because we have a zero segment, and the other is not (it is neither compressed nor 0).
						//Actually, we return false only if the 0 segment is the other string, because if the 0 segment is this it is only one segment while the other may be multi-segment.
						//If the other might be multi-segment, we defer to the segment check that will tell us if we must have matching segments here.
						if(c == '0') {
							if(otherChar == IPv6Address.SEGMENT_SEPARATOR || otherChar == 0) {
								return null;
							}
							int k = i + 1;
							if(k < str.length()) {
								char nextChar = str.charAt(k);
								if(nextChar != IPv4Address.SEGMENT_SEPARATOR  && nextChar != IPv6Address.SEGMENT_SEPARATOR) {
									return null;
								}
							}
							//defer to the segment check
						} else if(otherChar == '0') {
							if(c == IPv6Address.SEGMENT_SEPARATOR) {
								return null;
							}
							int k = i + 1;
							if(k < otherLen) {
								char nextChar = other.charAt(k);
								if(nextChar != IPv4Address.SEGMENT_SEPARATOR  && nextChar != IPv6Address.SEGMENT_SEPARATOR) {
									return null;
								}
							}
							return Boolean.FALSE;
						}
					}
					if(otherChar == IPv6Address.SEGMENT_SEPARATOR) {
						return Boolean.FALSE; // we've alreqdy accounted for the case of container address 0 segment, so it is non-zero, so ending matching segment here is false match
					} else if(otherChar == IPv4Address.SEGMENT_SEPARATOR) {
						if(!isIPv4) {
							return null; //mixed address
						}
						otherSegmentCount++;
					}
				}
				
				//if other is a range like 3-3 must return null
				for(int k = i + 1; k < otherLen; k++) {
					otherChar = other.charAt(k);
					if(otherChar == IPv6Address.SEGMENT_SEPARATOR) {
						return Boolean.FALSE;
					} else if(otherChar <= IPAddress.PREFIX_LEN_SEPARATOR && otherChar >= Address.SEGMENT_SQL_WILDCARD) {
						if(otherChar == IPv4Address.SEGMENT_SEPARATOR) {
							if(!isIPv4) {
								return null; //mixed address
							}
							otherSegmentCount++;
						} else {
							if(otherChar == IPAddress.PREFIX_LEN_SEPARATOR || otherChar == Address.SEGMENT_WILDCARD || 
									otherChar == Address.RANGE_SEPARATOR || otherChar == Address.SEGMENT_SQL_WILDCARD ||
									otherChar == Address.SEGMENT_SQL_SINGLE_WILDCARD) {
								return null;
							}
						}
					}
				}
				if(isIPv4) {
					// if we match ipv4 seg count and we see no wildcards or other special chars, we can conclude non-containment
					if(otherSegmentCount + 1 == IPv4Address.SEGMENT_COUNT) {
						return Boolean.FALSE;
					}
				} else {
					// for ipv6 we have already checked for compression and special chars.  If we are not single segment, then we can conclude non-containment
					if(otherSegmentCount > 0) {
						return Boolean.FALSE;
					}
				}
				return null;
			}
			if(c != '0') {
				boolean isSegmentEnd = c == IPv6Address.SEGMENT_SEPARATOR || c == IPv4Address.SEGMENT_SEPARATOR;
				if(isSegmentEnd) {
					otherSegmentCount++;
					currentSegHasNonZeroDigits = false;
				} else {
					currentSegHasNonZeroDigits = true;
				}
			}
		}

		// At this point we know the prefix matches, so we need to prove that the provided string is indeed a valid ip address
		if(pref != null) {
			if(prefixEndCharIndex == otherLen) {  
				if(networkSegsCount != expectedCount) {
					// we are ok if compressed and networkSegsCount <= expectedCount which is 8 for ipv6, for example 1::/64 matching 1::, there are only 4 network segs
					if(!compressedAlready || networkSegsCount > expectedCount) {
						return null;
					}
				}
			} else {
				if(isIPv4) {
					if(pref != 0) {
						//we must match the same number of chars til end of segment, otherwise we might not have matched that last segment at all
						//we also cannot make conclusions when not matching due to '-' or '_' characters or matching leading zeros
						int segmentEndIndex = prefixEndCharIndex + adjustment;
						if(otherLen < segmentEndIndex) {
							return null;
						}
						if(otherLen != segmentEndIndex && other.charAt(segmentEndIndex) != IPv4Address.SEGMENT_SEPARATOR) {
							return null;
						}
						for(int n = prefixEndCharIndex; n < segmentEndIndex; n++) {
							char otherChar = other.charAt(n);
							if(otherChar == IPv4Address.SEGMENT_SEPARATOR) {
								return null;
							}
						}
					}
					
					//now count the remaining segments and check those chars
					int digitCount = 0;
					int remainingSegCount = 0;
					boolean firstIsHighIPv4 = false;
					int i = remainingSegsCharIndex;
					for(; i < otherLen; i++) {
						char otherChar = other.charAt(i);
						if(otherChar <= '9' && otherChar >= '0') {
							if(digitCount == 0 && otherChar >= '3') {
								firstIsHighIPv4 = true;
							}
							++digitCount;
						} else if(otherChar == IPv4Address.SEGMENT_SEPARATOR) {
							if(digitCount == 0) {
								return Boolean.FALSE;
							}
							if(firstIsHighIPv4) {
								if(digitCount >= IPv4AddressSegment.MAX_CHARS) {
									return Boolean.FALSE;
								}
							} else if(digitCount > IPv4AddressSegment.MAX_CHARS) {
								return null;//leading zeros or inet_aton formats
							}
							digitCount = 0;
							remainingSegCount++;
							firstIsHighIPv4 = false;
						} else { 
							return null; //some other character, possibly base 85, also '/' or wildcards
						}
					} // end for
					if(digitCount == 0) {
						return Boolean.FALSE;
					}
					if(digitCount > IPv4AddressSegment.MAX_CHARS) {
						return null;
					} else if(firstIsHighIPv4 && digitCount == IPv4AddressSegment.MAX_CHARS) {
						return null;
					}
					int totalSegCount = networkSegsCount + remainingSegCount + 1;
					if(totalSegCount != expectedCount) {
						return null;
					}
				} else {
					if(pref != 0) {
						// we must match the same number of chars til end of segment, otherwise we might not have matched that last segment at all
						// we also cannot make conclusions when not matching due to '-' or '_' characters or matching leading zeros
						// end of prefixed segment must be followed by separator eg 1:2 is prefix and must be followed by :
						// also note this handles 1:2:: as prefix
						int segmentEndIndex = prefixEndCharIndex + adjustment;
						if(otherLen < segmentEndIndex) {
							return null;
						}
						if(otherLen != segmentEndIndex && other.charAt(segmentEndIndex) != IPv6Address.SEGMENT_SEPARATOR) {
							return null;
						}
						for(int n = prefixEndCharIndex; n < segmentEndIndex; n++) {
							char otherChar = other.charAt(n);
							if(otherChar == IPv6Address.SEGMENT_SEPARATOR) {
								return null;
							}
						}
					}
					
					//now count the remaining segments and check those chars
					int digitCount = 0;
					int remainingSegCount = 0;
					int i = remainingSegsCharIndex;
					for(; i < otherLen; i++) {
						char otherChar = other.charAt(i);		
						if(otherChar <= '9' && otherChar >= '0') {
							++digitCount;
						} else if((otherChar >= 'a' && otherChar <= 'f') || (otherChar >= 'A' && otherChar <= 'F')) {
							++digitCount;
						} else if(otherChar == IPv4Address.SEGMENT_SEPARATOR) {
							return null; // could be ipv6/ipv4 mixed
						} else if(otherChar == IPv6Address.SEGMENT_SEPARATOR) {
							if(digitCount > IPv6AddressSegment.MAX_CHARS) {
								return null;//possibly leading zeros or ranges
							}
							if(digitCount == 0) {
								if(compressedAlready) {
									return Boolean.FALSE;
								}
								compressedAlready = true;
							} else {
								digitCount = 0;
							}
							remainingSegCount++;
						} else { 
							return null; //some other character, possibly base 85, also '/' or wildcards
						}
					} // end for
					if(digitCount == 0) {
						int prevIndex = i - 1;
						if(prevIndex < 0) {
							return Boolean.FALSE;
						}
						char prevChar = other.charAt(prevIndex);
						if(prevChar != IPv6Address.SEGMENT_SEPARATOR) { // cannot end with empty segment unless prev segment also empty
							return Boolean.FALSE;
						}
					} else if(digitCount > IPv6AddressSegment.MAX_CHARS) {
						return null;
					}
					int totalSegCount = networkSegsCount + remainingSegCount + 1;
					if(totalSegCount > expectedCount || (totalSegCount < expectedCount && !compressedAlready)) {
						return null;
					}
					if(networkSegIsCompressed && expectedCount - remainingSegCount <= networkSegIndex) {
						//consider 1:: and you are looking at segment 7
						//So we look at the front and we see it matches 1::
						//But what if the end is 1::3:4:5?
						return null;
					}
				}
			}
		}
		return Boolean.TRUE;
	}

	@Override
	public Boolean contains(IPAddressProvider other) {
		if(other instanceof ParsedIPAddress) {
			CachedIPAddresses<?> vals = values;
			CachedIPAddresses<?> otherVals = values;
			if(vals == null || otherVals == null) {
				// one or the other value not yet created, so take the shortcut that provides an answer most (but not all) of the time
				// An answer is provided for all normalized, conventional or canonical addresses
				return contains((ParsedIPAddress) other, false, false);
			} // else we defer to the values-based containment check (in the caller), which is best since it is ready to go
		}
		return null;
	}
	
	@Override
	public Boolean parsedEquals(IPAddressProvider other) {
		if(other instanceof ParsedIPAddress) {
			CachedIPAddresses<?> vals = values;
			CachedIPAddresses<?> otherVals = values;
			if(vals == null || otherVals == null) {
				// one or the other value not yet created, so take the shortcut that provides an answer most (but not all) of the time
				// An answer is provided for all normalized, conventional or canonical addresses
				ParsedIPAddress parsedOther = (ParsedIPAddress) other;
				Boolean result = contains(parsedOther, false, true);
				if(result != null) {
					return result && Objects.equals(getQualifier().getZone(), parsedOther.getQualifier().getZone());
				} // else we defer to the values-based equality check (in the caller), which is best since it is ready to go.
			}
		}
		return null;
	}
	
	@Override
	public Boolean prefixEquals(IPAddressProvider other) {
		if(other instanceof ParsedIPAddress) {
			CachedIPAddresses<?> vals = values;
			CachedIPAddresses<?> otherVals = values;
			if(vals == null || otherVals == null) {
				// one or the other value not yet created, so take the shortcut that provides an answer most (but not all) of the time
				// An answer is provided for all normalized, conventional or canonical addresses
				return contains((ParsedIPAddress) other, true, true);
			} // else we defer to the values-based containment check (in the caller), which is best since it is ready to go.
		}
		return null;
	}
	
	//not used for invalid, or cases where parseData.isEmpty or parseData.isAll
	private Boolean contains(ParsedIPAddress other, boolean networkOnly, boolean equals) {
		AddressParseData parseData = getAddressParseData();
		AddressParseData otherParseData = other.getAddressParseData();
		int segmentData[] = parseData.getSegmentData(); //grab this field for thread safety, other threads can make it disappear
		int otherSegmentData[] = otherParseData.getSegmentData(); //grab this field for thread safety, other threads can make it disappear
		if(segmentData == null || otherSegmentData == null) {
			return null;
		}
		if(skipContains() || other.skipContains()) {
			return null;
		}
		IPVersion ipVersion = getProviderIPVersion();
		if(!ipVersion.equals(other.getProviderIPVersion())) {
			return Boolean.FALSE;
		}
		int segmentCount = parseData.getSegmentCount();
		int otherSegmentCount = otherParseData.getSegmentCount();
		int max;
		IPAddressNetwork<? extends IPAddress, ?, ?, ?, ?> network;
		boolean compressedAlready, otherCompressedAlready;
		int expectedSegCount, bitsPerSegment, bytesPerSegment;
		IPAddressStringParameters options = getParameters();
		if(isProvidingIPv4()) {
			max = IPv4Address.MAX_VALUE_PER_SEGMENT;
			expectedSegCount = IPv4Address.SEGMENT_COUNT;
			bitsPerSegment = IPv4Address.BITS_PER_SEGMENT;
			bytesPerSegment = IPv4Address.BYTES_PER_SEGMENT;
			network = options.getIPv4Parameters().getNetwork();
			compressedAlready = true;
			otherCompressedAlready = true;
		} else {
			max = IPv6Address.MAX_VALUE_PER_SEGMENT;
			expectedSegCount = IPv6Address.SEGMENT_COUNT;
			bitsPerSegment = IPv6Address.BITS_PER_SEGMENT;
			bytesPerSegment = IPv6Address.BYTES_PER_SEGMENT;
			network = options.getIPv6Parameters().getNetwork();
			compressedAlready = expectedSegCount == segmentCount;
			otherCompressedAlready = expectedSegCount == otherSegmentCount;
		}
		PrefixConfiguration prefConf = network.getPrefixConfiguration();
		boolean zeroHostsAreSubnets = prefConf.zeroHostsAreSubnets();
		boolean allPrefixedAddressesAreSubnets = prefConf.allPrefixedAddressesAreSubnets();
		Integer pref = getProviderNetworkPrefixLength();
		Integer otherPref = other.getProviderNetworkPrefixLength();
		int networkSegIndex, hostSegIndex, endIndex, otherHostAllSegIndex, hostAllSegIndex = expectedSegCount;
		endIndex = segmentCount;
		if(pref == null) {
			networkOnly = false;
			hostSegIndex = expectedSegCount;
			networkSegIndex = hostSegIndex - 1;
		} else {
			hostSegIndex = ParsedAddressGrouping.getHostSegmentIndex(pref, bytesPerSegment, bitsPerSegment);
			networkSegIndex = ParsedAddressGrouping.getNetworkSegmentIndex(pref, bytesPerSegment, bitsPerSegment);
			if(!networkOnly || networkSegIndex == hostSegIndex) {
				boolean isPrefixSubnet = allPrefixedAddressesAreSubnets || (zeroHostsAreSubnets && isPrefixSubnet(pref, network, segmentData));
				if(!equals) {
					networkOnly |= isPrefixSubnet;
				}
				if(isPrefixSubnet) {
					hostAllSegIndex = ParsedAddressGrouping.getHostSegmentIndex(pref, bytesPerSegment, bitsPerSegment);
				}
			}
		}
		if(otherPref != null && (allPrefixedAddressesAreSubnets || (zeroHostsAreSubnets && other.isPrefixSubnet(otherPref, network, otherSegmentData)))) {
			otherHostAllSegIndex = ParsedAddressGrouping.getHostSegmentIndex(otherPref, bytesPerSegment, bitsPerSegment);
		} else {
			otherHostAllSegIndex = expectedSegCount;
		}
		int i = 0, j = 0, normalizedCount = 0;
		int compressedCount, otherCompressedCount;
		compressedCount = otherCompressedCount = 0;
		while(i < endIndex || compressedCount > 0) {
			if(networkOnly && normalizedCount > networkSegIndex) {
				break;
			}		
			long lower, upper;
		    if(compressedCount > 0) {
		    	lower = upper = 0;
		    } else {
		    	lower = getValue(i, AddressParseData.KEY_LOWER, segmentData);
		    	upper = getValue(i, AddressParseData.KEY_UPPER, segmentData);
		    }
		    if(normalizedCount >= hostAllSegIndex) {
		    	Integer segPrefLength = ParsedAddressGrouping.getSegmentPrefixLength(bitsPerSegment, pref, normalizedCount);
				lower &= network.getSegmentNetworkMask(segPrefLength);
				upper |= network.getSegmentHostMask(segPrefLength);
			}
			long otherLower, otherUpper;
			if(normalizedCount > otherHostAllSegIndex) {
				otherLower = 0;
				otherUpper = max;
			} else {
				if(otherCompressedCount > 0) {
					otherLower = otherUpper = 0;
				} else {
					otherLower = getValue(j, AddressParseData.KEY_LOWER, otherSegmentData);
					otherUpper = getValue(j, AddressParseData.KEY_UPPER, otherSegmentData);
				}
				if(normalizedCount == otherHostAllSegIndex) {
					Integer segPrefLength = ParsedAddressGrouping.getSegmentPrefixLength(bitsPerSegment, otherPref, normalizedCount);
					otherLower &= network.getSegmentNetworkMask(segPrefLength);
					otherUpper |= network.getSegmentHostMask(segPrefLength);
				}
			}
			if(equals ? (lower != otherLower || upper != otherUpper) : (lower > otherLower || upper < otherUpper)) {
				return Boolean.FALSE;
			}
			if(!compressedAlready) {
				if(compressedCount > 0) {
					if(--compressedCount == 0) {
						compressedAlready = true;
					}
				} else if(isCompressed(i, segmentData)) {
					i++;
					compressedCount = expectedSegCount - segmentCount;
				} else {
					i++;
				}
			} else {
				i++;
			}
			if(!otherCompressedAlready) {
				if(otherCompressedCount > 0) {
					if(--otherCompressedCount == 0) {
						otherCompressedAlready = true;
					}
				} else if(other.isCompressed(j, otherSegmentData)) {
					j++;
					otherCompressedCount = expectedSegCount - otherSegmentCount;
				} else {
					j++;
				}
			} else {
				j++;
			}
			normalizedCount++;
		}
		return Boolean.TRUE;
	}
		
	protected boolean isPrefixSubnet(Integer networkPrefixLength, IPAddressNetwork<?, ?, ?, ?, ?> network, int segmentData[]) {
		IPVersion version = network.getIPVersion();
		int bytesPerSegment = IPAddressSection.bytesPerSegment(version);
		int bitsPerSegment = IPAddressSection.bitsPerSegment(version);
		int max = IPAddressSegment.getMaxSegmentValue(version);
		PrefixConfiguration prefConf = network.getPrefixConfiguration();
		AddressParseData addressParseData = getAddressParseData();
		int segmentCount = addressParseData.getSegmentCount();
		if(isCompressed()) {
			int compressedCount = IPv6Address.SEGMENT_COUNT - segmentCount;
			int compressedIndex = addressParseData.getConsecutiveSeparatorSegmentIndex();
			return ParsedAddressGrouping.isPrefixSubnet(
					(segmentIndex) -> {
						if(segmentIndex >= compressedIndex) {
							if(segmentIndex - compressedIndex < compressedCount) {
								return 0;
							}
							segmentIndex -= compressedCount;
						}
						return (int) getValue(segmentIndex, AddressParseData.KEY_LOWER, segmentData);
					},
					(segmentIndex) -> {
						if(segmentIndex >= compressedIndex) {
							if(segmentIndex - compressedIndex < compressedCount) {
								return 0;
							}
							segmentIndex -= compressedCount;
						}
						return (int) getValue(segmentIndex, AddressParseData.KEY_UPPER, segmentData);
					},
					segmentCount + compressedCount,
					bytesPerSegment,
					bitsPerSegment,
					max,
					networkPrefixLength,
					prefConf,
					false);
		}
		//we do not enter this method with parse data from inet_aton or single segment strings, so the cast to int is fine
		return ParsedAddressGrouping.isPrefixSubnet(
				(segmentIndex) -> (int) getValue(segmentIndex, AddressParseData.KEY_LOWER, segmentData),
				(segmentIndex) -> (int) getValue(segmentIndex, AddressParseData.KEY_UPPER, segmentData),
				segmentCount,
				bytesPerSegment,
				bitsPerSegment,
				max,
				networkPrefixLength,
				prefConf,
				false);
	}
	
	@Override 
	public Integer getProviderNetworkPrefixLength() {
		return getQualifier().getEquivalentPrefixLength();
	}
	
	IPAddresses<?, ?> createAddresses()  {
		IPVersion version = getProviderIPVersion();
		if(version == IPVersion.IPV4) {
			return createIPv4Addresses();
		} else if(version == IPVersion.IPV6) {
			return createIPv6Addresses();
		}
		return null;
	}
	
	private static <S extends IPAddressSegment> S[] allocateHostSegments(
			S segments[],
			S originalSegments[],
			AddressSegmentCreator<S> creator,
			int segmentCount,
			int originalCount) {
		if(segments == null) {
			segments = creator.createSegmentArray(segmentCount);
			System.arraycopy(originalSegments,  0,  segments, 0, originalCount);
		}
		return segments;
	}
	
	@SuppressWarnings("serial")
	private IPAddresses<IPv4Address, IPv4AddressSection> createIPv4Addresses() {
		ParsedHostIdentifierStringQualifier qualifier = getQualifier();
		IPAddress mask = qualifier.getMask();
		if(mask != null && mask.getBlockMaskPrefixLength(true) != null) {
			mask = null;//we don't do any masking if the mask is a subnet mask, instead we just map it to the corresponding prefix length
		}
		boolean hasMask = mask != null;
		AddressParseData addrParseData = getAddressParseData();
		int segmentCount = addrParseData.getSegmentCount();
		IPv4AddressCreator creator = getIPv4AddressCreator();
		int ipv4SegmentCount = IPv4Address.SEGMENT_COUNT;
		int missingCount = ipv4SegmentCount - segmentCount;
		IPv4AddressSegment hostSegments[] = null;
		IPv4AddressSegment segments[] = creator.createSegmentArray(ipv4SegmentCount);
		boolean expandedSegments = (missingCount <= 0);
		int expandedStart, expandedEnd;
		expandedStart = expandedEnd = -1;
		CharSequence addressString = str;
		for(int i = 0, normalizedSegmentIndex = 0; i < segmentCount; i++, normalizedSegmentIndex++) {
			long lower = addrParseData.getValue(i, AddressParseData.KEY_LOWER);
			long upper = addrParseData.getValue(i, AddressParseData.KEY_UPPER);

			//handle inet_aton style joined segments
			boolean isLastSegment = i == segmentCount - 1;
			if(!expandedSegments && isLastSegment && !addrParseData.isWildcard(i)) {
				boolean useStringIndicators = true;
				expandedSegments = true;
				int count = missingCount;
				expandedStart = i;
				expandedEnd = i + count;
				while(count >= 0) { //add the missing segments
					Integer currentPrefix = getSegmentPrefixLength(normalizedSegmentIndex, IPv4Address.BITS_PER_SEGMENT, qualifier);
					int newLower, newUpper;
					if(lower != upper) {
						int shift = IPv4Address.BITS_PER_SEGMENT * count;
						int segmentMask = IPv4Address.MAX_VALUE_PER_SEGMENT;
						newLower = (int) (lower >>> shift) & segmentMask;
						newUpper = (int) (upper >>> shift) & segmentMask;
						//we may be able to reuse our strings on the final segment
						//for previous segments, strings can be reused only when the value is 0, which we do not need to cache.  Any other value changes when shifted.  
						if(count == 0 && newLower == lower) {
							if(newUpper != upper) {
								addrParseData.setFlag(i, AddressParseData.KEY_STANDARD_RANGE_STR, false);
							}
						} else {
							useStringIndicators = false;
						}
					} else {
						newLower = newUpper = (int) (lower >> (IPv4Address.BITS_PER_SEGMENT * count)) & IPv4Address.MAX_VALUE_PER_SEGMENT;
						if(count != 0 || newLower != lower) {
							useStringIndicators = false;
						}
					}
					Integer segmentMask = hasMask ? cacheSegmentMask(mask.getSegment(normalizedSegmentIndex).getSegmentValue()) : null;
					if(segmentMask != null || currentPrefix != null) {
						hostSegments = allocateHostSegments(hostSegments, segments, creator, ipv4SegmentCount, normalizedSegmentIndex);
						hostSegments[normalizedSegmentIndex] = createSegment(
								addressString,
								IPVersion.IPV4,
								newLower,
								newUpper,
								useStringIndicators,
								addrParseData,
								i,
								null,
								null,
								creator);
					}
					segments[normalizedSegmentIndex] = createSegment(
						addressString,
						IPVersion.IPV4,
						newLower,
						newUpper,
						useStringIndicators,
						addrParseData,
						i,
						currentPrefix,
						segmentMask,
						creator);
					++normalizedSegmentIndex;
					count--;
				}
				break;
			} //end handle inet_aton joined segments
			Integer segmentMask = hasMask ? cacheSegmentMask(mask.getSegment(normalizedSegmentIndex).getSegmentValue()) : null;
			Integer segmentPrefixLength = getSegmentPrefixLength(normalizedSegmentIndex, IPv4Address.BITS_PER_SEGMENT, qualifier);
			if(segmentMask != null || segmentPrefixLength != null) {
				hostSegments = allocateHostSegments(hostSegments, segments, creator, ipv4SegmentCount, normalizedSegmentIndex);
				hostSegments[normalizedSegmentIndex] = createSegment(
						addressString,
						IPVersion.IPV4,
						(int) lower,
						(int) upper,
						true,
						addrParseData,
						i,
						null,
						null,
						creator);
			}
			segments[normalizedSegmentIndex] = createSegment(
					addressString,
					IPVersion.IPV4,
					(int) lower,
					(int) upper,
					true,
					addrParseData,
					i,
					segmentPrefixLength,
					segmentMask,
					creator);
			if(!expandedSegments &&
					//check for any missing segments that we should account for here
					addrParseData.isWildcard(i) && (!is_inet_aton_joined() || isLastSegment)) {
				boolean expandSegments = true;
				for(int j = i + 1; j < segmentCount; j++) {
					if(addrParseData.isWildcard(j)) {//another wildcard further down
						expandSegments = false;
						break;
					}
				}
				if(expandSegments) {
					expandedSegments = true;
					int count = missingCount;
					while(count-- > 0) { //add the missing segments
						++normalizedSegmentIndex;
						segmentMask = hasMask ? cacheSegmentMask(mask.getSegment(normalizedSegmentIndex).getSegmentValue()) : null;
						segmentPrefixLength = getSegmentPrefixLength(normalizedSegmentIndex, IPv4Address.BITS_PER_SEGMENT, qualifier);
						if(segmentMask != null || segmentPrefixLength != null) {
							hostSegments = allocateHostSegments(hostSegments, segments, creator, ipv4SegmentCount, normalizedSegmentIndex);
							hostSegments[normalizedSegmentIndex] = createSegment(
									addressString,
									IPVersion.IPV4,
									(int) lower,
									(int) upper,
									false,
									addrParseData,
									i,
									null,
									null,
									creator);
						}
						segments[normalizedSegmentIndex] = createSegment(
							addressString,
							IPVersion.IPV4,
							0,
							IPv4Address.MAX_VALUE_PER_SEGMENT,
							false,
							addrParseData,
							i,
							segmentPrefixLength,
							segmentMask,
							creator);
					}
				}
			}
		}
		ParsedAddressCreator<IPv4Address, IPv4AddressSection, ?, IPv4AddressSegment> addressCreator = creator;
		Integer prefLength = getPrefixLength(qualifier);
		IPv4AddressSection result = addressCreator.createPrefixedSectionInternal(segments, prefLength);
		IPv4AddressSection hostResult;
		if(hostSegments != null) {
			hostResult = addressCreator.createSectionInternal(hostSegments);
		} else {
			hostResult = null;
		}
		if(checkExpandedValues(result, expandedStart, expandedEnd)) {
			throw new IncompatibleAddressException(addressString, "ipaddress.error.invalid.joined.ranges");
		}
		if(checkExpandedValues(hostResult, expandedStart, expandedEnd)) {
			hostResult = null;
		}
		return new IPAddresses<IPv4Address, IPv4AddressSection>(result, hostResult) {
			@Override
			ParsedAddressCreator<IPv4Address, IPv4AddressSection, ?, ?> getCreator() {
				return getIPv4AddressCreator();
			}
		};
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
	private boolean checkExpandedValues(IPAddressSection section, int start, int end) {
		if(section != null && start < end) {
			IPAddressSegment seg = section.getSegment(start);
			boolean lastWasRange = seg.isMultiple();
			do {
				seg = section.getSegment(++start);
				if(lastWasRange) {
					if(!seg.isFullRange()) {
						return true;
					}
				} else {
					lastWasRange = seg.isMultiple();
				}
			} while(start < end);
		}
		return false;
	}
	
	@SuppressWarnings("serial")
	private IPAddresses<IPv6Address, IPv6AddressSection> createIPv6Addresses()  {
		ParsedHostIdentifierStringQualifier qualifier = getQualifier();
		IPAddress mask = qualifier.getMask();
		if(mask != null && mask.getBlockMaskPrefixLength(true) != null) {
			mask = null;//we don't do any masking if the mask is a subnet mask, instead we just map it to the corresponding prefix length
		}
		boolean hasMask = mask != null;
		AddressParseData addressParseData = getAddressParseData();
		int segmentCount = addressParseData.getSegmentCount();
		IPv6AddressCreator creator = getIPv6AddressCreator();
		int ipv6SegmentCount = IPv6Address.SEGMENT_COUNT;
		IPv6AddressSegment hostSegments[] = null;
		IPv6AddressSegment segments[] = creator.createSegmentArray(ipv6SegmentCount);
		boolean mixed = isProvidingMixedIPv6();
		int normalizedSegmentIndex = 0;
		int missingSegmentCount = (mixed ? IPv6Address.MIXED_ORIGINAL_SEGMENT_COUNT : ipv6SegmentCount) - segmentCount;
		boolean expandedSegments = (missingSegmentCount <= 0);
		int expandedStart, expandedEnd;
		expandedStart = expandedEnd = -1;
		CharSequence addressString = str;
		
		//get the segments for IPv6
		for(int i = 0; i < segmentCount; i++) {
			long lower = addressParseData.getValue(i, AddressParseData.KEY_LOWER);
			long upper = addressParseData.getValue(i, AddressParseData.KEY_UPPER);
			
			//handle joined segments
			if(!expandedSegments && i == segmentCount - 1 && !addressParseData.isWildcard(i)) {
				boolean useStringIndicators = true;
				expandedSegments = true;
				int count = missingSegmentCount;
				long lowerHighBytes, upperHighBytes;
				boolean isRange;
				if(count >= 4) {
					lowerHighBytes = addressParseData.getValue(i, AddressParseData.KEY_EXTENDED_LOWER);//the high half of the lower value
					upperHighBytes = addressParseData.getValue(i, AddressParseData.KEY_EXTENDED_UPPER);//the high half of the upper value
					isRange = (lower != upper) || (lowerHighBytes != upperHighBytes);
				} else {
					lowerHighBytes = upperHighBytes = 0;
					isRange = (lower != upper);
				}
				expandedStart = i;
				expandedEnd = i + count;
				while(count >= 0) { //add the missing segments
					Integer currentPrefix = getSegmentPrefixLength(normalizedSegmentIndex, IPv6Address.BITS_PER_SEGMENT, qualifier);
					int newLower, newUpper;
					if(isRange) {
						int segmentMask = IPv6Address.MAX_VALUE_PER_SEGMENT;
						if(count >= 4) {
							int shift = IPv6Address.BITS_PER_SEGMENT * (count % 4);
							newLower = (int) (lowerHighBytes >>> shift) & segmentMask;
							newUpper = (int) (upperHighBytes >>> shift) & segmentMask;
						} else {
							int shift = IPv6Address.BITS_PER_SEGMENT * count;
							newLower = (int) (lower >>> shift) & segmentMask;
							newUpper = (int) (upper >>> shift) & segmentMask;
						}
						//we may be able to reuse our strings on the final segment
						//for previous segments, strings can be reused only when the value is 0, which we do not need to cache.  Any other value changes when shifted.  
						if(count == 0 && newLower == lower && lowerHighBytes == 0) {
							if(newUpper != upper || upperHighBytes != 0) {
								addressParseData.setFlag(i, AddressParseData.KEY_STANDARD_RANGE_STR, false);
							}
						} else {
							useStringIndicators = false;
						}
					} else {
						if(count >= 4) {
							newLower = newUpper = (int) (lowerHighBytes >>> (IPv6Address.BITS_PER_SEGMENT * (count % 4))) & IPv6Address.MAX_VALUE_PER_SEGMENT;
							useStringIndicators = false;
						} else {
							newLower = newUpper = (int) (lower >>> (IPv6Address.BITS_PER_SEGMENT * count)) & IPv6Address.MAX_VALUE_PER_SEGMENT;
							if(count != 0 || newLower != lower || lowerHighBytes != 0) {
								useStringIndicators = false;
							}
						}
					}
					Integer segmentMask = hasMask ? cacheSegmentMask(mask.getSegment(normalizedSegmentIndex).getSegmentValue()) : null;
					if(segmentMask != null || currentPrefix != null) {
						hostSegments = allocateHostSegments(hostSegments, segments, creator, ipv6SegmentCount, normalizedSegmentIndex);
						hostSegments[normalizedSegmentIndex] = createSegment(
								addressString,
								IPVersion.IPV6,
								newLower,
								newUpper,
								useStringIndicators,
								addressParseData,
								i,
								null,
								null,
								creator);
					}
					segments[normalizedSegmentIndex] = createSegment(
						addressString,
						IPVersion.IPV6,
						newLower,
						newUpper,
						useStringIndicators,
						addressParseData,
						i,
						currentPrefix,
						segmentMask,
						creator);
					++normalizedSegmentIndex;
					count--;
				}
				break;
			} //end handle joined segments
			
			Integer segmentMask = hasMask ? cacheSegmentMask(mask.getSegment(normalizedSegmentIndex).getSegmentValue()) : null;
			Integer segmentPrefixLength = getSegmentPrefixLength(normalizedSegmentIndex, IPv6Address.BITS_PER_SEGMENT, qualifier);
			if(segmentMask != null || segmentPrefixLength != null) {
				hostSegments = allocateHostSegments(hostSegments, segments, creator, ipv6SegmentCount, normalizedSegmentIndex);
				hostSegments[normalizedSegmentIndex] = createSegment(
						addressString,
						IPVersion.IPV6,
						(int) lower,
						(int) upper,
						true,
						addressParseData,
						i,
						null,
						null,
						creator);
			}
			segments[normalizedSegmentIndex] = createSegment(
				addressString,
				IPVersion.IPV6,
				(int) lower,
				(int) upper,
				true,
				addressParseData,
				i,
				segmentPrefixLength,
				segmentMask,
				creator);
			normalizedSegmentIndex++;
			int expandValueLower = 0, expandValueUpper = 0;
			if(!expandedSegments) {
				//check for any missing segments that we should account for here
				boolean expandSegments = false;
				if(addressParseData.isWildcard(i)) {
					expandValueLower = 0;
					expandValueUpper = IPv6Address.MAX_VALUE_PER_SEGMENT;
					expandSegments = true;
					for(int j = i + 1; j < segmentCount; j++) {
						if(addressParseData.isWildcard(j) || isCompressed(j)) {//another wildcard further down
							expandSegments = false;
							break;
						}
					}
				} else {
					//compressed ipv6?
					if(isCompressed(i)) {
						expandSegments = true;
						expandValueLower = expandValueUpper = 0;
					}
				}
				//fill in missing segments
				if(expandSegments) {
					expandedSegments = true;
					int count = missingSegmentCount;
					while(count-- > 0) { //add the missing segments
						segmentMask = hasMask ? cacheSegmentMask(mask.getSegment(normalizedSegmentIndex).getSegmentValue()) : null;
						segmentPrefixLength = getSegmentPrefixLength(normalizedSegmentIndex, IPv6Address.BITS_PER_SEGMENT, qualifier);
						if(segmentMask != null || segmentPrefixLength != null) {
							hostSegments = allocateHostSegments(hostSegments, segments, creator, ipv6SegmentCount, normalizedSegmentIndex);
							hostSegments[normalizedSegmentIndex] = createSegment(
									addressString,
									IPVersion.IPV6,
									expandValueLower,
									expandValueUpper,
									false,
									addressParseData,
									i,
									null,
									null,
									creator);
						}
						segments[normalizedSegmentIndex] = createSegment(
								addressString,
								IPVersion.IPV6,
								expandValueLower,
								expandValueUpper,
								false,
								addressParseData,
								i,
								segmentPrefixLength,
								segmentMask,
								creator);
						normalizedSegmentIndex++;
					}
				}
			}
		}
		IPv6AddressSection result = null, hostResult = null;
		ParsedAddressCreator<?, IPv6AddressSection, IPv4AddressSection, IPv6AddressSegment> addressCreator = creator;
		if(mixed) {
			IPv4AddressSection ipv4AddressSection = getMixedParsedAddress().createIPv4Addresses().getSection();
			boolean embeddedSectionIsChanged = false;
			for(int n = 0; n < 2; n++) {
				int m = n << 1;
				IPv4AddressSegment one = ipv4AddressSection.getSegment(m);
				IPv4AddressSegment two = ipv4AddressSection.getSegment(m + 1);
				Integer segmentMask = hasMask ? cacheSegmentMask(mask.getSegment(normalizedSegmentIndex).getSegmentValue()) : null;
				IPv6AddressSegment newSegment;
				Integer segmentPrefixLength = getSegmentPrefixLength(normalizedSegmentIndex, IPv6Address.BITS_PER_SEGMENT, qualifier);
				boolean doHostSegment = segmentMask != null || segmentPrefixLength != null;
				if(doHostSegment) {
					hostSegments = allocateHostSegments(hostSegments, segments, creator, ipv6SegmentCount, normalizedSegmentIndex);
				}
				int oneLower = one.getSegmentValue();
				int twoLower = two.getSegmentValue();
				if(!one.isMultiple() && !two.isMultiple()) {
					if(doHostSegment) {
						hostSegments[normalizedSegmentIndex] = createSegment(oneLower, twoLower, null, null, creator);
					}
					segments[normalizedSegmentIndex] = newSegment = createSegment(
							oneLower,
							twoLower,
							segmentPrefixLength,
							segmentMask,
							creator);
				} else {
					// this can throw IncompatibleAddressException
					int oneUpper = one.getUpperSegmentValue();
					int twoUpper = two.getUpperSegmentValue();
					if(doHostSegment) {
						hostSegments[normalizedSegmentIndex] = createSegment(one, two, oneLower, oneUpper, twoLower, twoUpper, null, null, creator);
					}
					segments[normalizedSegmentIndex] = newSegment = createSegment(
							one, 
							two,
							oneLower,
							oneUpper,
							twoLower,
							twoUpper,
							segmentPrefixLength,
							segmentMask,
							creator);
				}
				embeddedSectionIsChanged |= newSegment.isPrefixed() || /* note that parseData.mixedParsedAddress is never prefixed */ 
						newSegment.getSegmentValue() != ((one.getSegmentValue() << IPv4Address.BITS_PER_SEGMENT) | two.getSegmentValue()) ||
						newSegment.getUpperSegmentValue() != ((one.getUpperSegmentValue() << IPv4Address.BITS_PER_SEGMENT) | two.getUpperSegmentValue());
				normalizedSegmentIndex++;
			}
			if(!embeddedSectionIsChanged) {
				if(hostSegments != null) {
					hostResult = addressCreator.createSectionInternal(hostSegments, ipv4AddressSection);
				}
				result = addressCreator.createSectionInternal(segments, ipv4AddressSection, getPrefixLength(qualifier));
			}
		} 
		if(result == null) {
			if(hostSegments != null) {
				hostResult = addressCreator.createSectionInternal(hostSegments);
			}
			result = addressCreator.createPrefixedSectionInternal(segments, getPrefixLength(qualifier));
		}
		if(checkExpandedValues(result, expandedStart, expandedEnd)) {
			throw new IncompatibleAddressException(addressString, "ipaddress.error.invalid.joined.ranges");
		}
		if(checkExpandedValues(hostResult, expandedStart, expandedEnd)) {
			hostResult = null;
		}
		return new IPAddresses<IPv6Address, IPv6AddressSection>(result, hostResult) {
			@Override
			ParsedAddressCreator<IPv6Address, IPv6AddressSection, ?, ?> getCreator() {
				return getIPv6AddressCreator();
			}
		};
	}
	
	private static <S extends IPAddressSegment> S createSegment(
			CharSequence addressString,
			IPVersion version,
			int val,
			int upperVal,
			boolean useFlags,
			AddressParseData parseData,
			int parsedSegIndex,
			Integer segmentPrefixLength,
			Integer mask,
			ParsedAddressCreator<?, ?, ?, S> creator) {
		if(val != upperVal) {
			return createRangeSegment(addressString, version, val, upperVal,
					useFlags, parseData, parsedSegIndex,
					segmentPrefixLength, mask, creator);
		}
		int stringVal = val;
		if(mask != null) {
			val &= mask;
		}
		S result;
		if(!useFlags) {
			result = creator.createSegment(val, val, segmentPrefixLength);
		} else {
			result = creator.createSegmentInternal(
				val,
				segmentPrefixLength,
				addressString,
				stringVal,
				parseData.getFlag(parsedSegIndex, AddressParseData.KEY_STANDARD_STR),
				parseData.getIndex(parsedSegIndex, AddressParseData.KEY_LOWER_STR_START_INDEX),
				parseData.getIndex(parsedSegIndex, AddressParseData.KEY_LOWER_STR_END_INDEX));
		}
		return result;
	}
	
	/*
	 * create an IPv6 segment by joining two IPv4 segments
	 */
	private static IPv6AddressSegment createSegment(int value1, int value2, Integer segmentPrefixLength, Integer mask,
			IPv6AddressCreator creator) {
		int value = (value1 << IPv4Address.BITS_PER_SEGMENT) | value2;
		if(mask != null) {
			value &= mask;
		}
		IPv6AddressSegment result = creator.createSegment(value, segmentPrefixLength);
		return result;
	}
	
	/*
	 * create an IPv6 segment by joining two IPv4 segments
	 */
	private static IPv6AddressSegment createSegment(
			IPv4AddressSegment one,
			IPv4AddressSegment two,
			int upperRangeLower,
			int upperRangeUpper,
			int lowerRangeLower,
			int lowerRangeUpper,
			Integer segmentPrefixLength,
			Integer mask,
			IPv6AddressCreator creator) throws IncompatibleAddressException {
		boolean hasMask = (mask != null);
		if(hasMask) {
			int maskInt = mask.intValue();
			int shift = IPv4Address.BITS_PER_SEGMENT;
			int shiftedMask = maskInt >> shift;
			upperRangeLower &= shiftedMask;
			upperRangeUpper &= shiftedMask;
			lowerRangeLower &= maskInt;
			lowerRangeUpper &= maskInt;
		}
		IPv6AddressSegment result = join(one, two, upperRangeLower, upperRangeUpper, lowerRangeLower, lowerRangeUpper, segmentPrefixLength, creator);
		if(hasMask && !result.isMaskCompatibleWithRange(mask.intValue(), segmentPrefixLength)) {
			throw new IncompatibleAddressException(result, mask, "ipaddress.error.maskMismatch");
		}
		return result;
	}
	
	private static IPv6AddressSegment join(
			IPv4AddressSegment one,
			IPv4AddressSegment two,
			int upperRangeLower,
			int upperRangeUpper,
			int lowerRangeLower,
			int lowerRangeUpper,
			Integer segmentPrefixLength,
			IPv6AddressCreator creator) throws IncompatibleAddressException {
		int shift = IPv4Address.BITS_PER_SEGMENT;
		if(upperRangeLower != upperRangeUpper) {
			//if the high segment has a range, the low segment must match the full range, 
			//otherwise it is not possible to create an equivalent IPv6 range when joining two IPv4 ranges
			if(segmentPrefixLength != null && creator.getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
				if(segmentPrefixLength > shift) {
					int lowerPrefixLength = segmentPrefixLength - shift;
					
					int fullMask = ~(~0 << shift); //allBitSize must be 6 digits at most for this shift to work per the java spec (so it must be less than 2^6 = 64)
					int networkMask = fullMask & (fullMask << (shift - lowerPrefixLength));
					int hostMask = ~networkMask & fullMask;
					lowerRangeLower &= networkMask;
					lowerRangeUpper |= hostMask;
					if(lowerRangeLower != 0 || lowerRangeUpper != IPv4Address.MAX_VALUE_PER_SEGMENT) {
						throw new IncompatibleAddressException(one, two, "ipaddress.error.invalidMixedRange");
					}
				} else {
					lowerRangeLower = 0;
					lowerRangeUpper = IPv4Address.MAX_VALUE_PER_SEGMENT;
				}
			} else if(lowerRangeLower != 0 || lowerRangeUpper != IPv4Address.MAX_VALUE_PER_SEGMENT) {
				throw new IncompatibleAddressException(one, two, "ipaddress.error.invalidMixedRange");
			}
		}
		return creator.createSegment(
				(upperRangeLower << shift) | lowerRangeLower,
				(upperRangeUpper << shift) | lowerRangeUpper,
				segmentPrefixLength);
	}
	
	private static <S extends IPAddressSegment> S createRangeSegment(
			CharSequence addressString,
			IPVersion version,
			int stringLower,
			int stringUpper,
			boolean useFlags,
			AddressParseData parseData,
			int parsedSegIndex,
			Integer segmentPrefixLength,
			Integer mask,
			ParsedAddressCreator<?, ?, ?, S> creator) {
		int lower = stringLower, upper = stringUpper;
		boolean hasMask = (mask != null);
		if(hasMask) {
			int maskInt = mask.intValue();
			lower &= maskInt;
			upper &= maskInt;
		}
		S result;
		if(!useFlags) {
			result = creator.createSegment(lower, upper, segmentPrefixLength);
		} else {
			result = creator.createSegmentInternal(
				lower,
				upper,
				segmentPrefixLength,
				addressString,
				stringLower,
				stringUpper,
				parseData.getFlag(parsedSegIndex, AddressParseData.KEY_STANDARD_STR),
				parseData.getFlag(parsedSegIndex, AddressParseData.KEY_STANDARD_RANGE_STR),
				parseData.getIndex(parsedSegIndex, AddressParseData.KEY_LOWER_STR_START_INDEX),
				parseData.getIndex(parsedSegIndex, AddressParseData.KEY_LOWER_STR_END_INDEX),
				parseData.getIndex(parsedSegIndex, AddressParseData.KEY_UPPER_STR_END_INDEX));
		}
		if(hasMask && !result.isMaskCompatibleWithRange(mask.intValue(), segmentPrefixLength)) {
			throw new IncompatibleAddressException(result, mask, "ipaddress.error.maskMismatch");
		}
		return result;
	}
	
	static IPAddress createAllAddress(
			IPVersion version,
			ParsedHostIdentifierStringQualifier qualifier,
			HostIdentifierString originator, 
			IPAddressStringParameters options) {
		int segmentCount = IPAddress.getSegmentCount(version);
		IPAddress mask = qualifier.getMask();
		if(mask != null && mask.getBlockMaskPrefixLength(true) != null) {
			mask = null;//we don't do any masking if the mask is a subnet mask, instead we just map it to the corresponding prefix length
		}
		boolean hasMask = mask != null;
		Integer prefLength = getPrefixLength(qualifier);
		if(version.isIPv4()) {
			ParsedAddressCreator<IPv4Address, IPv4AddressSection, ?, IPv4AddressSegment> creator = options.getIPv4Parameters().getNetwork().getAddressCreator();
			IPv4AddressSegment segments[] = creator.createSegmentArray(segmentCount);
			for(int i = 0; i < segmentCount; i++) {
				Integer segmentMask = hasMask ? cacheSegmentMask(mask.getSegment(i).getSegmentValue()) : null;
				segments[i] = createRangeSegment(
						null,
						version,
						0,
						IPv4Address.MAX_VALUE_PER_SEGMENT,
						false,
						null,
						i,
						getSegmentPrefixLength(i, version, qualifier),
						segmentMask,
						creator);
			}
			return creator.createAddressInternal(segments, originator, prefLength);
		} else {
			ParsedAddressCreator<IPv6Address, IPv6AddressSection, ?, IPv6AddressSegment> creator = options.getIPv6Parameters().getNetwork().getAddressCreator();
			IPv6AddressSegment segments[] = creator.createSegmentArray(segmentCount);
			for(int i = 0; i < segmentCount; i++) {
				Integer segmentMask = hasMask ? cacheSegmentMask(mask.getSegment(i).getSegmentValue()) : null;
				segments[i] = createRangeSegment(
						null,
						version,
						0,
						IPv6Address.MAX_VALUE_PER_SEGMENT,
						false,
						null,
						i,
						getSegmentPrefixLength(i, version, qualifier),
						segmentMask,
						creator);
			}
			return creator.createAddressInternal(segments, qualifier.getZone(), originator, prefLength);
		}
	}

	private static Integer getPrefixLength(ParsedHostIdentifierStringQualifier qualifier) {
		return qualifier.getEquivalentPrefixLength();
	}

	/**
	 * Across the address prefixes are:
	 * IPv6: (null):...:(null):(1 to 16):(0):...:(0)
	 * or IPv4: ...(null).(1 to 8).(0)...
	 * 
	 * @param segmentIndex
	 * @param segmentCount
	 * @param version
	 * @return
	 */
	private static Integer getSegmentPrefixLength(int segmentIndex, int bitsPerSegment, ParsedHostIdentifierStringQualifier qualifier) {
		Integer bits = getPrefixLength(qualifier);
		return ParsedAddressGrouping.getSegmentPrefixLength(bitsPerSegment, bits, segmentIndex);
	}
	
	/**
	 * Across the address prefixes are:
	 * IPv6: (null):...:(null):(1 to 16):(0):...:(0)
	 * or IPv4: ...(null).(1 to 8).(0)...
	 * 
	 * @param segmentIndex
	 * @param segmentCount
	 * @param version
	 * @return
	 */
	private static Integer getSegmentPrefixLength(int segmentIndex, IPVersion version, ParsedHostIdentifierStringQualifier qualifier) {
		return getSegmentPrefixLength(segmentIndex, IPAddressSection.bitsPerSegment(version), qualifier);
	}
	
	private static Integer cacheSegmentMask(int i) {
		return ParsedAddressGrouping.cache(i);
	}
}
