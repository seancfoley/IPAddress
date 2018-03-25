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

import java.io.Serializable;
import java.math.BigInteger;

import inet.ipaddr.AddressNetwork.AddressSegmentCreator;
import inet.ipaddr.IncompatibleAddressException;
import inet.ipaddr.HostIdentifierString;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressSection;
import inet.ipaddr.IPAddressSegment;
import inet.ipaddr.IPAddressStringParameters;
import inet.ipaddr.MACAddressString;
import inet.ipaddr.format.validate.ParsedMACAddress.MACAddressParseData.MACFormat;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv4.IPv4AddressNetwork.IPv4AddressCreator;
import inet.ipaddr.ipv4.IPv4AddressSection;
import inet.ipaddr.ipv4.IPv4AddressSegment;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.ipv6.IPv6AddressNetwork.IPv6AddressCreator;
import inet.ipaddr.ipv6.IPv6AddressSection;
import inet.ipaddr.ipv6.IPv6AddressSegment;
import inet.ipaddr.mac.MACAddress;
import inet.ipaddr.mac.MACAddressNetwork.MACAddressCreator;
import inet.ipaddr.mac.MACAddressSection;
import inet.ipaddr.mac.MACAddressSegment;

class AddressParseData implements Serializable {
	
	private static final long serialVersionUID = 4L;

	//these are for the segment values
	public static final int LOWER_INDEX = 0, UPPER_INDEX = 1, EXTENDED_LOWER_INDEX = 2, EXTENDED_UPPER_INDEX = 3;
	
	//these are for the indices
	public static final int LOWER_RADIX_INDEX = 0, UPPER_RADIX_INDEX = 1,
			LOWER_STR_DIGITS_INDEX = 2, LOWER_STR_START_INDEX = 3, LOWER_STR_END_INDEX = 4,
			UPPER_STR_DIGITS_INDEX = 5, UPPER_STR_START_INDEX = 6, UPPER_STR_END_INDEX = 7;
	
	//these are for the flags
	public static final int WILDCARD_INDEX = 0, SINGLE_WILDCARD_INDEX = 1, STANDARD_STR_INDEX = 2, STANDARD_RANGE_STR_INDEX = 3;
	
	boolean flags[][];
	int indices[][];
	long values[][];
	
	int segmentCount;
	
	boolean anyWildcard;
	boolean isEmpty, isAll;
	boolean isSingleSegment;
	
	//these are indices into the original string used while parsing
	int consecutiveSepIndex = -1;
	int addressEndIndex;
	
	final CharSequence str;
	
	AddressParseData(CharSequence str) {
		this.str = str;
	}
	
	void initSegmentData(int segmentCapacity) {
		flags = new boolean[segmentCapacity][STANDARD_RANGE_STR_INDEX + 1];
		indices = new int[segmentCapacity][UPPER_STR_END_INDEX + 1];
		values = new long[segmentCapacity][EXTENDED_UPPER_INDEX + 1];
	}
	
	boolean isWildcard(int index) {
		return flags[index][WILDCARD_INDEX];
	}
	
	void reverseSegments() {
		int mid = segmentCount >>> 1;
		for(int i = 0, reverseIndex = segmentCount - 1; i < mid; i++, reverseIndex--) {
			boolean tmpb[] = flags[i];
			int tmpi[] = indices[i];
			long tmpl[] = values[i];
			flags[i] = flags[reverseIndex];
			indices[i] = indices[reverseIndex];
			values[i] = values[reverseIndex];
			flags[reverseIndex] = tmpb;
			indices[reverseIndex] = tmpi;
			values[reverseIndex] = tmpl;
		}
	}
	
	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("address string: ").append(str).append('\n');
		if(addressEndIndex > 0 && addressEndIndex < str.length()) {
			builder.append("address end: ").append(str.subSequence(addressEndIndex, str.length())).append('\n');
		}
		builder.append("segment count: ").append(segmentCount).append('\n');
		if(segmentCount > 0) {
			for(int i = 0; i < segmentCount; i++) {
				builder.append("segment ").append(i).append(":\n");
				boolean flags[] = this.flags[i];
				boolean isWildcard = flags[WILDCARD_INDEX];
				if(isWildcard) {
					builder.append("\tis wildcard").append('\n');
				} else {
					long values[] = this.values[i];
					long lower = values[LOWER_INDEX];
					long upper = values[UPPER_INDEX];
					long extendedUpper = values[EXTENDED_UPPER_INDEX];
					long extendedLower = values[EXTENDED_LOWER_INDEX];
					BigInteger lowerResult;
					if(extendedLower != 0) {
						BigInteger extended = BigInteger.valueOf(extendedLower);
						BigInteger shiftMore = extended.shiftLeft(Long.SIZE);
						BigInteger notExtended = BigInteger.valueOf(lower);
						lowerResult = shiftMore.or(notExtended);
						builder.append("\tvalue: ").append(lowerResult).append('\n');
						builder.append("\tvalue in hex: ").append(lowerResult.toString(16)).append('\n');
					} else {
						builder.append("\tvalue: ").append(lower).append('\n');
						builder.append("\tvalue in hex: ").append(Long.toHexString(lower)).append('\n');
						lowerResult = null;
					}
					int indices[] = this.indices[i];
					builder.append("\tstring: ").append(str.subSequence(indices[LOWER_STR_START_INDEX], indices[LOWER_STR_END_INDEX])).append('\n');
					builder.append("\tradix: ").append(indices[LOWER_RADIX_INDEX]).append('\n');
					builder.append("\tis standard: ").append(flags[STANDARD_STR_INDEX]).append('\n');
					if(extendedUpper != 0) {
						BigInteger extended = BigInteger.valueOf(extendedUpper);
						BigInteger shiftMore = extended.shiftLeft(Long.SIZE);
						BigInteger notExtended = BigInteger.valueOf(upper);
						BigInteger result = shiftMore.or(notExtended);
						if(!result.equals(lowerResult)) {
							builder.append("\tupper value: ").append(result).append('\n');
							builder.append("\tupper value in hex: ").append(result.toString(16)).append('\n');
							builder.append("\tupper string: ").append(str.subSequence(indices[UPPER_STR_START_INDEX], indices[UPPER_STR_END_INDEX])).append('\n');
							builder.append("\tupper radix: ").append(indices[UPPER_RADIX_INDEX]).append('\n');
							builder.append("\tis standard range: ").append(flags[STANDARD_RANGE_STR_INDEX]).append('\n');
						}
					} else {
						if(upper != lower) {
							builder.append("\tupper value: ").append(upper).append('\n');
							builder.append("\tupper value in hex: ").append(Long.toHexString(upper)).append('\n');
							builder.append("\tupper string: ").append(str.subSequence(indices[UPPER_STR_START_INDEX], indices[UPPER_STR_END_INDEX])).append('\n');
							builder.append("\tupper radix: ").append(indices[UPPER_RADIX_INDEX]).append('\n');
							builder.append("\tis standard range: ").append(flags[STANDARD_RANGE_STR_INDEX]).append('\n');
						}
					}
					if(flags[SINGLE_WILDCARD_INDEX]) {
						builder.append("\thas single wildcard: ").append('\n');
					}
				}
			}
			builder.append("has a wildcard segment: ").append(anyWildcard).append('\n');
			if(consecutiveSepIndex >= 0) {
				builder.append("has compressed segment(s) at character ").append(consecutiveSepIndex + 1).append('\n');
			}
			if(isSingleSegment) {
				builder.append("is single segment").append('\n');
			}
		} else if (isEmpty) {
			builder.append("is empty").append('\n');
		} else if (isAll) {
			builder.append("is all addresses").append('\n');
		}
		return builder.toString();
	}
}

class ParsedMACAddress implements Serializable {

	private static final long serialVersionUID = 4L;
	
	static class MACAddressParseData implements Serializable {
		
		private static final long serialVersionUID = 4L;
		
		final AddressParseData addressParseData;
		
		static enum MACFormat {
			DASHED(MACAddress.DASH_SEGMENT_SEPARATOR),
			COLON_DELIMITED(MACAddress.COLON_SEGMENT_SEPARATOR),
			DOTTED(MACAddress.DOTTED_SEGMENT_SEPARATOR),
			SPACE_DELIMITED(MACAddress.SPACE_SEGMENT_SEPARATOR);
			
			private char separator;
			
			MACFormat(char separator) {
				this.separator = separator;
			}
			
			char getSeparator() {
				return separator;
			}
			
			@Override
			public String toString() {
				StringBuilder builder = new StringBuilder();
				builder.append("mac format:").append(super.toString()).append('\n');
				builder.append("segment separator:").append(separator).append('\n');
				return builder.toString();
			}
		};
		
		boolean isDoubleSegment;
		boolean isExtended;
		
		MACFormat format;
		
		MACAddressParseData(CharSequence str) {
			addressParseData = new AddressParseData(str);
		}
		
		void initSegmentData(int segmentCapacity) {
			addressParseData.initSegmentData(segmentCapacity);
		}
		
		boolean isWildcard(int index) {
			return addressParseData.isWildcard(index);
		}
		
		@Override
		public String toString() {
			StringBuilder builder = new StringBuilder();
			builder.append(addressParseData);
			if(isDoubleSegment) {
				builder.append("is double segment").append('\n');
			}
			builder.append("bit length:").append(isExtended ? 64 : 48).append('\n');
			if(format != null) {
				builder.append(format);
			}
			return builder.toString();
		}
	};
	
	private final String addressString;
	private final MACAddressString originator;
	private final MACAddressParseData parseData;
	
	ParsedMACAddress(
			MACAddressString from, 
			String addressString,
			MACAddressParseData parseData) {
		this.parseData = parseData;
		this.addressString = addressString;
		this.originator = from;
	}

	private MACAddressCreator getMACAddressCreator() {
		return originator.getValidationOptions().getNetwork().getAddressCreator();
	}

	MACAddress createAddress()  {
		ParsedAddressCreator<? extends MACAddress, MACAddressSection, ?, ?> creator = getMACAddressCreator();
		return creator.createAddressInternal(createSection(), originator);
	}

	private MACAddressSection createSection()  {
		AddressParseData addressParseData = parseData.addressParseData;
		int actualInitialSegmentCount = addressParseData.segmentCount;
		MACAddressCreator creator = getMACAddressCreator();
		MACFormat format = parseData.format;
		
		int finalSegmentCount, initialSegmentCount;
		if(format == null) {
			initialSegmentCount = finalSegmentCount = 
					parseData.isExtended ? MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT : MACAddress.MEDIA_ACCESS_CONTROL_SEGMENT_COUNT;
		} else if(format == MACFormat.DOTTED) {
			initialSegmentCount = parseData.isExtended ? MACAddress.MEDIA_ACCESS_CONTROL_DOTTED_64_SEGMENT_COUNT : MACAddress.MEDIA_ACCESS_CONTROL_DOTTED_SEGMENT_COUNT;
			if(actualInitialSegmentCount <= MACAddress.MEDIA_ACCESS_CONTROL_DOTTED_SEGMENT_COUNT && !parseData.isExtended) {
				finalSegmentCount = MACAddress.MEDIA_ACCESS_CONTROL_SEGMENT_COUNT;
			} else {
				finalSegmentCount = MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT;
			}
		} else {
			if(addressParseData.isSingleSegment || parseData.isDoubleSegment) {
				finalSegmentCount = parseData.isExtended ? MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT : MACAddress.MEDIA_ACCESS_CONTROL_SEGMENT_COUNT;
			} else if(actualInitialSegmentCount <= MACAddress.MEDIA_ACCESS_CONTROL_SEGMENT_COUNT && !parseData.isExtended) {
				finalSegmentCount = MACAddress.MEDIA_ACCESS_CONTROL_SEGMENT_COUNT;
			} else {
				finalSegmentCount = MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT;
			}
			initialSegmentCount = finalSegmentCount;
		}
		int missingCount = initialSegmentCount - actualInitialSegmentCount;
		boolean expandedSegments = (missingCount <= 0);
		MACAddressSegment segments[] = creator.createSegmentArray(finalSegmentCount);
		for(int i = 0, normalizedSegmentIndex = 0; i < actualInitialSegmentCount; i++) {
			long vals[] = addressParseData.values[i];
			boolean flags[] = addressParseData.flags[i];
			int indices[] = addressParseData.indices[i];
			long lower = vals[AddressParseData.LOWER_INDEX];
			long upper = vals[AddressParseData.UPPER_INDEX];
			if(format == MACFormat.DOTTED) {//aaa.bbb.ccc.ddd
				//aabb is becoming aa.bb
				int lowerHalfLower = (((int) lower) >>> 8);
				int lowerHalfUpper = (((int) upper) >>> 8);
				int adjustedLower2 = ((int) lower) & 0xff;
				int adjustedUpper2 = ((int) upper) & 0xff;
				if(lowerHalfLower != lowerHalfUpper && adjustedUpper2 - adjustedLower2 != 0xff) {
					throw new IncompatibleAddressException(addressString, "ipaddress.error.invalid.joined.ranges");
				}
				segments[normalizedSegmentIndex++] = createSegment(
						addressString,
						lowerHalfLower,
						lowerHalfUpper,
						null,
						null,
						creator);
				segments[normalizedSegmentIndex] = createSegment(
						addressString,
						adjustedLower2,
						adjustedUpper2,
						null,
						null,
						creator);
			} else {
				if(addressParseData.isSingleSegment || parseData.isDoubleSegment) {
					int count = (i == actualInitialSegmentCount - 1) ? missingCount : (MACAddress.ORGANIZATIONAL_UNIQUE_IDENTIFIER_SEGMENT_COUNT - 1);
					missingCount -= count;
					boolean isRange = (lower != upper);
					boolean previousAdjustedWasRange = false;
					while(count >= 0) { //add the missing segments
						int newLower, newUpper;
						boolean segFlags[] = flags;
						if(isRange) {
							int segmentMask = MACAddress.MAX_VALUE_PER_SEGMENT;
							int shift = count << 3;
							newLower = (int) (lower >>> shift) & segmentMask;
							newUpper = (int) (upper >>> shift) & segmentMask;
							if(previousAdjustedWasRange && newUpper - newLower != MACAddress.MAX_VALUE_PER_SEGMENT) {
								//any range extending into upper segments must have full range in lower segments
								//otherwise there is no way for us to represent the address
								//so we need to check whether the lower parts cover the full range
								//eg cannot represent 0.0.0x100-0x10f or 0.0.1-1ff, but can do 0.0.0x100-0x1ff or 0.0.0-1ff
								throw new IncompatibleAddressException(addressString, "ipaddress.error.invalid.joined.ranges");
							}
							previousAdjustedWasRange = newLower != newUpper;
							
							//we may be able to reuse our strings on the final segment
							//for previous segments, strings can be reused only when the value is 0, which we do not need to cache.  Any other value changes when shifted.  
							if(count == 0 && newLower == lower) {
								if(newUpper != upper) {
									segFlags[AddressParseData.STANDARD_RANGE_STR_INDEX] = false;
								}
							} else {
								segFlags = null;
							}
						} else {
							newLower = newUpper = (int) (lower >> (count << 3)) & MACAddress.MAX_VALUE_PER_SEGMENT;
							if(count != 0 || newLower != lower) {
								segFlags = null;
							}
						}
						segments[normalizedSegmentIndex] = createSegment(
							addressString,
							newLower,
							newUpper,
							segFlags,
							indices,
							creator);
						++normalizedSegmentIndex;
						count--;
					}
					//break;
					continue;
				} //end joined segments
				segments[normalizedSegmentIndex] = createSegment(
						addressString,
						(int) lower,
						(int) upper,
						flags,
						indices,
						creator);
			}
			if(!expandedSegments) {
				//check for any missing segments that we should account for here
				if(parseData.isWildcard(i)) {
					boolean expandSegments = true;
					for(int j = i + 1; j < actualInitialSegmentCount; j++) {
						if(parseData.isWildcard(j)) {//another wildcard further down
							expandSegments = false;
							break;
						}
					}
					if(expandSegments) {
						expandedSegments = true;
						int count = missingCount;
						while(count-- > 0) { //add the missing segments
							if(format == MACFormat.DOTTED) {
								MACAddressSegment seg = createSegment(
										addressString,
										0,
										MACAddress.MAX_VALUE_PER_SEGMENT,
										null,
										null,
										creator);
								segments[++normalizedSegmentIndex] = seg;
								segments[++normalizedSegmentIndex] = seg;
							} else {
								segments[++normalizedSegmentIndex] = createSegment(
									addressString,
									0,
									MACAddress.MAX_VALUE_PER_SEGMENT,
									null,
									null,
									creator);
							}
						}
					}
				}
			}
			normalizedSegmentIndex++;
		}
		ParsedAddressCreator<?, MACAddressSection, ?, MACAddressSegment> addressCreator = creator;
		MACAddressSection result = addressCreator.createSectionInternal(segments);
		return result;
	}
		
	private static <S extends MACAddressSegment> S createSegment(
			String addressString,
			int val,
			int upperVal,
			boolean flags[],
			int indices[],
			ParsedAddressCreator<?, ?, ?, S> creator) {
		if(val != upperVal) {
			return createRangeSegment(addressString, val, upperVal, flags, indices, creator);
		}
		S result;
		if(flags == null) {
			result = creator.createSegment(val, val, null);
		} else {
			result = creator.createSegmentInternal(
				val,
				null,//prefix length
				addressString,
				val,
				flags[AddressParseData.STANDARD_STR_INDEX],
				indices[AddressParseData.LOWER_STR_START_INDEX],
				indices[AddressParseData.LOWER_STR_END_INDEX]);
		}
		return result;
	}
	
	private static <S extends MACAddressSegment> S createRangeSegment(
			String addressString,
			int lower,
			int upper,
			boolean flags[],
			int indices[],
			ParsedAddressCreator<?, ?, ?, S> creator) {
		S result;
		if(flags == null) {
			result = creator.createSegment(lower, upper, null);
		} else {
			result = creator.createSegmentInternal(
				lower,
				upper,
				null,
				addressString,
				lower,
				upper,
				flags[AddressParseData.STANDARD_STR_INDEX],
				flags[AddressParseData.STANDARD_RANGE_STR_INDEX],
				indices[AddressParseData.LOWER_STR_START_INDEX],
				indices[AddressParseData.LOWER_STR_END_INDEX],
				indices[AddressParseData.UPPER_STR_END_INDEX]);
		}
		return result;
	}
}

/**
 * The result from parsing a valid address string.  This can be converted into an {@link IPv4Address} or {@link IPv6Address} instance.
 * 
 * @author sfoley
 *
 */
class ParsedIPAddress implements Serializable {

	private static final long serialVersionUID = 4L;
	
	/**
	 * Stores the data from a parsed address.  This data can later be translated into {@link IPv4Address} or {@link IPv6Address} objects.
	 * @author sfoley
	 *
	 */
	static class IPAddressParseData implements Serializable {
	
		private static final long serialVersionUID = 4L;
		
		AddressParseData addressParseData;
		
		int qualifierIndex = -1;
		
		boolean isPrefixed, isZoned;
		
		IPVersion ipVersion;
		
		boolean is_inet_aton_joined;
		ParsedIPAddress mixedParsedAddress;
	
		boolean isBase85, isBase85Zoned;
		
		IPAddressParseData(CharSequence str) {
			addressParseData = new AddressParseData(str);
		}
		
		void initSegmentData(int segmentCapacity) {
			addressParseData.initSegmentData(segmentCapacity);
		}
		
		void clearQualifier() {
			qualifierIndex = -1;
			isBase85Zoned = isPrefixed = isZoned = false;
		}

		void reverseSegments() {
			if(mixedParsedAddress != null) {
				mixedParsedAddress.reverseSegments();
			}
			addressParseData.reverseSegments();
		}
		
		boolean isCompressed() {
			return addressParseData.consecutiveSepIndex >= 0;
		}
		
		boolean isCompressed(int index) {
			int inds[] = addressParseData.indices[index];
			int end = inds[AddressParseData.UPPER_STR_END_INDEX];
			int start = inds[AddressParseData.LOWER_STR_START_INDEX];
			return start == end;
		}
		
		boolean isWildcard(int index) {
			return addressParseData.isWildcard(index);
		}
		
		boolean isMixedIPv6() {
			return mixedParsedAddress != null;
		}
		
		@Override
		public String toString() {
			StringBuilder builder = new StringBuilder();
			builder.append(addressParseData);
			builder.append("ip version: ").append(ipVersion);
			if(ipVersion.isIPv6()) {
				if(isMixedIPv6()) {
					if(isZoned) {
						builder.append(", with zone ");
						printQualifier(builder);
					}
					if(isPrefixed) {
						builder.append(", with prefix length ");
						printQualifier(builder);
					}
					builder.append(", with IPv4 embedded address: ").append('\n').append(mixedParsedAddress.parseData);
				} else {
					if(isBase85) {
						builder.append(" base 85");
						if(isBase85Zoned) {
							builder.append(", with zone ");
							printQualifier(builder);
						}
					} else {
						if(isZoned) {
							builder.append(", with zone ");
							printQualifier(builder);
						}
					}
					if(isPrefixed) {
						builder.append(", with prefix length ");
						printQualifier(builder);
					}
					builder.append('\n');
				}
			} else if(ipVersion.isIPv4()) {
				if(isPrefixed) {
					builder.append(", with prefix length  ");
					printQualifier(builder);
				}
				if(is_inet_aton_joined) {
					builder.append(", with joined segments");
				}
				builder.append('\n');
			}
			return builder.toString();
		}

		private void printQualifier(StringBuilder builder) {
			if(qualifierIndex >= 0) {//zone, prefix, or port
				CharSequence str = addressParseData.str;
				builder.append(str.subSequence(qualifierIndex, str.length()));
			} else {
				builder.append("unknown");
			}
		}
	};

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
	
	abstract class IPAddresses<T extends IPAddress, R extends IPAddressSection> extends CachedIPAddresses<T>  {

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
				address = getCreator().createAddressInternal(section, qualifier.getZone(), originator);
			}
			return address;
		}
		
		@Override
		public T getHostAddress() {
			if(hostSection == null) {
				return getAddress();
			}
			if(hostAddress == null) {
				hostAddress = getCreator().createAddressInternal(hostSection, qualifier.getZone(), null);
			}
			return hostAddress;
		}
		
		R getSection() {
			return section;
		}
	}
	
	private final IPVersion ipVersion; //the version, either IPv4 or IPv6.
	private final ParsedHostIdentifierStringQualifier qualifier;
	private final CharSequence addressString;
	final IPAddressStringParameters options;
	private final HostIdentifierString originator;
	private final IPAddressParseData parseData;
	
	ParsedIPAddress(
			HostIdentifierString from, 
			CharSequence addressString,
			IPAddressStringParameters options,
			IPAddressParseData parseData,
			IPVersion ipVersion,
			ParsedHostIdentifierStringQualifier qualifier) {
		this.ipVersion = ipVersion;
		this.parseData = parseData;
		this.qualifier = qualifier;
		this.addressString = addressString;
		this.options = options;
		this.originator = from;
	}
	
	private IPv6AddressCreator getIPv6AddressCreator() {
		return options.getIPv6Parameters().getNetwork().getAddressCreator();
	}
	
	private IPv4AddressCreator getIPv4AddressCreator() {
		return options.getIPv4Parameters().getNetwork().getAddressCreator();
	}
	
	
	void reverseSegments() {
		parseData.reverseSegments();
	}

	IPVersion getIPVersion() {
		return ipVersion;
	}
	
	boolean isMixedIPv6() {
		return parseData.isMixedIPv6();
	}
	
	boolean isBase85IPv6() {
		return parseData.isBase85;
	}
	
	boolean isIPv6() {
		return parseData.ipVersion.isIPv6();
	}
	
	boolean isIPv4() {
		return parseData.ipVersion.isIPv4();
	}
	
	Integer getNetworkPrefixLength() {
		return qualifier.getNetworkPrefixLength();
	}
	
	boolean isPrefixed() {
		return getNetworkPrefixLength() != null;
	}
	
	IPAddresses<?, ?> createAddresses()  {
		IPVersion version = ipVersion;
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
		IPAddress mask = qualifier.getMask();
		if(mask != null && mask.getBlockMaskPrefixLength(true) != null) {
			mask = null;//we don't do any masking if the mask is a subnet mask, instead we just map it to the corresponding prefix length
		}
		boolean hasMask = mask != null;
		int segmentCount = parseData.addressParseData.segmentCount;
		IPv4AddressCreator creator = getIPv4AddressCreator();
		int ipv4SegmentCount = IPv4Address.SEGMENT_COUNT;
		int missingCount = ipv4SegmentCount - segmentCount;
		IPv4AddressSegment hostSegments[] = null;
		IPv4AddressSegment segments[] = creator.createSegmentArray(ipv4SegmentCount);
		boolean expandedSegments = (missingCount <= 0);
		int expandedStart, expandedEnd;
		expandedStart = expandedEnd = -1;
		for(int i = 0, normalizedSegmentIndex = 0; i < segmentCount; i++, normalizedSegmentIndex++) {
			long vals[] = parseData.addressParseData.values[i];
			boolean flags[] = parseData.addressParseData.flags[i];
			int indices[] = parseData.addressParseData.indices[i];
			long lower = vals[AddressParseData.LOWER_INDEX];
			long upper = vals[AddressParseData.UPPER_INDEX];
			
			//handle inet_aton style joined segments
			boolean isLastSegment = i == segmentCount - 1;
			if(!expandedSegments && isLastSegment && !parseData.isWildcard(i)) {
				expandedSegments = true;
				int count = missingCount;
				expandedStart = i;
				expandedEnd = i + count;
				while(count >= 0) { //add the missing segments
					Integer currentPrefix = getSegmentPrefixLength(normalizedSegmentIndex, IPv4Address.BITS_PER_SEGMENT, qualifier);
					int newLower, newUpper;
					boolean segFlags[] = flags;
					if(lower != upper) {
						int shift = IPv4Address.BITS_PER_SEGMENT * count;
						int segmentMask = IPv4Address.MAX_VALUE_PER_SEGMENT;
						newLower = (int) (lower >>> shift) & segmentMask;
						newUpper = (int) (upper >>> shift) & segmentMask;
						//we may be able to reuse our strings on the final segment
						//for previous segments, strings can be reused only when the value is 0, which we do not need to cache.  Any other value changes when shifted.  
						if(count == 0 && newLower == lower) {
							if(newUpper != upper) {
								segFlags[AddressParseData.STANDARD_RANGE_STR_INDEX] = false;
							}
						} else {
							segFlags = null;
						}
					} else {
						newLower = newUpper = (int) (lower >> (IPv4Address.BITS_PER_SEGMENT * count)) & IPv4Address.MAX_VALUE_PER_SEGMENT;
						if(count != 0 || newLower != lower) {
							segFlags = null;
						}
					}
					Integer segmentMask = hasMask ? mask.getSegment(normalizedSegmentIndex).getLowerSegmentValue() : null;
					if(segmentMask != null || currentPrefix != null) {
						hostSegments = allocateHostSegments(hostSegments, segments, creator, ipv4SegmentCount, normalizedSegmentIndex);
						hostSegments[normalizedSegmentIndex] = createSegment(addressString, IPVersion.IPV4, newLower, newUpper, flags, indices, null, null, creator);
					}
					segments[normalizedSegmentIndex] = createSegment(
						addressString,
						IPVersion.IPV4,
						newLower,
						newUpper,
						segFlags,
						indices,
						currentPrefix,
						segmentMask,
						creator);
					++normalizedSegmentIndex;
					count--;
				}
				break;
			} //end handle inet_aton joined segments
			Integer segmentMask = hasMask ? mask.getSegment(normalizedSegmentIndex).getLowerSegmentValue() : null;
			Integer segmentPrefixLength = getSegmentPrefixLength(normalizedSegmentIndex, IPv4Address.BITS_PER_SEGMENT, qualifier);
			if(segmentMask != null || segmentPrefixLength != null) {
				hostSegments = allocateHostSegments(hostSegments, segments, creator, ipv4SegmentCount, normalizedSegmentIndex);
				hostSegments[normalizedSegmentIndex] = createSegment(addressString, IPVersion.IPV4, (int) lower, (int) upper, flags, indices, null, null, creator);
			}
			segments[normalizedSegmentIndex] = createSegment(
					addressString,
					IPVersion.IPV4,
					(int) lower,
					(int) upper,
					flags,
					indices,
					segmentPrefixLength,
					segmentMask,
					creator);
			if(!expandedSegments &&
					//check for any missing segments that we should account for here
					parseData.isWildcard(i) && (!parseData.is_inet_aton_joined || isLastSegment)) {
				boolean expandSegments = true;
				for(int j = i + 1; j < segmentCount; j++) {
					if(parseData.isWildcard(j)) {//another wildcard further down
						expandSegments = false;
						break;
					}
				}
				if(expandSegments) {
					expandedSegments = true;
					int count = missingCount;
					while(count-- > 0) { //add the missing segments
						++normalizedSegmentIndex;
						segmentMask = hasMask ?  mask.getSegment(normalizedSegmentIndex).getLowerSegmentValue() : null;
						segmentPrefixLength = getSegmentPrefixLength(normalizedSegmentIndex, IPv4Address.BITS_PER_SEGMENT, qualifier);
						if(segmentMask != null || segmentPrefixLength != null) {
							hostSegments = allocateHostSegments(hostSegments, segments, creator, ipv4SegmentCount, normalizedSegmentIndex);
							hostSegments[normalizedSegmentIndex] = createSegment(addressString, IPVersion.IPV4, (int) lower, (int) upper, flags, indices, null, null, creator);
						}
						segments[normalizedSegmentIndex] = createSegment(
							addressString,
							IPVersion.IPV4,
							0,
							IPv4Address.MAX_VALUE_PER_SEGMENT,
							null,
							null,
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
	IPAddresses<IPv6Address, IPv6AddressSection> createIPv6Addresses()  {
		IPAddress mask = qualifier.getMask();
		if(mask != null && mask.getBlockMaskPrefixLength(true) != null) {
			mask = null;//we don't do any masking if the mask is a subnet mask, instead we just map it to the corresponding prefix length
		}
		boolean hasMask = mask != null;
		int segmentCount = parseData.addressParseData.segmentCount;
		IPv6AddressCreator creator = getIPv6AddressCreator();
		int ipv6SegmentCount = IPv6Address.SEGMENT_COUNT;
		IPv6AddressSegment hostSegments[] = null;
		IPv6AddressSegment segments[] = creator.createSegmentArray(ipv6SegmentCount);
		boolean mixed = isMixedIPv6();
		int normalizedSegmentIndex = 0;
		int missingSegmentCount = (mixed ? IPv6Address.MIXED_ORIGINAL_SEGMENT_COUNT : IPv6Address.SEGMENT_COUNT) - segmentCount;
		boolean expandedSegments = (missingSegmentCount <= 0);
		int expandedStart, expandedEnd;
		expandedStart = expandedEnd = -1;
		
		//get the segments for IPv6
		for(int i = 0; i < segmentCount; i++) {
			long vals[] = parseData.addressParseData.values[i];
			boolean flags[] = parseData.addressParseData.flags[i];
			int indices[] = parseData.addressParseData.indices[i];
			long lower = vals[AddressParseData.LOWER_INDEX];
			long upper = vals[AddressParseData.UPPER_INDEX];
			
			//handle joined segments
			if(!expandedSegments && i == segmentCount - 1 && !parseData.isWildcard(i)) {
				expandedSegments = true;
				int count = missingSegmentCount;
				long lowerHighBytes, upperHighBytes;
				boolean isRange;
				if(count >= 4) {
					lowerHighBytes = vals[AddressParseData.EXTENDED_LOWER_INDEX];//the high half of the lower value
					upperHighBytes = vals[AddressParseData.EXTENDED_UPPER_INDEX];//the high half of the upper value
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
					boolean segFlags[] = flags;
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
								segFlags[AddressParseData.STANDARD_RANGE_STR_INDEX] = false;
							}
						} else {
							segFlags = null;
						}
					} else {
						if(count >= 4) {
							newLower = newUpper = (int) (lowerHighBytes >>> (IPv6Address.BITS_PER_SEGMENT * (count % 4))) & IPv6Address.MAX_VALUE_PER_SEGMENT;
							segFlags = null;
						} else {
							newLower = newUpper = (int) (lower >>> (IPv6Address.BITS_PER_SEGMENT * count)) & IPv6Address.MAX_VALUE_PER_SEGMENT;
							if(count != 0 || newLower != lower || lowerHighBytes != 0) {
								segFlags = null;
							}
						}
					}
					Integer segmentMask = hasMask ? mask.getSegment(normalizedSegmentIndex).getLowerSegmentValue() : null;
					if(segmentMask != null || currentPrefix != null) {
						hostSegments = allocateHostSegments(hostSegments, segments, creator, ipv6SegmentCount, normalizedSegmentIndex);
						hostSegments[normalizedSegmentIndex] = createSegment(addressString, IPVersion.IPV6, newLower, newUpper, segFlags, indices, null, null, creator);
					}
					segments[normalizedSegmentIndex] = createSegment(
						addressString,
						IPVersion.IPV6,
						newLower,
						newUpper,
						segFlags,
						indices,
						currentPrefix,
						segmentMask,
						creator);
					++normalizedSegmentIndex;
					count--;
				}
				break;
			} //end joined segments
			
			Integer segmentMask = hasMask ? mask.getSegment(normalizedSegmentIndex).getLowerSegmentValue() : null;
			Integer segmentPrefixLength = getSegmentPrefixLength(normalizedSegmentIndex, IPv6Address.BITS_PER_SEGMENT, qualifier);
			if(segmentMask != null || segmentPrefixLength != null) {
				hostSegments = allocateHostSegments(hostSegments, segments, creator, ipv6SegmentCount, normalizedSegmentIndex);
				hostSegments[normalizedSegmentIndex] = createSegment(addressString, IPVersion.IPV6, (int) lower, (int) upper, flags, indices, null, null, creator);
			}
			segments[normalizedSegmentIndex] = createSegment(
				addressString,
				IPVersion.IPV6,
				(int) lower,
				(int) upper,
				flags,
				indices,
				segmentPrefixLength,
				segmentMask,
				creator);
			normalizedSegmentIndex++;
			int expandValueLower = 0, expandValueUpper = 0;
			if(!expandedSegments) {
				//check for any missing segments that we should account for here
				boolean expandSegments = false;
				if(parseData.isWildcard(i)) {
					expandValueLower = 0;
					expandValueUpper = IPv6Address.MAX_VALUE_PER_SEGMENT;
					expandSegments = true;
					for(int j = i + 1; j < segmentCount; j++) {
						if(parseData.isWildcard(j) || parseData.isCompressed(j)) {//another wildcard further down
							expandSegments = false;
							break;
						}
					}
				} else {
					//compressed ipv6?
					if(parseData.isCompressed(i)) {
						expandSegments = true;
						expandValueLower = expandValueUpper = 0;
					}
				}
				//fill in missing segments
				if(expandSegments) {
					expandedSegments = true;
					int count = missingSegmentCount;
					while(count-- > 0) { //add the missing segments
						segmentMask = hasMask ? mask.getSegment(normalizedSegmentIndex).getLowerSegmentValue() : null;
						segmentPrefixLength = getSegmentPrefixLength(normalizedSegmentIndex, IPv6Address.BITS_PER_SEGMENT, qualifier);
						if(segmentMask != null || segmentPrefixLength != null) {
							hostSegments = allocateHostSegments(hostSegments, segments, creator, ipv6SegmentCount, normalizedSegmentIndex);
							hostSegments[normalizedSegmentIndex] = createSegment(addressString, IPVersion.IPV6, expandValueLower, expandValueUpper, null, null, null, null, creator);
						}
						segments[normalizedSegmentIndex] = createSegment(
								addressString,
								IPVersion.IPV6,
								expandValueLower,
								expandValueUpper,
								null,
								null,
								segmentPrefixLength,
								segmentMask,
								creator);
						normalizedSegmentIndex++;
					}
				}
			}
		}
		IPv6AddressSection result, hostResult;
		result = hostResult = null;
		ParsedAddressCreator<?, IPv6AddressSection, IPv4AddressSection, IPv6AddressSegment> addressCreator = creator;
		if(mixed) {
			IPv4AddressSection ipv4AddressSection = parseData.mixedParsedAddress.createIPv4Addresses().getSection();
			boolean embeddedSectionIsChanged = false;
			for(int n = 0; n < 2; n++) {
				int m = n << 1;
				IPv4AddressSegment one = ipv4AddressSection.getSegment(m);
				IPv4AddressSegment two = ipv4AddressSection.getSegment(m + 1);
				Integer segmentMask = hasMask ? mask.getSegment(normalizedSegmentIndex).getLowerSegmentValue() : null;
				IPv6AddressSegment newSegment;
				Integer segmentPrefixLength = getSegmentPrefixLength(normalizedSegmentIndex, IPv6Address.BITS_PER_SEGMENT, qualifier);
				boolean doHostSegment = segmentMask != null || segmentPrefixLength != null;
				if(doHostSegment) {
					hostSegments = allocateHostSegments(hostSegments, segments, creator, ipv6SegmentCount, normalizedSegmentIndex);
				}
				int oneLower = one.getLowerSegmentValue();
				int twoLower = two.getLowerSegmentValue();
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
						newSegment.getLowerSegmentValue() != ((one.getLowerSegmentValue() << IPv4Address.BITS_PER_SEGMENT) | two.getLowerSegmentValue()) ||
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
			boolean flags[],
			int indices[],
			Integer segmentPrefixLength,
			Integer mask,
			ParsedAddressCreator<?, ?, ?, S> creator) {
		if(val != upperVal) {
			return createRangeSegment(addressString, version, val, upperVal, flags, indices, segmentPrefixLength, mask, creator);
		}
		int stringVal = val;
		if(mask != null) {
			val &= mask;
		}
		S result;
		if(flags == null) {
			result = creator.createSegment(val, val, segmentPrefixLength);
		} else {
			result = creator.createSegmentInternal(
				val,
				segmentPrefixLength,
				addressString,
				stringVal,
				flags[AddressParseData.STANDARD_STR_INDEX],
				indices[AddressParseData.LOWER_STR_START_INDEX],
				indices[AddressParseData.LOWER_STR_END_INDEX]);
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
			boolean flags[],
			int indices[],
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
		if(flags == null) {
			result = creator.createSegment(lower, upper, segmentPrefixLength);
		} else {
			result = creator.createSegmentInternal(
				lower,
				upper,
				segmentPrefixLength,
				addressString,
				stringLower,
				stringUpper,
				flags[AddressParseData.STANDARD_STR_INDEX],
				flags[AddressParseData.STANDARD_RANGE_STR_INDEX],
				indices[AddressParseData.LOWER_STR_START_INDEX],
				indices[AddressParseData.LOWER_STR_END_INDEX],
				indices[AddressParseData.UPPER_STR_END_INDEX]);
		}
		if(hasMask && !result.isMaskCompatibleWithRange(mask.intValue(), segmentPrefixLength)) {
			throw new IncompatibleAddressException(result, mask, "ipaddress.error.maskMismatch");
		}
		return result;
	}
	
	static IPAddress createAllAddress(IPVersion version, ParsedHostIdentifierStringQualifier qualifier, HostIdentifierString originator, 
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
				Integer segmentMask = hasMask ? mask.getSegment(i).getLowerSegmentValue() : null;
				segments[i] = createRangeSegment(
						null,
						version,
						0,
						IPv4Address.MAX_VALUE_PER_SEGMENT,
						null,
						null,
						getSegmentPrefixLength(i, version, qualifier),
						segmentMask,
						creator);
			}
			return creator.createAddressInternal(segments, originator, prefLength);
		} else {
			ParsedAddressCreator<IPv6Address, IPv6AddressSection, ?, IPv6AddressSegment> creator = options.getIPv6Parameters().getNetwork().getAddressCreator();
			IPv6AddressSegment segments[] = creator.createSegmentArray(segmentCount);
			for(int i = 0; i < segmentCount; i++) {
				Integer segmentMask = hasMask ? mask.getSegment(i).getLowerSegmentValue() : null;
				segments[i] = createRangeSegment(
						null,
						version,
						0,
						IPv6Address.MAX_VALUE_PER_SEGMENT,
						null,
						null,
						getSegmentPrefixLength(i, version, qualifier),
						segmentMask,
						creator);
			}
			return creator.createAddressInternal(segments, qualifier.getZone(), originator, prefLength);
		}
	}

	private static Integer getPrefixLength(ParsedHostIdentifierStringQualifier qualifier) {
		IPAddress mask = qualifier.getMask();
		Integer bits = mask != null ? mask.getBlockMaskPrefixLength(true) : qualifier.getNetworkPrefixLength(); //note that the result of mask.getBlockMaskPrefixLength(true) is cached inside IPAddressSection
		return bits;
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
		IPAddress mask = qualifier.getMask();
		Integer networkPrefixLength = qualifier.getNetworkPrefixLength();
		//note that either mask or networkPrefixLength is non-null but not both
		Integer bits = mask != null ? mask.getBlockMaskPrefixLength(true) : networkPrefixLength; //note that the result of mask.getBlockMaskPrefixLength(true) is cached inside IPAddressSection
		return IPAddressSection.getSegmentPrefixLength(bitsPerSegment, bits, segmentIndex);
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
	
	@Override
	public String toString() {
		return addressString.toString();
	}
}
