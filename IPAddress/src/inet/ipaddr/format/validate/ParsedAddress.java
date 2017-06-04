package inet.ipaddr.format.validate;

import java.io.Serializable;

import inet.ipaddr.HostName;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressSection;
import inet.ipaddr.IPAddressSegment;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.IPAddressTypeException;
import inet.ipaddr.IPAddressTypeNetwork.IPAddressSegmentCreator;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv4.IPv4AddressNetwork;
import inet.ipaddr.ipv4.IPv4AddressNetwork.IPv4AddressCreator;
import inet.ipaddr.ipv4.IPv4AddressSection;
import inet.ipaddr.ipv4.IPv4AddressSegment;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.ipv6.IPv6AddressNetwork;
import inet.ipaddr.ipv6.IPv6AddressNetwork.IPv6AddressCreator;
import inet.ipaddr.ipv6.IPv6AddressSection;
import inet.ipaddr.ipv6.IPv6AddressSegment;

/**
 * The result from parsing a valid address string.  This can be converted into an {@link IPv4Address} or {@link IPv6Address} instance.
 * 
 * @author sfoley
 *
 */
class ParsedAddress implements Serializable {

	private static final long serialVersionUID = 1L;
	
	/**
	 * Stores the data from a parsed address.  This data can later be translated into {@link IPv4Address} or {@link IPv6Address} objects.
	 * @author sfoley
	 *
	 */
	static class ParseData implements Serializable {
	
		private static final long serialVersionUID = 1L;

		public static final int LOWER_INDEX = 0, UPPER_INDEX = 1;
		
		public static final int LOWER_RADIX_INDEX = 0, UPPER_RADIX_INDEX = 1,
				LOWER_STR_DIGITS_INDEX = 2, LOWER_STR_START_INDEX = 3, LOWER_STR_END_INDEX = 4,
				UPPER_STR_DIGITS_INDEX = 5, UPPER_STR_START_INDEX = 6, UPPER_STR_END_INDEX = 7;
		
		public static final int WILDCARD_INDEX = 0, SINGLE_WILDCARD_INDEX = 1, STANDARD_STR_INDEX = 2, STANDARD_RANGE_STR_INDEX = 3;
		
		boolean flags[][];
		int indices[][];
		long values[][];
		
		int segmentCount;
		int addressEndIndex;
		int consecutiveIPv6SepIndex = -1;
		int qualifierIndex = -1;
		
		boolean anyWildcard;
		boolean isEmpty, isAll;
		boolean isPrefixed, isZoned;
		
		IPVersion ipVersion;
		ParsedAddress mixedParsedAddress;
		
		void initSegmentData(int segmentCapacity) {
			flags = new boolean[segmentCapacity][STANDARD_RANGE_STR_INDEX + 1];
			indices = new int[segmentCapacity][UPPER_STR_END_INDEX + 1];
			values = new long[segmentCapacity][UPPER_INDEX + 1];
		}
		
		boolean isCompressed() {
			return consecutiveIPv6SepIndex >= 0;
		}
		
		boolean isCompressed(int index) {
			int inds[] = indices[index];
			int strLength = inds[ParseData.LOWER_STR_END_INDEX] - inds[ParseData.LOWER_STR_START_INDEX];
			return strLength == 0;
		}
		
		boolean isWildcard(int index) {
			boolean flgs[] = flags[index];
			return flgs[ParseData.WILDCARD_INDEX];
		}
	};
	
	static class CachedIPAddresses<T extends IPAddress> implements Serializable {
		
		private static final long serialVersionUID = 1L;
		
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
		
		private static final long serialVersionUID = 1L;
		
		private final R section, hostSection; //1.2.3.4 for the string 1.2.3.4/16

		IPAddresses(R section, R hostSection) {
			this.section = section;
			this.hostSection = hostSection;
		}
		
		abstract ParsedAddressCreator<T, R, ?> getCreator();
		
		public T getAddress() {
			if(address == null) {
				address = getCreator().createAddressInternal(getSection(), qualifier.getZone(), fromString, fromHost);
			}
			return address;
		}
		
		public T getHostAddress() {
			if(hostSection == null) {
				return getAddress();
			}
			if(hostAddress == null) {
				hostAddress = getCreator().createAddressInternal(getHostSection(), qualifier.getZone(), null, null);
			}
			return hostAddress;
		}
		
		private R getSection() {
			return section;
		}
		
		private R getHostSection() {
			if(hostSection == null) {
				return getSection();
			}
			return hostSection;
		}
	}
	
	private final IPVersion ipVersion; //the version, either IPv4 or IPv6.
	private final ParsedAddressQualifier qualifier;
	private final String addressString;
	private final IPAddressString fromString;
	private HostName fromHost;
	private final ParseData parseData;
	
	ParsedAddress(HostName fromHost, IPAddressString fromString, String addressString, ParseData parseData, IPVersion ipVersion, ParsedAddressQualifier qualifier) {
		this.ipVersion = ipVersion;
		this.parseData = parseData;
		this.qualifier = qualifier;
		this.addressString = addressString;
		this.fromString = fromString;
		this.fromHost = fromHost;
	}

	IPVersion getIPVersion() {
		return ipVersion;
	}
	
	boolean isMixedIPv6() {
		return parseData.mixedParsedAddress != null;
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
			IPAddressSegmentCreator<S> creator,
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
		int segmentCount = parseData.segmentCount;
		IPv4AddressCreator creator = getIPv4AddressCreator();
		int ipv4SegmentCount = IPv4Address.SEGMENT_COUNT;
		int missingCount = ipv4SegmentCount - segmentCount;
		IPv4AddressSegment hostSegments[] = null;
		IPv4AddressSegment segments[] = creator.createSegmentArray(ipv4SegmentCount);
		boolean expandedSegments = (missingCount <= 0);
		for(int i = 0, normalizedSegmentIndex = 0; i < segmentCount; i++, normalizedSegmentIndex++) {
			long vals[] = parseData.values[i];
			boolean flags[] = parseData.flags[i];
			int indices[] = parseData.indices[i];
			long lower = vals[ParseData.LOWER_INDEX];
			long upper = vals[ParseData.UPPER_INDEX];
			
			//handle inet_aton style joined segments
			if(!expandedSegments && i == segmentCount - 1 && !parseData.isWildcard(i)) {
				int count = missingCount;
				boolean previousAdjustedWasRange = false;
				while(count >= 0) { //add the missing segments
					Integer currentPrefix = getSegmentPrefixLength(normalizedSegmentIndex, IPv4Address.BITS_PER_SEGMENT, qualifier);
					int newLower, newUpper;
					boolean segFlags[] = flags;
					if(lower != upper) {
						//adjustedSegment = null;
						int shift = IPv4Address.BITS_PER_SEGMENT * count;
						int segmentMask = IPv4Address.MAX_VALUE_PER_SEGMENT;
						newLower = (int) (lower >> shift) & segmentMask;
						newUpper = (int) (upper >> shift) & segmentMask;
						boolean isStillRange = newLower != newUpper;
						if(currentPrefix != null) {
							IPv4AddressNetwork network = IPv4Address.network();
							int segMask = network.getSegmentNetworkMask(currentPrefix);
							newLower &= segMask;
							int upperMask = network.getSegmentHostMask(currentPrefix);
							newUpper |= upperMask;
						}
						if(previousAdjustedWasRange && newUpper - newLower != IPv4Address.MAX_VALUE_PER_SEGMENT) {
							//any range extending into upper segments must have full range in lower segments
							//otherwise there is no way for us to represent the address
							//so we need to check whether the lower parts cover the full range
							//eg cannot represent 0.0.0x100-0x10f or 0.0.1-1ff, but can do 0.0.0x100-0x1ff or 0.0.0-1ff
							throw new IPAddressTypeException(addressString, "ipaddress.error.invalid.joined.ranges");
						}
						if(isStillRange) {
							previousAdjustedWasRange = true;
							//we may be able to reuse our strings on the final segment
							//for previous segments, strings can be reused only when the value is 0, which we do not need to cache.  Any other value changes when shifted.  
							if(count == 0 && newLower == lower) {
								if(newUpper != upper) {
									segFlags[ParseData.STANDARD_RANGE_STR_INDEX] = false;
								}
							} else {
								segFlags = null;
							}
						} else {
							if(count == 0 && newLower == lower) {
								segFlags[ParseData.STANDARD_RANGE_STR_INDEX] = false;
							} else {
								segFlags = null;
							}
						}
					} else {
						newLower = newUpper = (int) (lower >> (IPv4Address.BITS_PER_SEGMENT * count)) & IPv4Address.MAX_VALUE_PER_SEGMENT;
						if(count != 0 || newLower != lower) {
							segFlags = null;
						}
					}
					Integer segmentMask = mask == null ? null : mask.getSegment(normalizedSegmentIndex).getLowerSegmentValue();
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
			Integer segmentPrefixLength = getSegmentPrefixLength(normalizedSegmentIndex, IPv4Address.BITS_PER_SEGMENT, qualifier);
			Integer segmentMask = mask == null ? null : mask.getSegment(normalizedSegmentIndex).getLowerSegmentValue();
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
			if(!expandedSegments) {
				//check for any missing segments that we should account for here
				if(parseData.isWildcard(i)) {
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
							segmentMask = mask == null ? null : mask.getSegment(normalizedSegmentIndex).getLowerSegmentValue();
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
		}
		
		ParsedAddressCreator<?, IPv4AddressSection, IPv4AddressSegment> addressCreator = creator;
		IPv4AddressSection result = addressCreator.createSectionInternal(segments);
		IPv4AddressSection hostResult;
		if(hostSegments != null) {
			hostResult = addressCreator.createSectionInternal(hostSegments);
		} else {
			hostResult = null;
		}
		return new IPAddresses<IPv4Address, IPv4AddressSection>(result, hostResult) {
			
			@Override
			ParsedAddressCreator<IPv4Address, IPv4AddressSection, ?> getCreator() {
				return getIPv4AddressCreator();
			}
		};
	}
	
	@SuppressWarnings("serial")
	IPAddresses<IPv6Address, IPv6AddressSection> createIPv6Addresses()  {
		IPAddress mask = qualifier.getMask();
		int segmentCount = parseData.segmentCount;
		IPv6AddressCreator creator = getIPv6AddressCreator();
		int ipv6SegmentCount = IPv6Address.SEGMENT_COUNT;
		IPv6AddressSegment hostSegments[] = null;
		IPv6AddressSegment segments[] = creator.createSegmentArray(ipv6SegmentCount);
		boolean mixed = isMixedIPv6();
		int normalizedSegmentIndex = 0;
		int missingSegmentCount = (mixed ? IPv6Address.MIXED_ORIGINAL_SEGMENT_COUNT : IPv6Address.SEGMENT_COUNT) - segmentCount;
		boolean expandedSegments = (missingSegmentCount <= 0);
		//get the segments for IPv6
		for(int i = 0; i < segmentCount; i++) {
			long vals[] = parseData.values[i];
			boolean flags[] = parseData.flags[i];
			int indices[] = parseData.indices[i];
			long lower = vals[ParseData.LOWER_INDEX];
			long upper = vals[ParseData.UPPER_INDEX];
			Integer segmentMask = mask == null ? null : mask.getSegment(normalizedSegmentIndex).getLowerSegmentValue();
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
						segmentMask = mask == null ? null : mask.getSegment(normalizedSegmentIndex).getLowerSegmentValue();
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
		IPv6AddressSection result, hostResult = null;
		ParsedAddressCreator<?, IPv6AddressSection, IPv6AddressSegment> addressCreator = creator;
		if(mixed) {
			IPv4AddressSection ipv4AddressSection = parseData.mixedParsedAddress.createIPv4Addresses().getSection();
			boolean embeddedSectionIsChanged = false;
			for(int n = 0; n < 2; n++) {
				int m = n << 1;
				IPv4AddressSegment one = ipv4AddressSection.getSegment(m);
				IPv4AddressSegment two = ipv4AddressSection.getSegment(m + 1);
				Integer segmentMask = mask == null ? null : mask.getSegment(normalizedSegmentIndex).getLowerSegmentValue();
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
						hostSegments[normalizedSegmentIndex] = createSegment(oneLower, twoLower, null, null);
					}
					segments[normalizedSegmentIndex] = newSegment = createSegment(
							oneLower,
							twoLower,
							segmentPrefixLength,
							segmentMask);
				} else {
					int oneUpper = one.getUpperSegmentValue();
					int twoUpper = two.getUpperSegmentValue();
					if(doHostSegment) {
						hostSegments[normalizedSegmentIndex] = createSegment(one, two, oneLower, oneUpper, twoLower, twoUpper, null, null);
					}
					segments[normalizedSegmentIndex] = newSegment = createSegment(// this can throw IPAddressTypeException
							one, 
							two,
							oneLower,
							oneUpper,
							twoLower,
							twoUpper,
							segmentPrefixLength,
							segmentMask);
				}
				embeddedSectionIsChanged |= newSegment.isPrefixed() || /* parseData.mixedParsedAddress is never prefixed */ 
						newSegment.getLowerSegmentValue() != ((one.getLowerSegmentValue() << IPv4Address.BITS_PER_SEGMENT) | two.getLowerSegmentValue()) ||
						newSegment.getUpperSegmentValue() != ((one.getUpperSegmentValue() << IPv4Address.BITS_PER_SEGMENT) | two.getUpperSegmentValue());
				normalizedSegmentIndex++;
			}
			if(embeddedSectionIsChanged) {
				if(hostSegments != null) {
					hostResult = addressCreator.createSectionInternal(hostSegments);
				}
				result = addressCreator.createSectionInternal(segments);
			} else {
				if(hostSegments != null) {
					hostResult = addressCreator.createSectionInternal(hostSegments, ipv4AddressSection);
				}
				result = addressCreator.createSectionInternal(segments, ipv4AddressSection);
			}
		} else {
			if(hostSegments != null) {
				hostResult = addressCreator.createSectionInternal(hostSegments);
			}
			result = addressCreator.createSectionInternal(segments);
		}
		return new IPAddresses<IPv6Address, IPv6AddressSection>(result, hostResult) {
			
			@Override
			ParsedAddressCreator<IPv6Address, IPv6AddressSection, ?> getCreator() {
				return getIPv6AddressCreator();
			}
		};
	} //end createValue
	
	//if val is null, range cannot be null
	private static <S extends IPAddressSegment> S createSegment(
			String addressString,
			IPVersion version,
			int val,
			int upperVal,
			boolean flags[],
			int indices[],
			Integer segmentPrefixLength,
			Integer mask,
			ParsedAddressCreator<?, ?, S> creator) {
		if(val != upperVal) { //val is null if the segment has a range so it could not be parsed to a single value
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
				flags[ParseData.STANDARD_STR_INDEX],
				indices[ParseData.LOWER_STR_START_INDEX],
				indices[ParseData.LOWER_STR_END_INDEX]);
		}
		return result;
	}
	
	/*
	 * create an IPv6 segment by joining two IPv4 segments
	 */
	private static IPv6AddressSegment createSegment(int value1, int value2, Integer segmentPrefixLength, Integer mask) {
		int value = (value1 << IPv4Address.BITS_PER_SEGMENT) | value2;
		if(mask != null) {
			value &= mask;
		}
		IPv6AddressSegment result = getIPv6AddressCreator().createSegment(value, segmentPrefixLength);
		return result;
	}
	
	/*
	 * create an IPv6 segment by joining two IPv4 segments
	 */
	private static IPv6AddressSegment createSegment(IPv4AddressSegment one, IPv4AddressSegment two, int upperRangeLower, int upperRangeUpper, int lowerRangeLower, int lowerRangeUpper, Integer segmentPrefixLength, Integer mask) throws IPAddressTypeException {
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
		IPv6AddressSegment result = IPv6AddressSegment.join(one, two, upperRangeLower, upperRangeUpper, lowerRangeLower, lowerRangeUpper, segmentPrefixLength);
		if(hasMask && !result.isMaskCompatibleWithRange(mask.intValue(), segmentPrefixLength)) {
			throw new IPAddressTypeException(result, mask, "ipaddress.error.maskMismatch");
		}
		return result;
	}
	
	private static <S extends IPAddressSegment> S createRangeSegment(
			String addressString,
			IPVersion version,
			int stringLower,
			int stringUpper,
			boolean flags[],
			int indices[],
			Integer segmentPrefixLength,
			Integer mask,
			ParsedAddressCreator<?, ?, S> creator) {
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
				flags[ParseData.STANDARD_STR_INDEX],
				flags[ParseData.STANDARD_RANGE_STR_INDEX],
				indices[ParseData.LOWER_STR_START_INDEX],
				indices[ParseData.LOWER_STR_END_INDEX],
				indices[ParseData.UPPER_STR_END_INDEX]);
		}
		if(hasMask && !result.isMaskCompatibleWithRange(mask.intValue(), segmentPrefixLength)) {
			throw new IPAddressTypeException(result, mask, "ipaddress.error.maskMismatch");
		}
		return result;
	}
	
	static IPAddress createAllAddress(IPVersion version, ParsedAddressQualifier qualifier, HostName fromHost, IPAddressString fromString) {
		int segmentCount = IPAddress.segmentCount(version);
		IPAddress mask = qualifier.getMask();
		boolean hasMask = mask != null;
		if(version.isIPv4()) {
			ParsedAddressCreator<IPv4Address, IPv4AddressSection, IPv4AddressSegment> creator = getIPv4AddressCreator();
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
			return creator.createAddressInternal(segments, null, fromString, fromHost);
		} else {
			ParsedAddressCreator<IPv6Address, IPv6AddressSection, IPv6AddressSegment> creator = getIPv6AddressCreator();
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
			return creator.createAddressInternal(segments, qualifier.getZone(), fromString, fromHost);
		}
	}
	

	private static IPv6AddressCreator getIPv6AddressCreator() {
		IPv6AddressNetwork network = IPv6Address.network();
		return network.getAddressCreator();
	}
	
	private static IPv4AddressCreator getIPv4AddressCreator() {
		IPv4AddressNetwork network = IPv4Address.network();
		return network.getAddressCreator();
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
	private static Integer getSegmentPrefixLength(int segmentIndex, int bitsPerSegment, ParsedAddressQualifier qualifier) {
		IPAddress mask = qualifier.getMask();
		Integer networkPrefixLength = qualifier.getNetworkPrefixLength();
		//note that either mask or networkPrefixLength is non-null but not both
		Integer bits = mask != null ? mask.getMaskPrefixLength(true) : networkPrefixLength; //note that the result of mask.getMaskPrefixLength(true) is cached inside IPAddressSection
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
	private static Integer getSegmentPrefixLength(int segmentIndex, IPVersion version, ParsedAddressQualifier qualifier) {
		return getSegmentPrefixLength(segmentIndex, IPAddressSection.bitsPerSegment(version), qualifier);
	}
	
	@Override
	public String toString() {
		return addressString;
	}
}
