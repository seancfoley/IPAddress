package inet.ipaddr.ipv4;

import java.util.ArrayList;
import java.util.Iterator;

import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressConverter.DefaultAddressConverter;
import inet.ipaddr.IPAddressSection;
import inet.ipaddr.IPAddressSection.WildcardOptions.Wildcards;
import inet.ipaddr.IPAddressTypeException;
import inet.ipaddr.format.IPAddressDivision;
import inet.ipaddr.format.IPAddressPart;
import inet.ipaddr.format.IPAddressSegmentGrouping;
import inet.ipaddr.format.util.IPAddressPartConfiguredString;
import inet.ipaddr.format.util.IPAddressPartStringCollection;
import inet.ipaddr.format.util.IPAddressPartStringParams;
import inet.ipaddr.format.util.IPAddressPartStringSubCollection;
import inet.ipaddr.ipv4.IPv4AddressNetwork.IPv4AddressCreator;
import inet.ipaddr.ipv4.IPv4AddressSection.IPv4StringCollection.IPv4AddressSectionStringCollection;
import inet.ipaddr.ipv4.IPv4AddressSection.IPv4StringCollection.IPv4StringBuilder;
import inet.ipaddr.ipv4.IPv4AddressSection.IPv4StringCollection.IPv4StringParams;
import inet.ipaddr.ipv6.IPv6Address.IPv6AddressConverter;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringBuilderOptions;

/**
 * 
 * @author sfoley
 *
 */
public class IPv4AddressSection extends IPAddressSection {

	private static final long serialVersionUID = 1L;

	private static class IPv4StringCache extends StringCache {
		//a set of pre-defined string types
		private static final StringOptions fullParams;
		private static final StringOptions canonicalParams;
		private static final StringOptions normalizedWildcardParams;
		private static final StringOptions sqlWildcardParams;
		private static final StringOptions octalParams;
		private static final StringOptions hexParams;
		
		static {
			WildcardOptions allWildcards = new WildcardOptions(WildcardOptions.WildcardOption.ALL);
			WildcardOptions allSQLWildcards = new WildcardOptions(WildcardOptions.WildcardOption.ALL, new Wildcards(IPAddress.SEGMENT_SQL_WILDCARD_STR, IPAddress.SEGMENT_SQL_SINGLE_WILDCARD_STR));
			WildcardOptions onlyNetworkWildcards = new WildcardOptions(WildcardOptions.WildcardOption.NETWORK_ONLY);
			WildcardOptions fullWildcards = new WildcardOptions(WildcardOptions.WildcardOption.NETWORK_ONLY, new Wildcards(IPAddress.RANGE_SEPARATOR_STR));
			fullParams = new StringOptions.Builder().setRadix(IPv4Address.DEFAULT_TEXTUAL_RADIX).setExpandSegments(true).setWildcardOptions(fullWildcards).toParams();
			canonicalParams = new StringOptions.Builder().setRadix(IPv4Address.DEFAULT_TEXTUAL_RADIX).setExpandSegments(false).setWildcardOptions(onlyNetworkWildcards).toParams();
			normalizedWildcardParams = new StringOptions.Builder().setRadix(IPv4Address.DEFAULT_TEXTUAL_RADIX).setExpandSegments(false).setWildcardOptions(allWildcards).toParams();
			sqlWildcardParams = new StringOptions.Builder().setRadix(IPv4Address.DEFAULT_TEXTUAL_RADIX).setExpandSegments(false).setWildcardOptions(allSQLWildcards).toParams();
			octalParams = new StringOptions.Builder().setRadix(IPv4Address.inet_aton_radix.OCTAL.getRadix()).setExpandSegments(false).setWildcardOptions(onlyNetworkWildcards).setSegmentStrPrefix(IPv4Address.inet_aton_radix.OCTAL.getSegmentStrPrefix()).toParams();
			hexParams = new StringOptions.Builder().setRadix(IPv4Address.inet_aton_radix.HEX.getRadix()).setExpandSegments(false).setWildcardOptions(onlyNetworkWildcards).setSegmentStrPrefix(IPv4Address.inet_aton_radix.HEX.getSegmentStrPrefix()).toParams();
		}
		
		public String octalString;
		public String hexString;
	}
	
	private transient IPv4StringCache stringCache;

	public IPv4AddressSection(IPv4AddressSegment[] segments, Integer networkPrefixLength) {
		this(toCIDRSegments(networkPrefixLength, segments, getIPv4SegmentCreator()), false);
	}
	
	public IPv4AddressSection(IPv4AddressSegment segments[]) {
		this(segments, true);
	}
	
	IPv4AddressSection(IPv4AddressSegment segments[], boolean cloneSegments) {
		super(segments, null, cloneSegments, false);
	}
	
	IPv4AddressSection(byte bytes[], Integer prefix, boolean cloneBytes) {
		super(toSegments(bytes, IPv4Address.SEGMENT_COUNT, IPv4Address.BYTES_PER_SEGMENT, IPv4Address.BITS_PER_SEGMENT, getIPv4SegmentCreator(), prefix), bytes, false, cloneBytes);
	}
	
	public IPv4AddressSection(byte bytes[], Integer prefix) {
		this(bytes, prefix, true);
	}
	
	public IPv4AddressSection(byte bytes[]) {
		this(bytes, null, true);
	}

	@Override
	public IPv4AddressSegment[] getLowestSegments() {
		return (IPv4AddressSegment[]) super.getLowestSegments();
	}
	
	@Override
	public IPv4AddressSegment[] getHighestSegments() {
		return (IPv4AddressSegment[]) super.getHighestSegments();
	}
	
	@Override
	public IPv4AddressSection getLowestSection() {
		return (IPv4AddressSection) super.getLowestSection();
	}
	
	@Override
	public IPv4AddressSection getHighestSection() {
		return (IPv4AddressSection) super.getHighestSection();
	}
	
	@Override
	public Iterator<IPv4AddressSection> sectionIterator() {
		return new SectionIterator<IPv4Address, IPv4AddressSection, IPv4AddressSegment>();
	}
	
	@Override
	public Iterator<IPv4AddressSegment[]> iterator() {
		return cast(super.iterator());
	}
	
	@Override
	protected IPv4AddressCreator getSegmentCreator() {
		return getIPv4SegmentCreator();
	}
	
	@Override
	protected IPv4AddressCreator getAddressCreator() {
		return getIPv4SegmentCreator();
	}
	
	private static IPv4AddressCreator getIPv4SegmentCreator() {
		return IPv4Address.network().getAddressCreator();
	}
	
	@Override
	public IPv4AddressSegment getSegment(int index) {
		return (IPv4AddressSegment) super.getSegment(index);
	}
	
	@Override
	public int getBitsPerSegment() {
		return IPv4Address.BITS_PER_SEGMENT;
	}
	
	@Override
	public int getBytesPerSegment() {
		return IPv4Address.BYTES_PER_SEGMENT;
	}
	
	@Override
	public boolean isIPv4() {
		return true;
	}
	
	@Override
	public IPVersion getIPVersion() {
		return IPVersion.IPV4;
	}
	
	@Override
	protected boolean isSameGrouping(IPAddressSegmentGrouping other) {
		return other instanceof IPv4AddressSection && super.isSameGrouping(other);
	}
	
	@Override
	public boolean equals(Object o) {
		if(o == this) {
			return true;
		}
		if(o instanceof IPv4AddressSection) {
			return super.isSameGrouping((IPv4AddressSection) o);
		}
		return false;
	}
	
	@Override
	public boolean contains(IPAddressSection other) {
		return other.isIPv4() && super.contains(other);
	}
	
	@Override
	public IPv4AddressSection[] subtract(IPAddressSection other) {
		return (IPv4AddressSection[]) super.subtract(other);
	}
	
	@Override
	public int getByteIndex(Integer networkPrefixLength) {
		return getByteIndex(networkPrefixLength, IPv4Address.BYTE_COUNT);
	}
	
	@Override
	public int getSegmentIndex(Integer networkPrefixLength) {
		return getSegmentIndex(networkPrefixLength, IPv4Address.BYTE_COUNT, IPv4Address.BYTES_PER_SEGMENT);
	}
	
	@Override
	public IPv4AddressNetwork getNetwork() {
		return IPv4Address.network();
	}
	
	@Override
	public IPv4AddressSection toSubnet(int networkPrefixLength) throws IPAddressTypeException {
		return (IPv4AddressSection) super.toSubnet(networkPrefixLength);
	}

	/**
	 * Creates a subnet address using the given mask. 
	 */
	@Override
	public IPv4AddressSection toSubnet(IPAddressSection mask) throws IPAddressTypeException {
		return toSubnet(mask, null);
	}
	
	/**
	 * Creates a subnet address using the given mask and prefix length.
	 * @param networkPrefixLength if non-null, applies the given prefix
	 */
	@Override
	public IPv4AddressSection toSubnet(IPAddressSection mask, Integer networkPrefixLength) throws IPAddressTypeException {
		return (IPv4AddressSection) super.toSubnet(mask, networkPrefixLength);
	}
	
	@Override
	public IPv4AddressSection getNetworkSection(int networkPrefixLength) {
		return getNetworkSection(networkPrefixLength, true);
	}
	
	@Override
	public IPv4AddressSection getNetworkSection(int networkPrefixLength, boolean withPrefixLength) {
		return (IPv4AddressSection) super.getNetworkSection(networkPrefixLength, withPrefixLength);
	}
	
	@Override
	public IPv4AddressSection getHostSection(int networkPrefixLength) {
		return (IPv4AddressSection) super.getHostSection(networkPrefixLength);
	}

	private boolean hasNoCache() {
		if(stringCache == null) {
			synchronized(this) {
				if(stringCache == null) {
					stringCache = new IPv4StringCache();
					return true;
				}
			}
		}
		return false;
	}
	
	/**
	 * This produces a canonical string.
	 */
	@Override
	public String toCanonicalString() {
		String result;
		if(hasNoCache() || (result = stringCache.canonicalString) == null) {
			stringCache.canonicalString = result = toNormalizedString(IPv4StringCache.canonicalParams);
		}
		return result;
	}

	/**
	 * This produces a string with no compressed segments and all segments of full length,
	 * which is 3 characters for IPv4 segments.
	 */
	@Override
	public String toFullString() {
		String result;
		if(hasNoCache() || (result = stringCache.fullString) == null) {
			stringCache.fullString = result = toNormalizedString(IPv4StringCache.fullParams);
		}
		return result;
	}
	
	/**
	 * The shortest string for IPv4 addresses is the same as the canonical string.
	 */
	@Override
	public String toCompressedString() {
		return toCanonicalString();
	}
	
	/**
	 * The normalized string returned by this method is consistent with java.net.Inet4Address,
	 * and is the same as the canonical string.
	 */
	@Override
	public String toNormalizedString() {
		return toCanonicalString();
	}
	
	@Override
	public String toCompressedWildcardString() {
		return toNormalizedWildcardString();
	}
	
	@Override
	public String toSubnetString() {
		return toNormalizedWildcardString();
	}
	
	@Override
	public String toNetworkPrefixLengthString() {
		return toCanonicalString();
	}
	
	public String toInetAtonString(IPv4Address.inet_aton_radix radix) {
		String result;
		if(radix == IPv4Address.inet_aton_radix.OCTAL) {
			if(hasNoCache() || (result = stringCache.octalString) == null) {
				stringCache.octalString = result = toNormalizedString(IPv4StringCache.octalParams);
			}
		} else if(radix == IPv4Address.inet_aton_radix.HEX) {
			if(hasNoCache() || (result = stringCache.hexString) == null) {
				stringCache.hexString = result = toNormalizedString(IPv4StringCache.hexParams);
			}
		} else {
			result = toCanonicalString();
		}
		return result;
	}
	
	public String toInetAtonString(IPv4Address.inet_aton_radix radix, int joinedCount) {
		if(joinedCount <= 0) {
			return toInetAtonString(radix);
		}
		StringOptions stringParams;
		if(radix == IPv4Address.inet_aton_radix.OCTAL) {
			stringParams = IPv4StringCache.octalParams;
		} else if(radix == IPv4Address.inet_aton_radix.HEX) {
			stringParams = IPv4StringCache.hexParams;
		} else {
			stringParams = IPv4StringCache.canonicalParams;
		}
		return toNormalizedString(stringParams, joinedCount);
	}
	
	@Override
	public String toNormalizedWildcardString() {
		String result;
		if(hasNoCache() || (result = stringCache.normalizedWildcardString) == null) {
			stringCache.normalizedWildcardString = result = toNormalizedString(IPv4StringCache.normalizedWildcardParams);
		}
		return result;
	}
	
	@Override
	public String toCanonicalWildcardString() {
		return toNormalizedWildcardString();
	}
	
	@Override
	public String toSQLWildcardString() {
		String result;
		if(hasNoCache() || (result = stringCache.sqlWildcardString) == null) {
			stringCache.sqlWildcardString = result = toNormalizedString(IPv4StringCache.sqlWildcardParams);
		}
		return result;
	}
	
	@Override
	public String toNormalizedString(StringOptions stringOptions) {
		return toNormalizedString(stringOptions, this);
	}
	
	public static String toNormalizedString(StringOptions opts, IPAddressPart section) {
		return toParams(opts).toString(section);
	}
	
	private static IPv4StringParams toParams(StringOptions opts) {
		IPv4StringParams result = new IPv4StringParams();
		result.expandSegments(opts.expandSegments);
		result.setWildcardOption(opts.wildcardOptions);
		result.setRadix(opts.base);
		result.setSegmentStrPrefix(opts.segmentStrPrefix);
		return result;
	}
	
	protected static IPAddressPartStringParams<IPAddressPart> toStringParams(StringOptions opts) {
		return toParams(opts);
	}
	
	public String toNormalizedString(StringOptions stringParams, int joinCount) {
		if(joinCount <= 0) {
			return toNormalizedString(stringParams);
		}
		int thisCount = getSegmentCount();
		if(thisCount <= 1) {
			return toNormalizedString(stringParams);
		}
		IPAddressPart equivalentPart = toJoinedSegments(joinCount);
		return toNormalizedString(stringParams, equivalentPart);
	}
	
	public IPAddressSegmentGrouping toJoinedSegments(int joinCount) {
		int thisCount = getSegmentCount();
		if(joinCount <= 0 || thisCount <=1) {
			return this;
		}
		int totalCount;
		if(joinCount >= thisCount) {
			joinCount = thisCount - 1;
			totalCount = 1;
		} else {
			totalCount = thisCount - joinCount;
		}
		int notJoinedCount = totalCount - 1;
		IPAddressDivision segs[] = new IPAddressDivision[totalCount];
		int i = 0;
		for(; i < notJoinedCount; i++) {
			segs[i] = getDivision(i);
		}
		IPv4JoinedSegments joinedSegment = joinSegments(joinCount);
		segs[notJoinedCount] = joinedSegment;
		IPAddressSegmentGrouping equivalentPart = new IPAddressSegmentGrouping(segs);
		return equivalentPart;
	}

	private IPv4JoinedSegments joinSegments(int joinCount) {
		long lower = 0, upper = 0;
		int networkPrefixLength = 0;
		Integer prefix = null;
		int firstSegIndex = 0;
		IPv4AddressSegment firstRange = null;
		int firstJoinedIndex = getSegmentCount() - 1 - joinCount;
		for(int j = 0; j <= joinCount; j++) {
			IPv4AddressSegment thisSeg = getSegment(firstJoinedIndex + j);
			if(firstRange != null) {
				if(!thisSeg.isFullRange()) {
					throw new IPAddressTypeException(firstRange, firstSegIndex, thisSeg, firstJoinedIndex + j, "ipaddress.error.segmentMismatch");
				}
			} else if(thisSeg.isMultiple()) {
				firstSegIndex = firstJoinedIndex + j;
				firstRange = thisSeg;
			}
			lower = lower << IPv4Address.BITS_PER_SEGMENT | thisSeg.getLowerSegmentValue();
			upper = upper << IPv4Address.BITS_PER_SEGMENT | thisSeg.getUpperSegmentValue();
			if(prefix == null) {
				Integer thisSegPrefix = thisSeg.getSegmentPrefixLength();
				if(thisSegPrefix != null) {
					prefix = networkPrefixLength + thisSegPrefix;
				} else {
					networkPrefixLength += thisSeg.getBitCount();
				}
			}
		}
		IPv4JoinedSegments joinedSegment = new IPv4JoinedSegments(joinCount, lower, upper, prefix);
		return joinedSegment;
	}
	
	@Override
	public IPAddressPartStringCollection toAllStringCollection() {
		return toStringCollection(IPv4StringBuilderOptions.ALL_OPTS);
	}
	
	@Override
	public IPAddressPartStringCollection toStandardStringCollection() {
		return toStringCollection(IPv4StringBuilderOptions.STANDARD_OPTS);
	}
	
	@Override
	public IPAddressPartStringCollection toDatabaseSearchStringCollection() {
		return toStringCollection(IPv4StringBuilderOptions.DATABASE_SEARCH_OPTS);
	}
	
	@Override
	public IPAddressPartStringCollection toStringCollection(IPStringBuilderOptions opts) {
		return toStringCollection(IPv4StringBuilderOptions.from(opts));
	}

	public IPAddressPartStringCollection toStringCollection(IPv4StringBuilderOptions opts) {
		IPv4SectionStringCollection collection = new IPv4SectionStringCollection();
		IPAddressPart parts[] = getParts(opts);
		for(IPAddressPart part : parts) {
			IPv4StringBuilder builder = new IPv4StringBuilder(part, opts, new IPv4AddressSectionStringCollection(part));
			IPv4AddressSectionStringCollection subCollection = builder.getVariations();
			collection.add(subCollection);
		}
		return collection;
	}
	
	@Override
	public IPAddressPart[] getParts(IPStringBuilderOptions options) {
		return getParts(IPv4StringBuilderOptions.from(options));
	}
	
	public IPAddressPart[] getParts(IPv4StringBuilderOptions options) {
		if(!options.includesAny(IPv4StringBuilderOptions.ALL_JOINS)) {
			return super.getParts(options);
		}
		ArrayList<IPAddressPart> parts = new ArrayList<IPAddressPart>(IPv4Address.SEGMENT_COUNT);
		if(options.includes(IPStringBuilderOptions.BASIC)) {
			parts.add(this);
		}
		boolean joined[] = new boolean[IPv4Address.SEGMENT_COUNT];
		int segmentCount = getSegmentCount();
		joined[Math.max(3, segmentCount - 1)] = options.includes(IPv4StringBuilderOptions.JOIN_ALL);
		joined[Math.max(2, Math.min(2, segmentCount - 1))] |= options.includes(IPv4StringBuilderOptions.JOIN_TWO);
		joined[Math.max(1, Math.min(1, segmentCount - 1))] |= options.includes(IPv4StringBuilderOptions.JOIN_ONE);
		for(int i = 1; i < joined.length; i++) {
			if(joined[i]) {
				parts.add(toJoinedSegments(i));
			}
		}
		return parts.toArray(new IPAddressPart[parts.size()]);
	}

	static class IPv4SectionStringCollection extends IPAddressPartStringCollection {
	
		@Override
		protected void add(IPAddressPartStringSubCollection<?, ?, ? extends IPAddressPartConfiguredString<?, ?>> collection) {
			super.add(collection);
		}
		
		@Override
		protected void addAll(IPAddressPartStringCollection collections) {
			super.addAll(collections);
		}
	}
	
	public static class IPv4StringBuilderOptions extends IPStringBuilderOptions {
		public static final int JOIN_ALL = 0x2;
		public static final int JOIN_TWO = 0x4;
		public static final int JOIN_ONE = 0x8;
		public static final int ALL_JOINS = JOIN_ALL | JOIN_TWO | JOIN_ONE;
		
		public static final int IPV6_CONVERSIONS = 0x10000;
		
		//right now we do not do mixing of octal and/or hex and/or decimal which could create another 81 = 3^4 combos with 4 segments
		public static final int OCTAL = 0x100;
		public static final int HEX = 0x200;
		
		public final IPv6StringBuilderOptions ipv6ConverterOptions;
		public final IPv6AddressConverter converter;

		public static final IPv4StringBuilderOptions STANDARD_OPTS = new IPv4StringBuilderOptions(IPStringBuilderOptions.BASIC | IPStringBuilderOptions.LEADING_ZEROS_FULL_ALL_SEGMENTS);
		
		public static final IPv4StringBuilderOptions DATABASE_SEARCH_OPTS = new IPv4StringBuilderOptions();
		
		public static final IPv4StringBuilderOptions ALL_OPTS = new IPv4StringBuilderOptions(
				IPStringBuilderOptions.BASIC | 
					IPv4StringBuilderOptions.JOIN_ALL | 
					IPv4StringBuilderOptions.JOIN_TWO | 
					IPv4StringBuilderOptions.JOIN_ONE |
					IPv4StringBuilderOptions.HEX |
					IPv4StringBuilderOptions.OCTAL |
					IPv4StringBuilderOptions.IPV6_CONVERSIONS |
					IPStringBuilderOptions.LEADING_ZEROS_FULL_SOME_SEGMENTS,
				null,
				new IPv6StringBuilderOptions(
						IPStringBuilderOptions.BASIC | 
							IPv6StringBuilderOptions.MIXED |
							IPv6StringBuilderOptions.UPPERCASE | 
							IPv6StringBuilderOptions.COMPRESSION_ALL_FULL |
							IPStringBuilderOptions.LEADING_ZEROS_FULL_SOME_SEGMENTS));

		public IPv4StringBuilderOptions() {
			this.ipv6ConverterOptions = null;
			this.converter = null;
		}
		
		public IPv4StringBuilderOptions(int options) {
			this(options, null, null);
		}
		
		public IPv4StringBuilderOptions(int options, IPv6AddressConverter ipv6AddressConverter, IPv6StringBuilderOptions ipv6ConverterOptions) {
			super(options | (ipv6ConverterOptions == null ? 0 : IPV6_CONVERSIONS));
			if(includes(IPV6_CONVERSIONS)) {
				if(ipv6ConverterOptions == null) {
					ipv6ConverterOptions = new IPv6StringBuilderOptions(
							IPStringBuilderOptions.BASIC | 
							IPv6StringBuilderOptions.UPPERCASE | 
							IPv6StringBuilderOptions.COMPRESSION_ALL_FULL | 
							IPv6StringBuilderOptions.LEADING_ZEROS_FULL_ALL_SEGMENTS | 
							IPv6StringBuilderOptions.MIXED);
				}
				if(ipv6AddressConverter == null) {
					ipv6AddressConverter = IPAddress.addressConverter;
					if(ipv6AddressConverter == null) {
						ipv6AddressConverter = new DefaultAddressConverter();
					}
				}
			}
			this.ipv6ConverterOptions = ipv6ConverterOptions;
			this.converter = ipv6AddressConverter;
		}
		
		public static IPv4StringBuilderOptions from(IPStringBuilderOptions opts) {
			if(opts instanceof IPv4StringBuilderOptions) {
				return (IPv4StringBuilderOptions) opts;
			}
			return new IPv4StringBuilderOptions(opts.options & ~(ALL_JOINS | IPV6_CONVERSIONS | OCTAL | HEX));
		}
	}

	static class IPv4StringCollection extends IPAddressPartStringCollection {
		
		@Override
		protected void addAll(IPAddressPartStringCollection collections) {
			super.addAll(collections);
		}
		
		static class IPv4AddressSectionStringCollection extends IPAddressPartStringSubCollection<IPAddressPart, IPv4StringParams, IPAddressPartConfiguredString<IPAddressPart, IPv4StringParams>> {
			IPv4AddressSectionStringCollection(IPAddressPart addr) {
				super(addr);
			}
			
			@Override
			public Iterator<IPAddressPartConfiguredString<IPAddressPart, IPv4StringParams>> iterator() {
				return new IPAddressConfigurableStringIterator() {
					@Override
					public IPAddressPartConfiguredString<IPAddressPart, IPv4StringParams> next() {
						return new IPAddressPartConfiguredString<IPAddressPart, IPv4StringParams>(part, iterator.next()); 
					}
				};
			}
		}
		
		/**
		 * Each IPv4StringParams instance has settings to write exactly one IPv4 address section string.
		 * 
		 * @author sfoley
		 *
		 */
		static class IPv4StringParams extends StringParams<IPAddressPart> {
			
			IPv4StringParams(int radix) {
				super(radix);
			}
			
			public IPv4StringParams() {
				this(IPv4Address.DEFAULT_TEXTUAL_RADIX);
			}
			
			@Override
			public int getTrailingSeparatorCount(IPAddressPart addr) {
				if(addr.getDivisionCount() > 0) {
					return addr.getDivisionCount() - 1;
				}
				return 0;
			}
			
			@Override
			public char getTrailingSegmentSeparator() {
				return IPv4Address.SEGMENT_SEPARATOR;
			}
			
			@Override
			public StringBuilder append(StringBuilder builder, IPAddressPart addr) {
				appendSegments(builder, addr);
				Integer networkPrefixLength = addr.getNetworkPrefixLength();
				if(networkPrefixLength != null && getWildcardOption().wildcardOption != WildcardOptions.WildcardOption.ALL) {
					builder.append(IPAddress.PREFIX_LEN_SEPARATOR).append(networkPrefixLength);
				}
				return builder;
			}
			
			@Override
			public StringBuilder appendSegments(StringBuilder builder, IPAddressPart part) {
				if(part.getDivisionCount() != 0) {
					WildcardOptions wildcardOptions = getWildcardOption();
					WildcardOptions.WildcardOption wildcardOption = wildcardOptions.wildcardOption;
					boolean isAll = wildcardOption == WildcardOptions.WildcardOption.ALL;
					for(int i = 0; i < part.getDivisionCount(); i++) {
						IPAddressDivision seg = part.getDivision(i);
						int leadingZeroCount = getLeadingZeros(i);
						if(isAll) {
							seg.getWildcardString(wildcardOptions.wildcards, leadingZeroCount, getSegmentStrPrefix(), getRadix(), false, builder);
						} else { //wildcardOption == WildcardOptions.WildcardOption.NETWORK_ONLY
							seg.getPrefixAdjustedWildcardString(wildcardOptions.wildcards, leadingZeroCount, getSegmentStrPrefix(), getRadix(), false, builder);
						}
						builder.append(IPv4Address.SEGMENT_SEPARATOR);
					}
					builder.deleteCharAt(builder.length() - 1);
				}
				return builder;
			}
			
			@Override
			public String toString(IPAddressPart addr) {
				StringBuilder builder = new StringBuilder(IPv4Address.MAX_STRING_LEN + EXTRA_SPACE);
				return append(builder, addr).toString();
			}
			
			@Override
			public IPv4StringParams clone() {
				return (IPv4StringParams) super.clone();
			}
		}

		/**
		 * Capable of building any and all possible representations of IPv4 addresses.
		 * Not all such representations are necessarily something you might consider valid.
		 * For example: 001.02.3.04
		 * This string has the number '2' and '4' expanded partially to 02 (a partial expansion), rather than left as is, or expanded to the full 3 chars 002.
		 * The number '1' is fully expanded to 3 characters.
		 * 
		 * With the default settings of this class, a single address can have 16 variations.  If partial expansions are allowed, there are many more.
		 * 
		 * @author sfoley
		 */
		static class IPv4StringBuilder
			extends AddressPartStringBuilder<IPAddressPart, IPv4StringParams, IPAddressPartConfiguredString<IPAddressPart, IPv4StringParams>, IPv4AddressSectionStringCollection, IPv4StringBuilderOptions> {
			
			private IPv4StringBuilder(IPAddressPart address, IPv4StringBuilderOptions options, IPv4AddressSectionStringCollection collection) {
				super(address, options, collection);
			}
			
			@Override
			public void addAllVariations() {
				ArrayList<IPv4StringParams> allParams = new ArrayList<IPv4StringParams>();
				ArrayList<Integer> radices = new ArrayList<Integer>();
				radices.add(IPv4Address.DEFAULT_TEXTUAL_RADIX);
				if(options.includes(IPv4StringBuilderOptions.HEX)) {
					radices.add(16);
				}
				boolean hasDecimalOctalDups = false;
				if(options.includes(IPv4StringBuilderOptions.OCTAL)) {
					radices.add(8);
					//We need to consider when octal intersects with a leading zero config. 01 as octal vs 01 as a decimal with leading zero
					//Or 001 as octal with a single leading zero and 001 as decimal with two leading zeros.
					//However, keep in mind this is only true when the segment value is <= 8, otherwise the segment value is different in octal.
					//So if the segment value is <=8 (or both values of a range are <=8) and we are doing both decimal and octal and we are doing partial expansions,
					//then we cannot have repeats. In such cases, each octal expansion of size x is same as decimal expansion of size x + 1 (where x = 0 or 1)
					//But the full string is only a repeat if the whole thing is same in decimal as octal.  Only then will we see dups.
					//So, we skip if we are (a) doing both octal and decimal and (b) all segments are <=8 and 
					//case 1: for the octal:  (c) Every segment is either no expansion or expansion of size 1
					//case 2: for the decimal: (c) Every segment is an expansion of size 1 or 2 (ie 2 is full) 
					//Here we are checking for cases (a) and (b).  (c) we check below.
					hasDecimalOctalDups = IPv4Address.inet_aton_radix.OCTAL.getSegmentStrPrefix().equals("0") &&
							IPAddressSection.isDecimalSameAsOctal(false, addressSection);
				}
				for(int radix : radices) {
					ArrayList<IPv4StringParams> radixParams = new ArrayList<IPv4StringParams>();
					IPv4StringParams stringParams = new IPv4StringParams(radix);
					radixParams.add(stringParams);
					switch(radix) {
						case 8:
							stringParams.setSegmentStrPrefix(IPv4Address.inet_aton_radix.OCTAL.getSegmentStrPrefix());
							break;
						case 16:
							stringParams.setSegmentStrPrefix(IPv4Address.inet_aton_radix.HEX.getSegmentStrPrefix());
							break;
					}
					if(options.includes(IPStringBuilderOptions.LEADING_ZEROS_FULL_SOME_SEGMENTS)) {
						int expandables[] = getExpandableSegments(radix);
						for(int i = 0; i < addressSection.getDivisionCount(); i++) {
							int expansionLength = expandables[i];
							int len = radixParams.size();
							while(expansionLength > 0) {
								for(int j = 0; j < len; j++) {
									IPv4StringParams clone = radixParams.get(j);
									if(hasDecimalOctalDups && radix == 10) {
										//See above for explanation.
										//we know already expansionLength == 1 || expansionLength == 2 for the current segment
										//Here we check the others
										boolean isDup = true;
										for(int k = 0; k < addressSection.getDivisionCount(); k++) {
											if(k != i) {
												int length = clone.getExpandedSegmentLength(k);
												if(length == 0) {//length is not either 1 or 2
													isDup = false;
													break;
												}
											}
										}
										if(isDup) {
											//this decimal string is a duplicate of an octal string, so we skip it
											continue;
										}
									}
									clone = clone.clone();
									clone.expandSegment(i, expansionLength, addressSection.getDivisionCount());
									radixParams.add(clone);
								}
								if(!options.includes(IPStringBuilderOptions.LEADING_ZEROS_PARTIAL_SOME_SEGMENTS)) {
									break;
								}
								expansionLength--;
							}
						}
					} else if(options.includes(IPStringBuilderOptions.LEADING_ZEROS_FULL_ALL_SEGMENTS)) {
						boolean allExpandable = isExpandable(radix);
						if(allExpandable) {
							IPv4StringParams expandParams = new IPv4StringParams();
							expandParams.expandSegments(true);
							radixParams.add(expandParams);
						}
					}
					allParams.addAll(radixParams);
				}
				for(int i=0; i<allParams.size(); i++) {
					IPv4StringParams param = allParams.get(i);
					addStringParam(param);
				}
			}
			
			@Override
			protected void addStringParam(IPv4StringParams stringParams) {
				super.addStringParam(stringParams);
			}
		} //end IPv4StringBuilder
	} //end IPv4StringCollection
}
