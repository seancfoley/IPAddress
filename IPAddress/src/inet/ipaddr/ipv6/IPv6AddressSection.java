package inet.ipaddr.ipv6;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;

import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressConverter.DefaultAddressConverter;
import inet.ipaddr.IPAddressSection;
import inet.ipaddr.IPAddressSection.WildcardOptions.Wildcards;
import inet.ipaddr.IPAddressSegment;
import inet.ipaddr.IPAddressTypeException;
import inet.ipaddr.format.IPAddressDivision;
import inet.ipaddr.format.IPAddressPart;
import inet.ipaddr.format.IPAddressSegmentGrouping;
import inet.ipaddr.format.util.IPAddressPartConfiguredString;
import inet.ipaddr.format.util.IPAddressPartStringCollection;
import inet.ipaddr.format.util.IPAddressPartStringParams;
import inet.ipaddr.format.util.IPAddressPartStringSubCollection;
import inet.ipaddr.format.util.sql.IPAddressSQLTranslator;
import inet.ipaddr.format.util.sql.SQLStringMatcher;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv4.IPv4Address.IPv4AddressConverter;
import inet.ipaddr.ipv4.IPv4AddressNetwork.IPv4AddressCreator;
import inet.ipaddr.ipv4.IPv4AddressSection;
import inet.ipaddr.ipv4.IPv4AddressSection.IPv4StringBuilderOptions;
import inet.ipaddr.ipv4.IPv4AddressSegment;
import inet.ipaddr.ipv6.IPv6AddressNetwork.IPv6AddressCreator;
import inet.ipaddr.ipv6.IPv6AddressSection.CompressOptions.CompressionChoiceOptions;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringCollection.IPv6StringBuilder;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringCollection.IPv6StringParams;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringCollection.IPv6v4MixedParams;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringCollection.IPv6v4MixedStringBuilder;

/**
 * 
 * @author sfoley
 *
 */
public class IPv6AddressSection extends IPAddressSection {

	private static final long serialVersionUID = 1L;

	private static IPv6AddressCreator creators[] = new IPv6AddressCreator[IPv6Address.SEGMENT_COUNT + 1];

	static class IPv6StringCache extends StringCache {
		//a set of pre-defined string types
		static final IPv6StringOptions mixedParams;
		static final IPv6StringOptions fullParams;

		static final IPv6StringOptions normalizedParams;
		static final IPv6StringOptions canonicalParams;
		static final IPv6StringOptions compressedParams;
		
		static final IPv6StringOptions wildcardNormalizedParams;
		static final IPv6StringOptions wildcardCanonicalParams;
		static final IPv6StringOptions sqlWildcardParams;
		static final IPv6StringOptions wildcardCompressedParams;
		static final IPv6StringOptions networkPrefixLengthParams;
		
		static {
			CompressOptions 
				compressAll = new CompressOptions(true, CompressOptions.CompressionChoiceOptions.ZEROS_OR_HOST),
				compressMixed = new CompressOptions(true, CompressOptions.CompressionChoiceOptions.MIXED_PREFERRED),
				compressAllNoSingles = new CompressOptions(false, CompressOptions.CompressionChoiceOptions.ZEROS_OR_HOST), 
				compressHostPreferred = new CompressOptions(true, CompressOptions.CompressionChoiceOptions.HOST_PREFERRED),
				compressZeros = new CompressOptions(true, CompressOptions.CompressionChoiceOptions.ZEROS),
				compressZerosNoSingles = new CompressOptions(false, CompressOptions.CompressionChoiceOptions.ZEROS);

			mixedParams = new IPv6StringOptions.Builder().setMakeMixed(true).setCompressOptions(compressMixed).toParams();
			fullParams = new IPv6StringOptions.Builder().setExpandSegments(true).setWildcardOptions(new WildcardOptions(WildcardOptions.WildcardOption.NETWORK_ONLY, new Wildcards(IPAddress.RANGE_SEPARATOR_STR))).toParams();
			canonicalParams = new IPv6StringOptions.Builder().setCompressOptions(compressAllNoSingles).toParams();
			compressedParams = new IPv6StringOptions.Builder().setCompressOptions(compressAll).toParams();
			normalizedParams = new IPv6StringOptions.Builder().toParams();
			
			WildcardOptions 
				allWildcards = new WildcardOptions(WildcardOptions.WildcardOption.ALL),
				allSQLWildcards = new WildcardOptions(WildcardOptions.WildcardOption.ALL, new Wildcards(IPAddress.SEGMENT_SQL_WILDCARD_STR, IPAddress.SEGMENT_SQL_SINGLE_WILDCARD_STR));

			wildcardCanonicalParams = new IPv6StringOptions.Builder().setWildcardOptions(allWildcards).setCompressOptions(compressZerosNoSingles).toParams();
			wildcardNormalizedParams = new IPv6StringOptions.Builder().setWildcardOptions(allWildcards).toParams(); //no compression
			sqlWildcardParams = new IPv6StringOptions.Builder().setWildcardOptions(allSQLWildcards).toParams(); //no compression
			wildcardCompressedParams = new IPv6StringOptions.Builder().setWildcardOptions(allWildcards).setCompressOptions(compressZeros).toParams();
			networkPrefixLengthParams = new IPv6StringOptions.Builder().setCompressOptions(compressHostPreferred).toParams();
		}
		
		public String normalizedString;
		public String compressedString;
		public String mixedString;
		public String compressedWildcardString;									
		public String canonicalWildcardString;
		public String networkPrefixLengthString;
	}
	
	transient IPv6StringCache stringCache;

	transient IPv4AddressSection mixedSection;
	transient IPv6v4MixedAddressSection defaultMixedAddressSection;

	/*
	 * Indicates the index of the first segment where this section starts in a full IPv6 address.  0 for network sections or full addresses
	 */
	public final int startIndex;

	/* also for caching: index of segments that are zero, and the number of consecutive zeros for each. */
	private transient RangeList zeroSegments;
	
	/* also for caching: index of segments that are zero or any value due to CIDR prefix, and the number of consecutive segments for each. */
	private transient RangeList zeroRanges;
	
	/*
	 * Only an address section including leading segment should use this constructor
	 */
	public IPv6AddressSection(IPv6AddressSegment segments[]) {
		this(segments, 0, true);
	}
	
	/*
	 * Only an address section including leading segment should use this constructor
	 */
	public IPv6AddressSection(IPv6AddressSegment segments[], Integer networkPrefixLength) {
		this(segments, 0, networkPrefixLength);
	}
	
	public IPv6AddressSection(IPv6AddressSegment[] segments, int startIndex, Integer networkPrefixLength) {
		this(toCIDRSegments(networkPrefixLength, segments, getIPv6SegmentCreator()), startIndex, false);
		
	}
	
	IPv6AddressSection(IPv6AddressSegment[] segments, int startIndex, boolean cloneSegments) {
		super(segments, null, cloneSegments, false);
		if(startIndex < 0) {
			throw new IllegalArgumentException();
		}
		this.startIndex = startIndex;
	}
	
	IPv6AddressSection(byte bytes[], Integer prefix, boolean cloneBytes) {
		super(toSegments(bytes, IPv6Address.SEGMENT_COUNT, IPv6Address.BYTES_PER_SEGMENT, IPv6Address.BITS_PER_SEGMENT, getIPv6SegmentCreator(), prefix), bytes, false, cloneBytes);
		this.startIndex = 0;
	}
	
	public IPv6AddressSection(byte bytes[], Integer prefix) {
		this(bytes, prefix, true);
	}
	
	@Override
	protected void initCachedValues(
			Integer prefixLen,
			boolean network,
			Integer cachedNetworkPrefix,
			Integer cachedMinPrefix,
			Integer cachedEquivalentPrefix,
			BigInteger cachedCount,
			RangeList zeroSegments,
			RangeList zeroRanges) {
		super.initCachedValues(prefixLen, network, cachedNetworkPrefix, cachedMinPrefix, cachedEquivalentPrefix, cachedCount, zeroSegments, zeroRanges);
		this.zeroSegments = zeroSegments;
		this.zeroRanges = zeroRanges;
	}
	
	@Override
	public IPv6AddressSegment[] getLowestSegments() {
		return (IPv6AddressSegment[]) super.getLowestSegments();
	}
	
	@Override
	public IPv6AddressSegment[] getHighestSegments() {
		return (IPv6AddressSegment[]) super.getHighestSegments();
	}
	
	@Override
	public IPv6AddressSection getLowestSection() {
		return (IPv6AddressSection) super.getLowestSection();
	}
	
	@Override
	public IPv6AddressSection getHighestSection() {
		return (IPv6AddressSection) super.getHighestSection();
	}
	
	@Override
	public Iterator<IPv6AddressSection> sectionIterator() {
		return new SectionIterator<IPv6Address, IPv6AddressSection, IPv6AddressSegment>();
	}
	
	@Override
	public Iterator<IPv6AddressSegment[]> iterator() {
		return cast(super.iterator());
	}
	
	@Override
	protected IPv6AddressCreator getSegmentCreator() {
		return getIPv6SegmentCreator();
	}
	
	private static IPv6AddressCreator getIPv6SegmentCreator() {
		return IPv6Address.network().getAddressCreator();
	}
	
	@Override
	protected IPv6AddressCreator getAddressCreator() {
		return getAddressCreator(startIndex);
	}
	
	protected IPv6AddressCreator getAddressCreator(final int startIndex) {
		IPv6AddressCreator result = creators[startIndex];
		if(result == null) {
			creators[startIndex] = result = new IPv6AddressCreator() {
				@Override
				protected IPv6AddressSection createSectionInternal(IPv6AddressSegment segments[]) {
					return IPv6Address.network().getAddressCreator().createSectionInternal(segments, startIndex);
				}
			};
		}
		return result;
	}
	
	@Override
	public IPv6AddressSegment getSegment(int index) {
		return (IPv6AddressSegment) super.getSegment(index);
	}

	/**
	 * Produces an IPv4 address section from any sequence of bytes in this IPv6 address section
	 * 
	 * @param startIndex the byte index in this section to start from
	 * @param endIndex the byte index in this section to end at
	 * @throws IndexOutOfBoundsException
	 * @return
	 */
	public IPv4AddressSection getEmbeddedIPv4AddressSection(int startIndex, int endIndex) {
		if(startIndex == ((IPv6Address.MIXED_ORIGINAL_SEGMENT_COUNT - this.startIndex) << 1) && endIndex == (getSegmentCount() << 1)) {
			return getMixedSection();
		}
		IPv4AddressCreator creator = IPv4Address.network().getAddressCreator();
		IPv4AddressSegment[] segments = creator.createAddressSegmentArray((endIndex - startIndex) >> 1);
		int i = startIndex, j = 0;
		if(i % IPv6Address.BYTES_PER_SEGMENT == 1) {
			IPv6AddressSegment ipv6Segment = getSegment(i++ / IPv6Address.BYTES_PER_SEGMENT);
			ipv6Segment.getIPv4Segments(segments, j++ - 1);
		}
		for(; i < endIndex; i <<= 1, j <<= 1) {
			IPv6AddressSegment ipv6Segment = getSegment(i / IPv6Address.BYTES_PER_SEGMENT);
			ipv6Segment.getIPv4Segments(segments, j);
		}
		return getSection(creator, segments);
	}
	
	/**
	 * Gets the IPv4 section corresponding to the lowest (least-significant) 4 bytes in the original address,
	 * which will correspond to between 0 and 4 bytes in this address.
	 * 
	 * @return
	 */
	public IPv4AddressSection getMixedSection() {
		int mixedCount = getSegmentCount() - Math.max(IPv6Address.MIXED_ORIGINAL_SEGMENT_COUNT - startIndex, 0);
		if(mixedCount > 0 && mixedSection == null) {
			synchronized(this) {
				if(mixedSection == null) {
					int lastIndex = getSegmentCount() - 1;
					//mixedCount is either 1 or 2
					IPv4AddressSegment[] mixed = (mixedCount == 1) ? 
							getSegment(lastIndex).split() : 
							IPv6AddressSegment.split(getSegment(lastIndex - 1), getSegment(lastIndex));
					IPv4AddressCreator creator = IPv4Address.network().getAddressCreator();
					mixedSection = getSection(creator, mixed);
				}
			}
		}
		return mixedSection;
	}
	
	public IPv6AddressSection createNonMixedSection() {
		int mixedCount = getSegmentCount() - Math.max(IPv6Address.MIXED_ORIGINAL_SEGMENT_COUNT - startIndex, 0);
		if(mixedCount <= 0) {
			return this;
		}
		int nonMixedCount = Math.max(0, getSegmentCount() - mixedCount);
		IPv6AddressSegment[] nonMixed = new IPv6AddressSegment[nonMixedCount];
		copySegments(0, nonMixedCount, nonMixed, 0);
		IPv6AddressCreator creator = IPv6Address.network().getAddressCreator();
		return creator.createSectionInternal(nonMixed, startIndex);
	}
	
	public IPv6v4MixedAddressSection getMixedAddressSection() {
		if(defaultMixedAddressSection == null) {
			synchronized(this) {
				if(defaultMixedAddressSection == null) {
					defaultMixedAddressSection = new IPv6v4MixedAddressSection(
							createNonMixedSection(),
							getMixedSection());
				}
			}
		}
		return defaultMixedAddressSection;
	}
	
	@Override
	public int getBitsPerSegment() {
		return IPv6Address.BITS_PER_SEGMENT;
	}
	
	@Override
	public int getBytesPerSegment() {
		return IPv6Address.BYTES_PER_SEGMENT;
	}
	
	/**
	 * Returns whether this subnet or address has alphabetic digits when printed.
	 * 
	 * Note that this method does not indicate whether any address contained within this subnet has alphabetic digits,
	 * only whether the subnet itself when printed has alphabetic digits.
	 * 
	 * @return whether the section has alphabetic digits when printed.
	 */
	public boolean hasAlphabeticDigits(int base, boolean lowerOnly) {
		if(base > 10) {
			int count = getSegmentCount();
			for(int i = 0; i < count; i++) {
				IPv6AddressSegment seg = getSegment(i);
				if(seg.hasAlphabeticDigits(base, lowerOnly)) {
					return true;
				}
			}
		}
		return false;
	}
	
	@Override
	public boolean isIPv6() {
		return true;
	}
	
	@Override
	public IPVersion getIPVersion() {
		return IPVersion.IPV6;
	}
	
	@Override
	public boolean contains(IPAddressSection other) {
		return other.isIPv6() && super.contains(other);
	}
	
	@Override
	protected boolean isSameGrouping(IPAddressSegmentGrouping other) {
		return other instanceof IPv6AddressSection &&
				startIndex == ((IPv6AddressSection) other).startIndex &&
				super.isSameGrouping(other);
	}
	
	@Override
	public boolean equals(Object o) {
		if(o == this) {
			return true;
		}
		if(o instanceof IPv6AddressSection) {
			IPv6AddressSection other = (IPv6AddressSection) o;
			return startIndex == other.startIndex && super.isSameGrouping(other);
		}
		return false;
	}
	
	@Override
	public int getByteIndex(Integer networkPrefixLength) {
		return getByteIndex(networkPrefixLength, IPv6Address.BYTE_COUNT);
	}
	
	@Override
	public int getSegmentIndex(Integer networkPrefixLength) {
		return getSegmentIndex(networkPrefixLength, IPv6Address.BYTE_COUNT, IPv6Address.BYTES_PER_SEGMENT);
	}
	
	@Override
	public IPv6AddressNetwork getNetwork() {
		return IPv6Address.network();
	}
	
	@Override
	public IPv6AddressSection toSubnet(int networkPrefixLength) throws IPAddressTypeException {
		return (IPv6AddressSection) super.toSubnet(networkPrefixLength);
	}
	
	/**
	 * Creates a subnet address using the given mask. 
	 */
	@Override
	public IPv6AddressSection toSubnet(IPAddressSection mask) throws IPAddressTypeException {
		return toSubnet(mask, null);
	}
	
	/**
	 * Creates a subnet address using the given mask.  If networkPrefixLength is non-null, applies the prefix length as well.
	 */
	@Override
	public IPv6AddressSection toSubnet(IPAddressSection mask, Integer networkPrefixLength) throws IPAddressTypeException {
		return (IPv6AddressSection) super.toSubnet(mask, networkPrefixLength);
	}
	
	@Override
	public IPv6AddressSection getNetworkSection(int networkPrefixLength, boolean withPrefixLength) {
		int cidrSegmentCount = getNetworkSegmentCount(networkPrefixLength);
		IPv6AddressCreator creator = getAddressCreator(startIndex);
		return getNetworkSegments(networkPrefixLength, cidrSegmentCount, withPrefixLength, creator);
	}
	
	@Override
	public IPv6AddressSection getNetworkSection(int networkPrefixLength) {
		return getNetworkSection(networkPrefixLength, true);
	}
	
	@Override
	public IPv6AddressSection getHostSection(int networkPrefixLength) {
		int cidrSegmentCount = getHostSegmentCount(networkPrefixLength);
		IPv6AddressCreator creator = getAddressCreator(startIndex + (getSegmentCount() - cidrSegmentCount));
		return getHostSegments(networkPrefixLength, cidrSegmentCount, creator);
	}
	
	////////////////string creation below ///////////////////////////////////////////////////////////////////////////////////////////

	boolean hasNoCache() {
		if(stringCache == null) {
			synchronized(this) {
				if(stringCache == null) {
					stringCache = new IPv6StringCache();
					return true;
				}
			}
		}
		return false;
	}
	
	/**
	 * This produces the shortest valid string for the address.
	 */
	@Override
	public String toCompressedString() {
		String result;
		if(hasNoCache() || (result = stringCache.compressedString) == null) {
			stringCache.compressedString = result = toNormalizedString(IPv6StringCache.compressedParams);
		}
		return result;
	}

	/**
	 * This produces a canonical string.
	 * 
	 * RFC 5952 describes canonical representations.
	 * http://en.wikipedia.org/wiki/IPv6_address#Recommended_representation_as_text
	 * http://tools.ietf.org/html/rfc5952
	 */
	@Override
	public String toCanonicalString() {
		String result;
		if(hasNoCache() || (result = stringCache.canonicalString) == null) {
			stringCache.canonicalString = result = toNormalizedString(IPv6StringCache.canonicalParams);
		}
		return result;
	}
	
	/**
	 * This produces the mixed IPv6/IPv4 string.  It is the shortest such string (ie fully compressed).
	 */
	public String toMixedString() {
		String result;
		if(hasNoCache() || (result = stringCache.mixedString) == null) {
			stringCache.mixedString = result = toNormalizedString(IPv6StringCache.mixedParams);
		}
		return result;
	}

	/**
	 * This produces a string with no compressed segments and all segments of full length,
	 * which is 4 characters for IPv6 segments and 3 characters for IPv4 segments.
	 */
	@Override
	public String toFullString() {
		String result;
		if(hasNoCache() || (result = stringCache.fullString) == null) {
			stringCache.fullString = result = toNormalizedString(IPv6StringCache.fullParams);
		}
		return result;
	}
	
	@Override
	public String toCompressedWildcardString() {
		String result;
		if(hasNoCache() || (result = stringCache.compressedWildcardString) == null) {
			stringCache.compressedWildcardString = result = toNormalizedString(IPv6StringCache.wildcardCompressedParams);
		}
		return result;
	}
	
	@Override
	public String toNetworkPrefixLengthString() {
		String result;
		if(hasNoCache() || (result = stringCache.networkPrefixLengthString) == null) {
			stringCache.networkPrefixLengthString = result = toNormalizedString(IPv6StringCache.networkPrefixLengthParams);
		}
		return result;
	}
	
	@Override
	public String toSubnetString() {
		return toNetworkPrefixLengthString();
	}
	
	@Override
	public String toCanonicalWildcardString() {
		String result;
		if(hasNoCache() || (result = stringCache.canonicalWildcardString) == null) {
			stringCache.canonicalWildcardString = result = toNormalizedString(IPv6StringCache.wildcardCanonicalParams);
		}
		return result;
	}
	
	@Override
	public String toNormalizedWildcardString() {
		String result;
		if(hasNoCache() || (result = stringCache.normalizedWildcardString) == null) {
			stringCache.normalizedWildcardString = result = toNormalizedString(IPv6StringCache.wildcardNormalizedParams);
		}
		return result;
	}
	
	@Override
	public String toSQLWildcardString() {
		String result;
		if(hasNoCache() || (result = stringCache.sqlWildcardString) == null) {
			stringCache.sqlWildcardString = result = toNormalizedString(IPv6StringCache.sqlWildcardParams);
		}
		return result;
	}
	
	/**
	 * The normalized string returned by this method is consistent with java.net.Inet6address.
	 * IPs are not compressed nor mixed in this representation.
	 */
	@Override
	public String toNormalizedString() {
		String result;
		if(hasNoCache() || (result = stringCache.normalizedString) == null) {
			stringCache.normalizedString = result = toNormalizedString(IPv6StringCache.normalizedParams);
		}
		return result;
	}
	
	public String toNormalizedString(IPv6StringOptions params) {
		return toNormalizedString(params, null);
	}
	
	String toNormalizedString(IPv6StringOptions options, String zone) {
		IPv6StringParams stringParams = options.from(this);
		stringParams.zone = zone;
		if(options.makeMixed() && stringParams.nextUncompressedIndex <= IPv6Address.MIXED_ORIGINAL_SEGMENT_COUNT - startIndex) {//the mixed section is not compressed
			IPv6v4MixedParams mixedParams = new IPv6v4MixedParams(stringParams, options.ipv4Opts);
			IPv6v4MixedAddressSection mixed = getMixedAddressSection();
			String result =  mixedParams.toString(mixed);
			return result;
		}
		return stringParams.toString(this);
	}
	
	@Override
	public String toNormalizedString(StringOptions paramsBase) {
		if(paramsBase instanceof IPv6StringOptions) {
			return toNormalizedString((IPv6StringOptions) paramsBase);
		}
		return toNormalizedString(new IPv6StringOptions.Builder().
				setRadix(paramsBase.base).setExpandSegments(paramsBase.expandSegments).
				setWildcardOptions(paramsBase.wildcardOptions).setSegmentStrPrefix(paramsBase.segmentStrPrefix).toParams());
	}

	@Override
	public IPAddressPartStringCollection toStandardStringCollection() {
		return toStringCollection(IPv6StringBuilderOptions.STANDARD_OPTS);
	}
	
	@Override
	public IPAddressPartStringCollection toAllStringCollection() {
		return toStringCollection(IPv6StringBuilderOptions.ALL_OPTS);
	}
	
	@Override
	public IPAddressPartStringCollection toDatabaseSearchStringCollection() {
		return toStringCollection(IPv6StringBuilderOptions.DATABASE_SEARCH_OPTS);
	}
	
	@Override
	public IPAddressPartStringCollection toStringCollection(IPStringBuilderOptions options) {
		return toStringCollection(IPv6StringBuilderOptions.from(options));
	}
	
	public IPAddressPartStringCollection toStringCollection(IPv6StringBuilderOptions opts) {
		return toStringCollection(opts, null);
	}

	IPv6StringCollection toStringCollection(IPv6StringBuilderOptions opts, String zone) {
		IPv6StringCollection collection = new IPv6StringCollection();
		int mixedCount = getSegmentCount() - Math.max(IPv6Address.MIXED_ORIGINAL_SEGMENT_COUNT - startIndex, 0);
		if(mixedCount > 0 && opts.includes(IPv6StringBuilderOptions.MIXED)) {
			IPv6v4MixedAddressSection mixed = getMixedAddressSection();
			IPv6v4MixedStringBuilder mixedBuilder = new IPv6v4MixedStringBuilder(mixed, opts, zone);
			IPv6v4MixedStringCollection mixedCollection = mixedBuilder.getVariations();
			collection.add(mixedCollection);
		}
		if(opts.includes(IPStringBuilderOptions.BASIC)) {
			IPv6StringBuilder ipv6Builder = new IPv6StringBuilder(this, opts, zone);
			IPv6AddressSectionStringCollection ipv6Collection = ipv6Builder.getVariations();
			collection.add(ipv6Collection);
		}
		return collection;
	}
	
	@Override
	public IPAddressPart[] getParts(IPStringBuilderOptions opts) {
		return getParts(IPv6StringBuilderOptions.from(opts));
	}
	
	public IPAddressPart[] getParts(IPv6StringBuilderOptions opts) {
		if(opts.includes(IPv6StringBuilderOptions.MIXED)) {
			if(opts.includes(IPStringBuilderOptions.BASIC)) {
				return new IPAddressPart[] { this, getMixedAddressSection() };
			}
			return new IPAddressPart[] { getMixedAddressSection() };
		}
		return super.getParts(opts);
	}
	
	private static class IPv6StringMatcher extends SQLStringMatcher<IPv6AddressSection, IPv6StringParams, IPv6AddressSectionString> {
		IPv6StringMatcher(
				IPv6AddressSectionString networkString,
				IPAddressSQLTranslator translator) {
			super(networkString, networkString.addr.isEntireAddress(), translator);
		}
			
		@Override
		public StringBuilder getSQLCondition(StringBuilder builder, String columnName) {
			if(networkString.addr.isEntireAddress()) {
				matchString(builder, columnName, networkString.getString());
			} else if(networkString.endIsCompressed()) { //'::' is at end of networkString
				char sep = networkString.getTrailingSegmentSeparator();
				String searchStr = networkString.getString().substring(0, networkString.getString().length() - 1);
				builder.append('(');
				matchSubString(builder, columnName, sep, networkString.getTrailingSeparatorCount(), searchStr);
				
				//We count the separators to ensure they are below a max count.
				//The :: is expected to match a certain number of segments in the network and possibly more in the host.
				//If the network has y segments then there can be anywhere between 0 and 7 - y additional separators for the host. 
				//eg 1:: matching 7 segments in network means full string has at most an additional 7 - 7 = 0 host separators, so it is either 1:: or 1::x.  It cannot be 1::x:x.
				//eg 1:: matching 6 segments means full string has at most an additional 7 - 6 = 1 separators, so it is either 1::, 1::x or 1::x:x.  It cannot be 1::x:x:x.
				int extraSeparatorCountMax = (IPv6Address.SEGMENT_COUNT - 1) - networkString.addr.getSegmentCount();
				builder.append(") AND (");
				boundSeparatorCount(builder, columnName, sep, extraSeparatorCountMax + networkString.getTrailingSeparatorCount());
				builder.append(')');
			} else if(networkString.isCompressed()) { //'::' is in networkString but not at end of networkString
				char sep = networkString.getTrailingSegmentSeparator();
				builder.append('(');
				matchSubString(builder, columnName, sep, networkString.getTrailingSeparatorCount() + 1, networkString.getString());
				
				//we count the separators to ensure they are an exact count.
				//The :: is expected to match a certain number of segments in the network and there is no compression in the host.
				//If the network has y segments then there is 8 - y additional separators for the host. 
				//eg ::1 matching 7 segments in network means full string has additional 8 - 7 = 1 host separators, so it is ::1:x
				//eg ::1 matching 6 segments means full string has additional 8 - 6 = 2 separators, so it is ::1:x:x
				int extraSeparatorCount = IPv6Address.SEGMENT_COUNT - networkString.addr.getSegmentCount();
				builder.append(") AND (");
				matchSeparatorCount(builder, columnName, sep, extraSeparatorCount + networkString.getTrailingSeparatorCount());
				builder.append(')');
			} else {
				matchSubString(builder, columnName, networkString.getTrailingSegmentSeparator(), networkString.getTrailingSeparatorCount() + 1, networkString.getString());
			}
			return builder;
		}
	}
	
	public static class CompressOptions {
		public enum CompressionChoiceOptions {
			HOST_PREFERRED, //if there is a host section, compress the host along with any adjoining zero segments, otherwise compress a range of zero segments
			MIXED_PREFERRED, //if there is a mixed section that is compressible according to the MixedCompressionOptions, compress the mixed section along with any adjoining zero segments, otherwise compress a range of zero segments
			ZEROS_OR_HOST, //compress the largest range of zero or host segments
			ZEROS; //compress the largest range of zero segments
			
			boolean compressHost() {
				return this != ZEROS;
			}
		}
		
		public enum MixedCompressionOptions {
			NO, //do not allow compression of a mixed section
			NO_HOST, //allow compression of a mixed section when there is no host section
			COVERED_BY_HOST, //allow compression of a mixed section when there is no host section or the host section covers the mixed section
			YES; //allow compression of a mixed section
			
			boolean compressMixed(IPv6AddressSection addressSection) {
				switch(this) {
					default:
					case YES:
						return true;
					case NO:
						return false;
					case NO_HOST:
						return !addressSection.isPrefixed();
					case COVERED_BY_HOST:
						if(addressSection.isPrefixed()) {
							int mixedDistance = IPv6Address.MIXED_ORIGINAL_SEGMENT_COUNT - addressSection.startIndex;
							int mixedCount = addressSection.getSegmentCount() - Math.max(mixedDistance, 0);
							if(mixedCount > 0) {
								return (mixedDistance * addressSection.getBitsPerSegment()) >= addressSection.getNetworkPrefixLength();
							}
						}
						return true;
				}
			}
		}

		public final boolean compressSingle;
		public final CompressionChoiceOptions rangeSelection;
		
		//options for addresses with an ipv4 section
		public final MixedCompressionOptions compressMixedOptions;
				
		public CompressOptions(boolean compressSingle, CompressionChoiceOptions rangeSelection) {
			this(compressSingle, rangeSelection, MixedCompressionOptions.YES);
		}
		
		public CompressOptions(boolean compressSingle, CompressionChoiceOptions rangeSelection, MixedCompressionOptions compressMixedOptions) {
			this.compressSingle = compressSingle;
			this.rangeSelection = rangeSelection;
			this.compressMixedOptions = compressMixedOptions == null ? MixedCompressionOptions.YES : compressMixedOptions;
		}
	}
	
	/**
	 * Provides a clear way to create a specific type of string.
	 * 
	 * @author sfoley
	 *
	 */
	public static class IPv6StringOptions extends StringOptions {
		public final StringOptions ipv4Opts;

		//can be null, which means no compression
		public final CompressOptions compressOptions;
		
		IPv6StringOptions(
				int base,
				boolean expandSegments,
				WildcardOptions wildcardOptions,
				String segmentStrPrefix,
				boolean makeMixed,
				StringOptions ipv4Opts,
				CompressOptions compressOptions) {
			super(base, expandSegments, wildcardOptions, segmentStrPrefix);
			this.compressOptions = compressOptions;
			if(makeMixed) {
				if(ipv4Opts == null) {
					ipv4Opts = new StringOptions.Builder().
							setExpandSegments(expandSegments).setWildcardOptions(wildcardOptions).toParams();
				}
				this.ipv4Opts = ipv4Opts;
			} else {
				this.ipv4Opts = null;
			}
		}
		
		boolean makeMixed() {
			return ipv4Opts != null;
		}
		
		private IPv6StringParams from(IPv6AddressSection addr) {
			IPv6StringParams result = new IPv6StringParams();
			result.expandSegments(expandSegments);
			if(compressOptions != null) {
				boolean makeMixed = makeMixed();
				int vals[] = addr.getCompressIndexAndCount(compressOptions, makeMixed);
				if(vals != null) {
					int maxIndex = vals[0];
					int maxCount = vals[1];
					result.firstCompressedSegmentIndex = maxIndex;
					result.nextUncompressedIndex = maxIndex + maxCount;
					result.hostCompressed = compressOptions.rangeSelection.compressHost() &&
							(result.nextUncompressedIndex > 
								getSegmentIndex(addr.getNetworkPrefixLength(), IPv6Address.BYTE_COUNT, IPv6Address.BYTES_PER_SEGMENT));
				}
			}
			result.setWildcardOption(wildcardOptions);
			return result;
		}
		
		public static IPv6StringOptions from(StringOptions opts) {
			if(opts instanceof IPv6StringOptions) {
				return (IPv6StringOptions) opts;
			}
			return new IPv6StringOptions(
					opts.base,
					opts.expandSegments,
					opts.wildcardOptions,
					opts.segmentStrPrefix,
					false,
					null,
					null);
		}
		
		public static class Builder extends StringOptions.Builder {
			private boolean makeMixed;
			private StringOptions ipv4Options;
			
			//default is null, which means no compression
			private CompressOptions compressOptions; 
			
			public Builder() {
				super(IPv6Address.DEFAULT_TEXTUAL_RADIX);
			}
			
			public Builder setCompressOptions(CompressOptions compressOptions) {
				this.compressOptions = compressOptions;
				return this;
			}
			
			public Builder setMakeMixed(boolean makeMixed) {
				this.makeMixed = makeMixed;
				return this;
			}
			
			public Builder setMakeMixed(StringOptions ipv4Options) {
				this.makeMixed = true;
				this.ipv4Options = ipv4Options;
				return this;
			}
			
			@Override
			public Builder setWildcardOptions(WildcardOptions wildcardOptions) {
				return (Builder) super.setWildcardOptions(wildcardOptions);
			}
			
			@Override
			public Builder setExpandSegments(boolean expandSegments) {
				return (Builder) super.setExpandSegments(expandSegments);
			}
			
			@Override
			public Builder setRadix(int base) {
				return (Builder) super.setRadix(base);
			}
			
			@Override
			public Builder setSegmentStrPrefix(String prefix) {
				return (Builder) super.setSegmentStrPrefix(prefix);
			}
			
			@Override
			public IPv6StringOptions toParams() {
				return new IPv6StringOptions(base, expandSegments, wildcardOptions, segmentStrPrefix, makeMixed, ipv4Options, compressOptions);
			}
		}
	}
	
	@Override
	public RangeList getZeroSegments() {
		if(zeroSegments == null) {
			zeroSegments = super.getZeroSegments();
		}
		return zeroSegments;
	}

	@Override
	public RangeList getZeroRangeSegments() {
		if(zeroRanges == null) {
			zeroRanges = super.getZeroRangeSegments();
		}
		return zeroRanges;
	}

	@Override
	public boolean isZero() {
		RangeList ranges = getZeroSegments();
		return ranges.size() == 1 && ranges.getRange(0).length == getSegmentCount();
	}
	
	private int[] getCompressIndexAndCount(CompressOptions options) {
		return getCompressIndexAndCount(options, false);
	}
	
	/**
	 * Chooses a single segment to be compressed, or null if no segment could be chosen.
	 * @param options
	 * @param createMixed
	 * @return
	 */
	private int[] getCompressIndexAndCount(CompressOptions options, boolean createMixed) {
		if(options != null) {
			CompressionChoiceOptions rangeSelection = options.rangeSelection;
			RangeList compressibleSegs = rangeSelection.compressHost() ? getZeroRangeSegments() : getZeroSegments();
			int maxIndex = -1, maxCount = 0;
			int segmentCount = getSegmentCount();
			
			boolean compressMixed = createMixed && options.compressMixedOptions.compressMixed(this);
			boolean preferHost = (rangeSelection == CompressOptions.CompressionChoiceOptions.HOST_PREFERRED);
			boolean preferMixed = createMixed && (rangeSelection == CompressOptions.CompressionChoiceOptions.MIXED_PREFERRED);
			for(int i = compressibleSegs.size() - 1; i >= 0 ; i--) {
				Range range = compressibleSegs.getRange(i);
				int index = range.index;
				int count = range.length;
				if(createMixed) {
					//so here we shorten the range to exclude the mixed part if necessary
					int mixedIndex = IPv6Address.MIXED_ORIGINAL_SEGMENT_COUNT - startIndex;
					if(!compressMixed ||
							index > mixedIndex || index + count < segmentCount) { //range does not include entire mixed part.  We never compress only part of a mixed part.
						//the compressible range must stop at the mixed part
						count = Math.min(count, mixedIndex - index);
					}
				}
				//select this range if is the longest
				if(count > 0 && count >= maxCount && (options.compressSingle || count > 1)) {
					maxIndex = index;
					maxCount = count;
				}
				if(preferHost && isPrefixed() &&
						((index + count) * IPv6Address.BITS_PER_SEGMENT) > getNetworkPrefixLength()) { //this range contains the host
					//Since we are going backwards, this means we select as the maximum any zero segment that includes the host
					break;
				}
				if(preferMixed && index + count >= segmentCount) { //this range contains the mixed section
					//Since we are going backwards, this means we select to compress the mixed segment
					break;
				}
			}
			if(maxIndex >= 0) {
				return new int[] {maxIndex, maxCount};
			}
		}
		return null;
	}

	public static class IPv6v4MixedAddressSection extends IPAddressSegmentGrouping {

		private static final long serialVersionUID = 1L;
		
		private final IPv6AddressSection ipv6Section;
		private final IPv4AddressSection ipv4Section;
		
		private IPv6v4MixedAddressSection(
				IPv6AddressSection ipv6Section,
				IPv4AddressSection ipv4Section) {
			super(createSegments(ipv6Section, ipv4Section));
			this.ipv4Section = ipv4Section;
			this.ipv6Section = ipv6Section;
		}
		
		private static IPAddressDivision[] createSegments(IPv6AddressSection ipv6Section, IPv4AddressSection ipv4Section) {
			int ipv6Len = ipv6Section.getSegmentCount();
			int ipv4Len = ipv4Section.getSegmentCount();
			IPAddressSegment allSegs[] = new IPAddressSegment[ipv6Len + ipv4Len];
			ipv6Section.copySegments(0, ipv6Len, allSegs, 0);
			ipv4Section.copySegments(0, ipv4Len, allSegs, ipv6Len);
			return allSegs;
		}

		@Override
		public int getByteCount() {
			return ipv6Section.getByteCount() + ipv4Section.getByteCount();
		}

		@Override
		public int getBitCount() {
			return ipv6Section.getBitCount() + ipv4Section.getBitCount();
		}
		
		@Override
		public String toString() {
			if(string == null) {
				IPv6StringOptions mixedParams = IPv6StringCache.mixedParams;
				IPv6StringParams ipv6Params = mixedParams.from(ipv6Section);
				StringOptions ipv4Opts = mixedParams.ipv4Opts;
				IPv6v4MixedParams parms = new IPv6v4MixedParams(ipv6Params, ipv4Opts);
				string = parms.toString(this);
			}
			return string;
		}
		
		@Override
		protected boolean isSameGrouping(IPAddressSegmentGrouping o) {
			if(o instanceof IPv6v4MixedAddressSection) {
				IPv6v4MixedAddressSection other = (IPv6v4MixedAddressSection) o;
				return ipv6Section.equals(other.ipv6Section) && ipv4Section.equals(other.ipv4Section);
			}
			return false;
		}
		
		@Override
		public boolean equals(Object o) {
			if(o == this) {
				return true;
			}
			if(o instanceof IPv6v4MixedAddressSection) {
				IPv6v4MixedAddressSection other = (IPv6v4MixedAddressSection) o;
				return ipv6Section.equals(other.ipv6Section) && ipv4Section.equals(other.ipv4Section);
			}
			return false;
		}
	}

	static class IPv6AddressSectionStringCollection extends IPAddressPartStringSubCollection<IPv6AddressSection, IPv6StringParams, IPv6AddressSectionString> {
		IPv6AddressSectionStringCollection(IPv6AddressSection addr) {
			super(addr);
		}
		
		@Override
		public Iterator<IPv6AddressSectionString> iterator() {
			return new IPAddressConfigurableStringIterator() {
				@Override
				public IPv6AddressSectionString next() {
					return new IPv6AddressSectionString(part, iterator.next()); 
				}
			};
		}
	}
	
	static class IPv6v4MixedStringCollection
		extends IPAddressPartStringSubCollection<IPv6v4MixedAddressSection, IPv6v4MixedParams, IPAddressPartConfiguredString<IPv6v4MixedAddressSection, IPv6v4MixedParams>> {
	
		public IPv6v4MixedStringCollection(IPv6v4MixedAddressSection part) {
			super(part);
		}
		
		@Override
		public Iterator<IPAddressPartConfiguredString<IPv6v4MixedAddressSection, IPv6v4MixedParams>> iterator() {
			return new IPAddressConfigurableStringIterator() {
				@Override
				public IPAddressPartConfiguredString<IPv6v4MixedAddressSection, IPv6v4MixedParams> next() {
					return new IPAddressPartConfiguredString<IPv6v4MixedAddressSection, IPv6v4MixedParams>(part, iterator.next()); 
				}
			};
		}
	}
	
	static class IPv6StringCollection extends IPAddressPartStringCollection {
		
		@Override
		protected void add(IPAddressPartStringSubCollection<?, ?, ?> collection) {
			super.add(collection);
		}
		
		@Override
		protected void addAll(IPAddressPartStringCollection collections) {
			super.addAll(collections);
		}
		
		
		static class IPv6v4MixedParams extends IPAddressPartStringParams<IPv6v4MixedAddressSection> {
			@SuppressWarnings("serial")
			static class IPv4MixedSection extends IPv4AddressSection {
				private IPv4MixedSection() {
					super((byte[]) null);
				}
				
				protected static StringParams<IPAddressPart> toParams(StringOptions opts) {
					return (StringParams<IPAddressPart>) toStringParams(opts);
				}
			}
			
			private StringParams<IPAddressPart> ipv4Params; //params for the IPv4 part of a mixed IPv6/IPv4 address a:b:c:d:e:f:1.2.3.4
			private IPv6StringParams ipv6Params;
			
			@SuppressWarnings("unchecked")
			IPv6v4MixedParams(IPv6AddressSectionString ipv6Variation, IPAddressPartConfiguredString<?, ?> ipv4Variation) {
				this.ipv4Params = (StringParams<IPAddressPart>) ipv4Variation.stringParams;
				this.ipv6Params = ipv6Variation.stringParams;
			}
			
			IPv6v4MixedParams(IPv6StringParams ipv6Params, StringOptions ipv4Opts) {
				this.ipv4Params = IPv4MixedSection.toParams(ipv4Opts);
				this.ipv6Params = ipv6Params;
			}
			
			@Override
			public char getTrailingSegmentSeparator() {
				return ipv4Params.getTrailingSegmentSeparator();
			}
			
			@Override
			public int getTrailingSeparatorCount(IPv6v4MixedAddressSection addr) {
				return ipv4Params.getTrailingSeparatorCount(addr.ipv4Section);
			}
			
			@Override
			public String toString(IPv6v4MixedAddressSection addr) {
				StringBuilder builder = new StringBuilder(IPv6Address.MAX_STRING_LEN + IPv4Address.MAX_STRING_LEN);
				return append(builder, addr).toString();
			}
			
			@Override
			public StringBuilder append(StringBuilder builder, IPv6v4MixedAddressSection addr) {
				ipv6Params.appendSegments(builder, addr.ipv6Section);
				if(ipv6Params.nextUncompressedIndex < addr.ipv6Section.getSegmentCount()) {
					builder.append(ipv6Params.getTrailingSegmentSeparator());
				}
				ipv4Params.appendSegments(builder, addr.ipv4Section);
				appendPrefixIndicator(builder, addr);
				ipv6Params.appendZone(builder);
				return builder;
			}

			private void appendPrefixIndicator(StringBuilder builder, IPv6v4MixedAddressSection addr) {
				if(requiresPrefixIndicator(addr.ipv6Section) || requiresPrefixIndicator(addr.ipv4Section)) {
					builder.append(IPAddress.PREFIX_LEN_SEPARATOR).append(addr.getNetworkPrefixLength());
				}
			}
			
			protected boolean requiresPrefixIndicator(IPv4AddressSection ipv4Section)    {
				return ipv4Section.isPrefixed() && ipv4Params.getWildcardOption().wildcardOption != WildcardOptions.WildcardOption.ALL;
			}
			
			protected boolean requiresPrefixIndicator(IPv6AddressSection ipv6Section)    {
				return ipv6Section.isPrefixed() && (ipv6Params.getWildcardOption().wildcardOption != WildcardOptions.WildcardOption.ALL || ipv6Params.hostCompressed);
			}
			
			@Override
			public IPv6v4MixedParams clone() {
				IPv6v4MixedParams params = (IPv6v4MixedParams) super.clone();
				params.ipv6Params = ipv6Params.clone();
				params.ipv4Params = ipv4Params.clone();
				return params;
			}
		}
		
		/**
		 * Each IPv6StringParams has settings to write exactly one IPv6 address section string
		 * 
		 * @author sfoley
		 *
		 */
		static class IPv6StringParams extends StringParams<IPv6AddressSection> {
			
			int firstCompressedSegmentIndex, nextUncompressedIndex; //the start and end of any compressed section
			
			boolean hostCompressed; //whether the host was compressed, which means we must print the network prefix
			
			boolean uppercase; //whether to print A or a
			
			String zone;
			
			IPv6StringParams() {
				this(false, -1, 0, false);
			}
			
			IPv6StringParams(int firstCompressedSegmentIndex, int compressedCount) {
				this(false, firstCompressedSegmentIndex, compressedCount, false);
			}
			
			private IPv6StringParams(
					boolean expandSegments,
					int firstCompressedSegmentIndex,
					int compressedCount,
					boolean uppercase) {
				super(IPv6Address.DEFAULT_TEXTUAL_RADIX);
				this.expandSegments(expandSegments);
				this.firstCompressedSegmentIndex = firstCompressedSegmentIndex;
				this.nextUncompressedIndex = firstCompressedSegmentIndex + compressedCount;
				this.uppercase = uppercase;
			}
			
			public boolean endIsCompressed(IPAddressPart addr) {
				return nextUncompressedIndex >= addr.getDivisionCount();
			}
			
			public boolean isCompressed(IPAddressPart addr) {
				return firstCompressedSegmentIndex >= 0;
			}
			
			@Override
			public char getTrailingSegmentSeparator() {
				return IPv6Address.SEGMENT_SEPARATOR;
			}

			@Override
			public int getTrailingSeparatorCount(IPv6AddressSection addr) {
				return getTrailingSepCount(addr);
			}
			
			public int getTrailingSepCount(IPAddressPart addr) {
				int divisionCount = addr.getDivisionCount();
				if(divisionCount == 0) {
					return 0;
				}
				int count = divisionCount - 1;//separators with no compression
				if(isCompressed(addr)) {
					count -= (nextUncompressedIndex - firstCompressedSegmentIndex) - 1; //missing seps
					if(firstCompressedSegmentIndex == 0 /* additional separator at front */ || 
							nextUncompressedIndex >= divisionCount /* additional separator at end */) {
						count++;
					}
				}
				return count;
			}
			
			@Override
			public StringBuilder append(StringBuilder builder, IPv6AddressSection addr) {
				appendSegments(builder, addr);
				appendPrefixIndicator(builder, addr);
				appendZone(builder);
				return builder;
			}

			protected void appendPrefixIndicator(StringBuilder builder, IPAddressPart addr) {
				Integer networkPrefixLength = addr.getNetworkPrefixLength();
				if(networkPrefixLength != null && (getWildcardOption().wildcardOption != WildcardOptions.WildcardOption.ALL || hostCompressed)) {
					builder.append(IPAddress.PREFIX_LEN_SEPARATOR).append(networkPrefixLength);
				}
			}
			
			protected void appendZone(StringBuilder builder) {
				if(zone != null && zone.length() > 0) {
					builder.append(IPv6Address.ZONE_SEPARATOR).append(zone);
				}
			}
			
			@Override
			public StringBuilder appendSegments(StringBuilder builder, IPv6AddressSection addr) {
				int divisionCount = addr.getDivisionCount();
				if(divisionCount <= 0) {
					return builder;
				}
				int lastIndex = divisionCount - 1;
				char separator = IPv6Address.SEGMENT_SEPARATOR;
				int i = 0;
				WildcardOptions wildcardOptions = getWildcardOption();
				WildcardOptions.WildcardOption wildcardOption = wildcardOptions.wildcardOption;
				boolean isAll = wildcardOption == WildcardOptions.WildcardOption.ALL;
				for(; i <= lastIndex; i++) {
					if(i < firstCompressedSegmentIndex || i >= nextUncompressedIndex) {
						IPAddressDivision seg = addr.getDivision(i);
						int leadingZeroCount = getLeadingZeros(i);
						if(isAll) {
							seg.getWildcardString(wildcardOptions.wildcards, leadingZeroCount, getSegmentStrPrefix(), getRadix(), uppercase, builder);
						} else { //wildcardOption == WildcardOptions.WildcardOption.NETWORK_ONLY
							seg.getPrefixAdjustedWildcardString(wildcardOptions.wildcards, leadingZeroCount, getSegmentStrPrefix(), getRadix(), uppercase, builder);
						}
						builder.append(separator);
					} else if(i == firstCompressedSegmentIndex) { //the next segment is compressed
						builder.append(separator);
						if(i == 0) {//when compressing the front we use two separators
							builder.append(separator);
						}
					}
				}
				if(nextUncompressedIndex <= lastIndex) {//the last segment we printed was after any compression, so delete the extra separator at the end
					if(builder.length() > 0) {
						builder.deleteCharAt(builder.length() - 1);
					}
				}
				return builder;
			}
			
			@Override
			public String toString(IPv6AddressSection addr) {
				StringBuilder builder = new StringBuilder(IPv6Address.MAX_STRING_LEN + EXTRA_SPACE);
				return append(builder, addr).toString();
			}
			
			@Override
			public IPv6StringParams clone() {
				return (IPv6StringParams) super.clone();
			}
			
		}
		
		/**
		 * Capable of building any and all possible representations of IPv6 addresses.
		 * Not all such representations are necessarily something you might consider valid.
		 * For example: a:0::b:0c:d:1:2
		 * This string has a single zero segment compressed rather than two consecutive (a partial compression),
		 * it has the number 'c' expanded partially to 0c (a partial expansion), rather than left as is, or expanded to the full 4 chars 000c.
		 * 
		 * Mixed representation strings are produced by the IPv6 mixed builder.
		 * The one other type of variation not produced by this class are mixed case, containing both upper and lower case characters: A-F vs a-f.
		 * That would result in gazillions of possible representations.  
		 * But such variations are easy to work with for comparison purposes because you can easily convert strings to lowercase,
		 * so in general there is no need to cover such variations.
		 * However, this does provide the option to have either all uppercase or all lowercase strings.
		 * 
		 * A single address can have hundreds of thousands, even millions, of possible variations.
		 * The default settings for this class will produce at most a couple thousand possible variations.
		 * 
		 * @author sfoley
		 */
		static class IPv6StringBuilder
				extends AddressPartStringBuilder<IPv6AddressSection, IPv6StringParams, IPv6AddressSectionString, IPv6AddressSectionStringCollection, IPv6StringBuilderOptions> {
		
			private final String zone;
			
			IPv6StringBuilder(IPv6AddressSection address, IPv6StringBuilderOptions opts, String zone) {
				super(address,  opts, new IPv6AddressSectionStringCollection(address));
				this.zone = zone;
			}
			
			private void addUppercaseVariations(ArrayList<IPv6StringParams> allParams, int base) {
				boolean lowerOnly = true; //by default we use NETWORK_ONLY wildcards (we use prefix notation otherwise) so here we check lower values only for alphabetic
				if(options.includes(IPv6StringBuilderOptions.UPPERCASE) && addressSection.hasAlphabeticDigits(base, lowerOnly)) {
					int len = allParams.size();
					for(int j=0; j<len; j++) {
						IPv6StringParams clone = allParams.get(j);
						clone = clone.clone();
						clone.uppercase = true;
						allParams.add(clone);
					}
				}
			}
			
			private void addAllExpansions(int firstCompressedIndex, int count, int segmentCount) {
				IPv6StringParams stringParams = new IPv6StringParams(firstCompressedIndex, count);
				stringParams.zone = this.zone;
				int base = stringParams.getRadix();
				final ArrayList<IPv6StringParams> allParams = new ArrayList<IPv6StringParams>();
				allParams.add(stringParams);
				
				int radix = IPv6Address.DEFAULT_TEXTUAL_RADIX;
				if(options.includes(IPStringBuilderOptions.LEADING_ZEROS_FULL_SOME_SEGMENTS)) {
					int expandables[] = getExpandableSegments(radix);
					int nextUncompressedIndex = firstCompressedIndex + count;
					int ipv6SegmentEnd = addressSection.getSegmentCount();
					for(int i=0; i < ipv6SegmentEnd; i++) {
						if(i < firstCompressedIndex || i >= nextUncompressedIndex) {
							int expansionLength = expandables[i];
							int len = allParams.size();
							while(expansionLength > 0) {		
								for(int j=0; j<len; j++) {
									IPv6StringParams clone = allParams.get(j);
									clone = clone.clone();
									clone.expandSegment(i, expansionLength, addressSection.getSegmentCount());
									allParams.add(clone);
								}
								if(!options.includes(IPStringBuilderOptions.LEADING_ZEROS_PARTIAL_SOME_SEGMENTS)) {
									break;
								}
								expansionLength--;
							}
						}
					}
				} else if(options.includes(IPStringBuilderOptions.LEADING_ZEROS_FULL_ALL_SEGMENTS)) {
					boolean isExpandable = isExpandableOutsideRange(radix, firstCompressedIndex, count);
					if(isExpandable) {
						int len = allParams.size();
						for(int j=0; j<len; j++) {
							IPv6StringParams clone = allParams.get(j);
							clone = clone.clone();
							clone.expandSegments(true);
							allParams.add(clone);
						}
					}
				}
				
				addUppercaseVariations(allParams, base);
				
				for(int i=0; i<allParams.size(); i++) {
					IPv6StringParams param = allParams.get(i);
					addStringParam(param);
				}	
			}

			private void addAllCompressedStrings(int zeroStartIndex, int count, boolean partial, int segmentCount) {
				int end = zeroStartIndex + count;
				if(partial) {
					for(int i = zeroStartIndex; i < end; i++) {
						for(int j = i + 1; j <= end; j++) {
							addAllExpansions(i, j - i, segmentCount);
						}	
					}
				} else {
					int len = end - zeroStartIndex;
					if(len > 0) {
						addAllExpansions(zeroStartIndex, len, segmentCount);
					}
				}
			}
			
			/*
			Here is how we get all potential strings:
					//for each zero-segment we choose, including the one case of choosing no zero segment
						//for each sub-segment of that zero-segment compressed (this loop is skipped for the no-zero segment case)
							//for each potential expansion of a non-compressed segment
								//we write the string
			 */
			@Override
			protected void addAllVariations() {
				int segmentCount = addressSection.getSegmentCount();
				
				//start with the case of compressing nothing
				addAllExpansions(-1, 0, segmentCount);
				
				//now do the compressed strings
				if(options.includes(IPv6StringBuilderOptions.COMPRESSION_ALL_FULL)) {
					RangeList zeroSegs  = addressSection.getZeroSegments();
					for(int i = 0; i < zeroSegs.size(); i++) {
						Range range = zeroSegs.getRange(i);
						addAllCompressedStrings(range.index, range.length, options.includes(IPv6StringBuilderOptions.COMPRESSION_ALL_PARTIAL), segmentCount);
					}
				} else if(options.includes(IPv6StringBuilderOptions.COMPRESSION_CANONICAL)) {
					CompressOptions opts = new CompressOptions(options.includes(IPv6StringBuilderOptions.COMPRESSION_SINGLE), CompressOptions.CompressionChoiceOptions.ZEROS);
					int indexes[] = addressSection.getCompressIndexAndCount(opts);
					if(indexes != null) {
						if(options.includes(IPv6StringBuilderOptions.COMPRESSION_LARGEST)) {
							//we compress any section with length that matches the max
							int maxCount = indexes[1];
							RangeList zeroSegs  = addressSection.getZeroSegments();
							for(int i = 0; i < zeroSegs.size(); i++) {
								Range range = zeroSegs.getRange(i);
								int count = range.length;
								if(count == maxCount) {
									addAllCompressedStrings(range.index, count, options.includes(IPv6StringBuilderOptions.COMPRESSION_ALL_PARTIAL), segmentCount);
								}
							}
						} else {
							int maxIndex = indexes[0];
							int maxCount = indexes[1];
							addAllCompressedStrings(maxIndex, maxCount, false, segmentCount);
						}
					} // else nothing to compress, and this case already handled
				}
			}
		}
		
		static class IPv6v4MixedStringBuilder
				extends AddressPartStringBuilder<
					IPv6v4MixedAddressSection,
					IPv6v4MixedParams,
					IPAddressPartConfiguredString<IPv6v4MixedAddressSection, IPv6v4MixedParams>,
					IPv6v4MixedStringCollection,
					IPv6StringBuilderOptions> {
			private final String zone;
			
			IPv6v4MixedStringBuilder(IPv6v4MixedAddressSection address, IPv6StringBuilderOptions opts, String zone) {
				super(address, opts, new IPv6v4MixedStringCollection(address));
				this.zone = zone;
			}

			@Override
			protected void addAllVariations() {
				IPv6StringBuilder ipv6Builder = new IPv6StringBuilder(addressSection.ipv6Section, options, zone);
				IPv6AddressSectionStringCollection ipv6Variations = ipv6Builder.getVariations();
				IPAddressPartStringCollection ipv4Collection = 
						addressSection.ipv4Section.toStringCollection(options.mixedOptions);
				for(IPv6AddressSectionString ipv6Variation : ipv6Variations) {
					for(IPAddressPartConfiguredString<?, ?> ipv4Variation : ipv4Collection) {
						IPv6v4MixedParams mixed = new IPv6v4MixedParams(ipv6Variation, ipv4Variation);
						addStringParam(mixed);
					}
				}
			}
		}
	}
	
	private static class IPv6AddressSectionString extends IPAddressPartConfiguredString<IPv6AddressSection, IPv6StringParams> {
		IPv6AddressSectionString(IPv6AddressSection addr, IPv6StringParams stringParams) {
			super(addr, stringParams);
		}
		
		@SuppressWarnings("unchecked")
		@Override
		public IPv6StringMatcher getNetworkStringMatcher(boolean isEntireAddress, IPAddressSQLTranslator translator) {
			return new IPv6StringMatcher(this, translator);
		}
		
		public boolean endIsCompressed() {
			return stringParams.endIsCompressed(addr);
		}
		
		public boolean isCompressed() {
			return stringParams.isCompressed(addr);
		}
	}
	
	public static class IPv6StringBuilderOptions extends IPStringBuilderOptions {
		public static final int MIXED = 0x2;

		public static final int UPPERCASE = 0x4;

		public static final int COMPRESSION_CANONICAL = 0x100; //use the compression that is part of the canonical string format
		public static final int COMPRESSION_SINGLE = COMPRESSION_CANONICAL | 0x200; //compress a single segment.  If more than one is compressible, choose the largest, and if multiple are largest, choose the most leftward.
		public static final int COMPRESSION_LARGEST = COMPRESSION_SINGLE | 0x400; //compress fully any section that is largest 
		public static final int COMPRESSION_ALL_FULL = COMPRESSION_LARGEST | 0x800; //compress fully any section that can be compressed
		public static final int COMPRESSION_ALL_PARTIAL = COMPRESSION_ALL_FULL | 0x1000;

		public static final int IPV4_CONVERSIONS = 0x10000;

		public final IPv4StringBuilderOptions mixedOptions;
		public final IPv4StringBuilderOptions ipv4ConverterOptions;
		public final IPv4AddressConverter converter;
		
		public static final IPv6StringBuilderOptions STANDARD_OPTS = new IPv6StringBuilderOptions(
				IPStringBuilderOptions.BASIC |
					IPv6StringBuilderOptions.UPPERCASE |
					IPStringBuilderOptions.LEADING_ZEROS_FULL_ALL_SEGMENTS |
					IPv6StringBuilderOptions.COMPRESSION_ALL_FULL, 
			new IPv4StringBuilderOptions(IPStringBuilderOptions.BASIC | IPStringBuilderOptions.LEADING_ZEROS_FULL_ALL_SEGMENTS));
		
		public static final IPv6StringBuilderOptions ALL_OPTS =  
				new IPv6StringBuilderOptions(
						IPStringBuilderOptions.BASIC | 
							IPv6StringBuilderOptions.MIXED | 
							IPv6StringBuilderOptions.UPPERCASE | 
							IPv6StringBuilderOptions.COMPRESSION_ALL_FULL |
							IPv6StringBuilderOptions.IPV4_CONVERSIONS |
							IPStringBuilderOptions.LEADING_ZEROS_FULL_SOME_SEGMENTS, 
						new IPv4StringBuilderOptions(IPStringBuilderOptions.BASIC | IPStringBuilderOptions.LEADING_ZEROS_FULL_SOME_SEGMENTS),//mixed
						null,
						new IPv4StringBuilderOptions(
							IPStringBuilderOptions.BASIC | 
								IPv4StringBuilderOptions.JOIN_ALL | 
								IPv4StringBuilderOptions.JOIN_TWO | 
								IPv4StringBuilderOptions.JOIN_ONE |
								IPv4StringBuilderOptions.HEX |
								IPv4StringBuilderOptions.OCTAL |IPStringBuilderOptions.LEADING_ZEROS_FULL_SOME_SEGMENTS));

		public static final IPv6StringBuilderOptions DATABASE_SEARCH_OPTS =
				new IPv6StringBuilderOptions(IPStringBuilderOptions.BASIC | IPv6StringBuilderOptions.COMPRESSION_LARGEST);

		public IPv6StringBuilderOptions(int options) {
			this(options, null, null, null);
		}

		public IPv6StringBuilderOptions(int options, IPv4StringBuilderOptions mixedOptions) {
			this(options, mixedOptions, null, null);
		}
		
		public IPv6StringBuilderOptions(int options, IPv4StringBuilderOptions mixedOptions, IPv4AddressConverter ipv4AddressConverter, IPv4StringBuilderOptions ipv4ConverterOptions) {
			super(options | (mixedOptions == null ? 0 : MIXED) | (ipv4ConverterOptions == null ? 0 : IPV4_CONVERSIONS));
			if(includes(MIXED) && mixedOptions == null) {
				mixedOptions = new IPv4StringBuilderOptions();
			}
			this.mixedOptions = mixedOptions;
			if(includes(IPV4_CONVERSIONS)) {
				if(ipv4ConverterOptions == null) {
					ipv4ConverterOptions = new IPv4StringBuilderOptions();
				}
				if(ipv4AddressConverter == null) {
					ipv4AddressConverter = IPAddress.addressConverter;
					if(ipv4AddressConverter == null) {
						ipv4AddressConverter = new DefaultAddressConverter();
					}
				}
			}
			this.ipv4ConverterOptions = ipv4ConverterOptions;
			this.converter = ipv4AddressConverter;
		}

		public static IPv6StringBuilderOptions from(IPStringBuilderOptions opts) {
			if(opts instanceof IPv6StringBuilderOptions) {
				return (IPv6StringBuilderOptions) opts;
			}
			return new IPv6StringBuilderOptions(opts.options & ~(MIXED | UPPERCASE | COMPRESSION_ALL_PARTIAL | IPV4_CONVERSIONS));
		}
	}
}
