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

package inet.ipaddr.ipv6;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import inet.ipaddr.Address;
import inet.ipaddr.Address.SegmentValueProvider;
import inet.ipaddr.AddressNetwork.AddressSegmentCreator;
import inet.ipaddr.AddressSection;
import inet.ipaddr.AddressTypeException;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressConverter.DefaultAddressConverter;
import inet.ipaddr.IPAddressSection;
import inet.ipaddr.IPAddressSection.WildcardOptions.WildcardOption;
import inet.ipaddr.IPAddressSegment;
import inet.ipaddr.format.AddressCreator;
import inet.ipaddr.format.AddressDivisionBase;
import inet.ipaddr.format.AddressDivisionGrouping;
import inet.ipaddr.format.AddressDivisionGrouping.StringOptions.Wildcards;
import inet.ipaddr.format.AddressLargeDivision;
import inet.ipaddr.format.AddressStringDivision;
import inet.ipaddr.format.IPAddressBitsDivision;
import inet.ipaddr.format.IPAddressDivision;
import inet.ipaddr.format.IPAddressDivisionGrouping;
import inet.ipaddr.format.IPAddressStringDivisionGrouping;
import inet.ipaddr.format.IPAddressStringDivisionSeries;
import inet.ipaddr.format.util.IPAddressPartConfiguredString;
import inet.ipaddr.format.util.IPAddressPartStringCollection;
import inet.ipaddr.format.util.IPAddressPartStringSubCollection;
import inet.ipaddr.format.util.IPAddressStringWriter;
import inet.ipaddr.format.util.sql.IPAddressSQLTranslator;
import inet.ipaddr.format.util.sql.SQLStringMatcher;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv4.IPv4Address.IPv4AddressConverter;
import inet.ipaddr.ipv4.IPv4AddressNetwork.IPv4AddressCreator;
import inet.ipaddr.ipv4.IPv4AddressSection;
import inet.ipaddr.ipv4.IPv4AddressSection.IPv4StringBuilderOptions;
import inet.ipaddr.ipv4.IPv4AddressSection.IPv4StringOptions;
import inet.ipaddr.ipv4.IPv4AddressSegment;
import inet.ipaddr.ipv6.IPv6AddressNetwork.IPv6AddressCreator;
import inet.ipaddr.ipv6.IPv6AddressSection.CompressOptions.CompressionChoiceOptions;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringCollection.IPv6StringBuilder;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringCollection.IPv6v4MixedStringBuilder;
import inet.ipaddr.mac.MACAddress;
import inet.ipaddr.mac.MACAddressNetwork.MACAddressCreator;
import inet.ipaddr.mac.MACAddressSection;
import inet.ipaddr.mac.MACAddressSegment;

/**
 * 
 * @author sfoley
 *
 */
public class IPv6AddressSection extends IPAddressSection implements Iterable<IPv6AddressSection> {

	private static final long serialVersionUID = 3L;

	private static IPv6AddressCreator creators[] = new IPv6AddressCreator[IPv6Address.SEGMENT_COUNT + 1];

	public static final IPv6AddressSection LINK_LOCAL_PREFIX = 
			getAddressCreator(0).createSection(new IPv6AddressSegment[] {
					getIPv6SegmentCreator().createSegment(0xfe80),
					IPv6AddressSegment.ZERO_SEGMENT,
					IPv6AddressSegment.ZERO_SEGMENT,
					IPv6AddressSegment.ZERO_SEGMENT
			});
	
	static class IPv6StringCache extends IPStringCache {
		//a set of pre-defined string types
		static final IPv6StringOptions mixedParams;
		static final IPv6StringOptions fullParams;

		static final IPv6StringOptions normalizedParams;
		static final IPv6StringOptions canonicalParams;
		static final IPv6StringOptions uncParams;
		static final IPv6StringOptions compressedParams;
		
		static final IPv6StringOptions wildcardNormalizedParams;
		static final IPv6StringOptions wildcardCanonicalParams;
		static final IPv6StringOptions sqlWildcardParams;
		static final IPv6StringOptions wildcardCompressedParams;
		static final IPv6StringOptions networkPrefixLengthParams;
		static final IPv6StringOptions reverseDNSParams;
		
		static final IPStringOptions base85Params;
		
		static {
			CompressOptions 
				compressAll = new CompressOptions(true, CompressOptions.CompressionChoiceOptions.ZEROS_OR_HOST),
				compressMixed = new CompressOptions(true, CompressOptions.CompressionChoiceOptions.MIXED_PREFERRED),
				compressAllNoSingles = new CompressOptions(false, CompressOptions.CompressionChoiceOptions.ZEROS_OR_HOST), 
				compressHostPreferred = new CompressOptions(true, CompressOptions.CompressionChoiceOptions.HOST_PREFERRED),
				compressZeros = new CompressOptions(true, CompressOptions.CompressionChoiceOptions.ZEROS),
				compressZerosNoSingles = new CompressOptions(false, CompressOptions.CompressionChoiceOptions.ZEROS);
			mixedParams = new IPv6StringOptions.Builder().setMakeMixed(true).setCompressOptions(compressMixed).toParams();
			fullParams = new IPv6StringOptions.Builder().setExpandedSegments(true).setWildcardOptions(new WildcardOptions(WildcardOptions.WildcardOption.NETWORK_ONLY, new Wildcards(IPAddress.RANGE_SEPARATOR_STR))).toParams();
			canonicalParams = new IPv6StringOptions.Builder().setCompressOptions(compressAllNoSingles).toParams();
			uncParams = new IPv6StringOptions.Builder().setSeparator(IPv6Address.UNC_SEGMENT_SEPARATOR).setZoneSeparator(IPv6Address.UNC_ZONE_SEPARATOR).
					setAddressSuffix(IPv6Address.UNC_SUFFIX).
					setWildcardOptions(new WildcardOptions(WildcardOptions.WildcardOption.NETWORK_ONLY, new Wildcards(IPv6Address.UNC_RANGE_SEPARATOR_STR, IPAddress.SEGMENT_WILDCARD_STR, null))).toParams();
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
			reverseDNSParams = new IPv6StringOptions.Builder().setReverse(true).setAddressSuffix(IPv6Address.REVERSE_DNS_SUFFIX).setSplitDigits(true).setExpandedSegments(true).setSeparator('.').toParams();
			base85Params = new IPStringOptions.Builder(85).setExpandedSegments(true).setWildcards(new Wildcards(Address.ALTERNATIVE_RANGE_SEPARATOR_STR)).setZoneSeparator(IPv6Address.ALTERNATIVE_ZONE_SEPARATOR).toParams();
		}
		
		public String normalizedString;
		public String compressedString;
		public String mixedString;
		public String compressedWildcardString;									
		public String canonicalWildcardString;
		public String networkPrefixLengthString;
		public String base85String;
		
		//we piggy-back on the section cache for strings that are full address only
		public String uncString;
	}
	
	static class AddressCache extends SectionCache<IPv6Address> {}

	private transient IPv6StringCache stringCache;
	
	private transient SectionCache<IPv6AddressSection> sectionCache;
	
	transient IPv4AddressSection embeddedIPv4Section;//the lowest 4 bytes as IPv4
	transient IPv6v4MixedAddressSection defaultMixedAddressSection;

	/*
	 * Indicates the index of the first segment where this section would be located in a full IPv6 address.  0 for network sections or full addresses
	 */
	public final int startIndex;

	/* also for caching: index of segments that are zero, and the number of consecutive zeros for each. */
	private transient RangeList zeroSegments;
	
	/* also for caching: index of segments that are zero or any value due to CIDR prefix, and the number of consecutive segments for each. */
	private transient RangeList zeroRanges;
	
	/**
	 * Constructs a single segment section, the segment being the leading segment.
	 * 
	 * @param segment
	 */
	public IPv6AddressSection(IPv6AddressSegment segment) {
		this(new IPv6AddressSegment[] {segment}, 0, false);
	}
	
	/**
	 * Constructs a single segment section with the segment at the given index in the address.
	 * 
	 * @param segment
	 */
	public IPv6AddressSection(IPv6AddressSegment segment, int startIndex) {
		this(new IPv6AddressSegment[] {segment}, startIndex, false);
	}
	
	/**
	 * Use this constructor for any address section that includes the leading segment of an IPv6 address
	 */
	public IPv6AddressSection(IPv6AddressSegment segments[]) {
		this(segments, 0, true);
	}
	
	/**
	 * Use this constructor for any address section that includes the leading segment of an IPv6 address
	 * @param segments an array containing the segments.  Segments that are entirely part of the host section need not be provided, although the array must be the correct length.
	 * @param networkPrefixLength
	 */
	public IPv6AddressSection(IPv6AddressSegment segments[], Integer networkPrefixLength) {
		this(segments, 0, networkPrefixLength);
	}
	
	/**
	 * @param startIndex the index of the first segment where this section would be located in a full address, 0 for network sections or full addresses
	 * @param segments an array containing the segments.  Segments that are entirely part of the host section need not be provided, although the array must be the correct length.
	 * @param networkPrefixLength
	 */
	public IPv6AddressSection(IPv6AddressSegment[] segments, int startIndex, Integer networkPrefixLength) {
		this(toPrefixedSegments(networkPrefixLength, segments, IPv6Address.BITS_PER_SEGMENT, getIPv6SegmentCreator(), IPv6AddressSegment::toNetworkSegment, true), startIndex, false);
	}
	
	IPv6AddressSection(IPv6AddressSegment[] segments, int startIndex, boolean cloneSegments) {
		super(segments, null, cloneSegments, false);
		if(startIndex < 0) {
			throw new IllegalArgumentException();
		}
		if(startIndex + segments.length > IPv6Address.SEGMENT_COUNT) {
			throw new IllegalArgumentException(getMessage("ipaddress.error.exceeds.size"));
		}
		this.startIndex = startIndex;
	}
	
	IPv6AddressSection(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefix) {
		super(toSegments(lowerValueProvider, upperValueProvider, IPv6Address.SEGMENT_COUNT, IPv6Address.BYTES_PER_SEGMENT, IPv6Address.BITS_PER_SEGMENT, IPv6Address.MAX_VALUE_PER_SEGMENT, getIPv6SegmentCreator(), prefix), null, false, false);
		this.startIndex = 0;
	}

	IPv6AddressSection(byte bytes[], Integer prefix, boolean cloneBytes) {
		super(toSegments(bytes, IPv6Address.SEGMENT_COUNT, IPv6Address.BYTES_PER_SEGMENT, IPv6Address.BITS_PER_SEGMENT, IPv6Address.MAX_VALUE_PER_SEGMENT, getIPv6SegmentCreator(), prefix), bytes, false, cloneBytes);
		if(bytes.length > IPv6Address.BYTE_COUNT) {
			throw new IllegalArgumentException(getMessage("ipaddress.error.exceeds.size") + ' ' + bytes.length);
		}
		this.startIndex = 0;
	}
	
	/*
	 * Use this constructor for any address section that includes the leading segment of an IPv6 address
	 */
	public IPv6AddressSection(byte bytes[], Integer prefix) {
		this(bytes, prefix, true);
	}
	
	/**
	 * Constructs the corresponding IPv6 address section from a modified EUI-64 (Extended Unique Identifier) address.
	 * 
	 * If the supplied address is an 8 byte EUI-64, then it must match the required EUI-64 format of xx-xx-ff-fe-xx-xx
	 * with the ff-fe section in the middle.
	 * 
	 * If the supplied address is a 6 byte MAC-48 or EUI-48, then the ff-fe pattern will be inserted.
	 * 
	 * The constructor will toggle the MAC U/L (universal/local) bit as required with EUI-64.
	 * 
	 * @throws AddressTypeException when the MAC address is an EUI-64 that cannot be converted to an IPv6 address (ff-fe section in middle)
	 * 
	 * @param eui
	 */
	public IPv6AddressSection(MACAddress eui) {
		this(eui.getSection(), 4, 4);
	}
	
	/**
	 * Constructs the corresponding IPv6 address section from a modified EUI-64 (Extended Unique Identifier) address section.
	 * 
	 * If the supplied address section comes from an 8 byte EUI-64, then it must match the required EUI-64 format of xx-xx-ff-fe-xx-xx
	 * with the ff-fe section in the middle.
	 * 
	 * If the supplied address section comes from a 6 byte MAC-48 or EUI-48, then the ff-fe pattern will be inserted.
	 * 
	 * The constructor will toggle the MAC U/L (universal/local) bit as required with EUI-64.
	 * 
	 * @throws AddressTypeException when the MAC address section is an EUI-64 that cannot be converted to an IPv6 address (ff-fe section in middle)
	 * 
	 * @param eui
	 */
	public IPv6AddressSection(MACAddressSection eui) {
		this(eui, getIPv6StartIndex(eui), getIPv6SegmentCount(eui));
	}
	
	private IPv6AddressSection(MACAddressSection eui, int ipv6StartIndex, int ipv6SegmentCount) {
		super(IPv6Address.toEUI64Segments(getAddressCreator(ipv6StartIndex).createSegmentArray(ipv6SegmentCount), 0, eui, eui.startIndex, eui.isExtended()), 
				eui.getSegmentCount() == 8 ? AddressDivisionGrouping.getCachedBytes(eui) : null,
				false, 
				false);
		this.startIndex = ipv6StartIndex;
	}
	
	private static int getIPv6SegmentCount(MACAddressSection eui) {
		int euiStartIndex = eui.startIndex;
		int euiEndIndex = euiStartIndex + eui.getSegmentCount();
		//we must round up both sides of the subtraction
		int result = (euiEndIndex + 1) >> 1;
		result -= (euiStartIndex >> 1);
		if(!eui.isExtended() && euiStartIndex <= 2 && euiEndIndex >= 4) {
			//if we have a segment 2 but no segment 3, then we just add ff to the end of already counted segment
			//if we have a segment 3 but no segment 2, the same is true
			//so we only add an extra segment if we have both, in which case segment 3 will be shifted to fit an extra segment
			result++;
		}
		return result;
	}
	
	private static int getIPv6StartIndex(MACAddressSection eui) {
		int euiStartIndex = eui.startIndex;
		int result =  4 + (euiStartIndex >> 1);
		if(!eui.isExtended() && euiStartIndex >= 3) {
			result++;
		}
		return result;
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
	public IPv6AddressSection getSection(int index) {
		return getSection(index, getSegmentCount());
	}

	@Override
	public IPv6AddressSection getSection(int index, int endIndex) {
		return getSection(index, endIndex, this, getAddressCreator(startIndex + index));
	}
	
	@Override
	public IPv6AddressSegment[] getSegments() {
		return (IPv6AddressSegment[]) divisions.clone();
	}
	
	private IPv6AddressSection getLowestOrHighestSection(boolean lowest) {
		return getLowestOrHighestSection(
			this,
			getAddressCreator(),
			lowest,
			i -> lowest ? getSegment(i).getLower() : getSegment(i).getUpper(),
			() -> getSectionCache(this, () -> sectionCache, () -> sectionCache = new SectionCache<IPv6AddressSection>()));
	}
	
	IPv6Address getLowestOrHighest(IPv6AddressCreator creator, IPv6Address addr, boolean lowest) {
		return getLowestOrHighestAddress(
			addr,
			creator,
			lowest,
			() -> getLowestOrHighestSection(lowest),
			() -> getSectionCache(addr, () -> addr.sectionCache, () -> addr.sectionCache = new AddressCache()));
	}
	
	@Override
	public IPv6AddressSection getLower() {
		return getLowestOrHighestSection(true);
	}
	
	@Override
	public IPv6AddressSection getUpper() {
		return getLowestOrHighestSection(false);
	}
	
	@Override
	public IPv6AddressSection reverseBits(boolean perByte) {
		return reverseBits(perByte, this, getAddressCreator(), i -> getSegment(i).reverseBits(perByte), true);
	}
	
	@Override
	public IPv6AddressSection reverseBytes() {
		return reverseBytes(false);
	}
	
	@Override
	public IPv6AddressSection reverseBytesPerSegment() {
		return reverseBytes(true);
	}
	
	private IPv6AddressSection reverseBytes(boolean perSegment) {
		return reverseBytes(perSegment, this, getAddressCreator(), i -> getSegment(i).reverseBytes(), true);
	}
	
	@Override
	public IPv6AddressSection reverseSegments() {
		if(getSegmentCount() <= 1) {
			return this;
		}
		return reverseSegments(this, getAddressCreator(), i -> getSegment(i).removePrefixLength(false), true);
	}
	
	@Override
	public Iterable<IPv6AddressSection> getIterable() {
		return this;
	}
	
	@Override
	public Iterator<IPv6AddressSection> iterator() {
		boolean useOriginal = !isMultiple() && !isPrefixed();
		return iterator(
				useOriginal,
				this,
				getAddressCreator(),
				useOriginal ? null : segmentsIterator());
	}
	
	@Override
	public Iterator<IPv6AddressSegment[]> segmentsIterator() {
		return super.iterator(getSegmentCreator(), () -> getLower().getSegments(), index -> getSegment(index).iterator());
	}
	
	protected Iterator<IPv6Address> iterator(
			IPv6Address original,
			AddressCreator<IPv6Address, ?, ?, IPv6AddressSegment> creator) {
		boolean useOriginal = !isMultiple() && !isPrefixed();
		return iterator(
				original, 
				creator,//using a lambda for this one results in a big performance hit
				useOriginal,
				useOriginal ? null : iterator(creator, () -> (IPv6AddressSegment[]) getLower().divisions, index -> getSegment(index).iterator()));
	}

	@Override
	protected BigInteger getCountImpl() {
		int segCount = getSegmentCount();
		if(!isMultiple()) {
			return BigInteger.ONE;
		}
		long result1 = getSegment(0).getValueCount();
		BigInteger big1 = null;
		int limit = Math.min(segCount,  3);
		for(int i = 1; i < limit; i++) {
			result1 *= getSegment(i).getValueCount();
		}
		if(segCount > 3) {
			long otherValue = getSegment(3).getValueCount();
			if(otherValue != 1) {
				if(result1 <= 0x7fffffffffffL) {
					result1 *= otherValue;
				} else {
					big1 = BigInteger.valueOf(result1).multiply(BigInteger.valueOf(otherValue));
				}
			}
		}
		if(segCount > 4) {
			long result2 = getSegment(4).getValueCount();
			BigInteger big2 = null;
			limit = Math.min(segCount,  7);
			for(int i = 5; i < limit; i++) {
				result2 *= getSegment(i).getValueCount();
			}
			if(segCount > 7) {
				long otherValue = getSegment(7).getValueCount();
				if(otherValue != 1) {
					if(result2 <= 0x7fffffffffffL) {
						result2 *= otherValue;
					} else {
						big2 = BigInteger.valueOf(result2).multiply(BigInteger.valueOf(otherValue));
					}
				}
			}
			if(big1 == null) {
				if(big2 == null) {
					if(result1 <= 0xb504f333 && result2 <= 0xb504f333) {
						return BigInteger.valueOf(result1 * result2);
					}
					big2 = BigInteger.valueOf(result2);
				}
				big1 = BigInteger.valueOf(result1);
			} else if(big2 == null) {
				big2 = BigInteger.valueOf(result2);
			}
			return big1.multiply(big2);
		}
		if(big1 != null) {
			return big1;
		}
		return BigInteger.valueOf(result1);
	}
	
	private AddressSegmentCreator<IPv6AddressSegment> getSegmentCreator() {
		return getIPv6SegmentCreator();
	}
	
	private static AddressSegmentCreator<IPv6AddressSegment> getIPv6SegmentCreator() {
		return IPv6Address.network().getAddressCreator();
	}
	
	private IPv6AddressCreator getAddressCreator() {
		return getAddressCreator(startIndex);
	}
	
	protected static IPv6AddressCreator getAddressCreator(int startIndex) {
		IPv6AddressCreator result = creators[startIndex];
		if(result == null) {
			creators[startIndex] = result = new IPv6AddressCreator() {
				@Override
				protected IPv6AddressSection createSectionInternal(IPv6AddressSegment segments[]) {
					return IPv6Address.network().getAddressCreator().createSectionInternal(segments, startIndex); /* address creation */
				}
			};
		}
		return result;
	}
	
	@Override
	public IPv6AddressSegment getSegment(int index) {
		return (IPv6AddressSegment) super.getSegment(index);
	}

	public void getSegments(Collection<? super IPv6AddressSegment> segs) {
		getSegments(0, getSegmentCount(), segs);
	}

	public void getSegments(int start, int end, Collection<? super IPv6AddressSegment> segs) {
		for(int i = start; i < end; i++) {
			segs.add(getSegment(i));
		}
	}
	
	/**
	 * Equivalent to isEUI64(false)
	 * 
	 * @return
	 */
	public boolean isEUI64() {
		return isEUI64(false);
	}
	
	/**
	 * Whether this section is consistent with an EUI64 section,
	 * which means it came from an extended 8 byte address,
	 * and the corresponding segments in the middle match 0xff and 0xfe
	 * 
	 * @param partial whether missing segments are considered a match
	 * @return
	 */
	public boolean isEUI64(boolean partial) {
		int segmentCount = getSegmentCount();
		int endIndex = startIndex + segmentCount;
		if(startIndex <= 5) {
			if(endIndex > 6) {
				int index3 = 5 - startIndex;
				IPv6AddressSegment seg3 = getSegment(index3);
				IPv6AddressSegment seg4 = getSegment(index3 + 1);
				return seg4.matchesWithMask(0xfe00, 0xff00) && seg3.matchesWithMask(0xff, 0xff);
			} else if(partial && endIndex == 6) {
				IPv6AddressSegment seg3 = getSegment(5 - startIndex);
				return seg3.matchesWithMask(0xff, 0xff);
			}
		} else if(partial && startIndex == 6 && endIndex > 6) {
			IPv6AddressSegment seg4 = getSegment(6 - startIndex);
			return seg4.matchesWithMask(0xfe00, 0xff00);
		}
		return partial;
	}
	
	/**
	 * Returns the corresponding mac section, or null if this address section does not correspond to a mac section
	 * @param extended
	 * @return
	 */
	public MACAddressSection toEUI(boolean extended) {
		MACAddressSegment[] segs = toEUISegments(extended);
		if(segs == null) {
			return null;
		}
		MACAddressCreator creator = MACAddress.getAddressCreator();
		return createSectionInternal(creator, segs, Math.max(0, startIndex - 4) << 1, extended);
	}
	
	protected static MACAddressSection createSectionInternal(MACAddressCreator creator, MACAddressSegment[] segments, int startIndex, boolean extended) {
		return AddressDivisionGrouping.createSectionInternal(creator, segments, startIndex, extended);
	}
	
	MACAddressSegment[] toEUISegments(boolean extended) {
		IPv6AddressSegment seg0, seg1, seg2, seg3;
		int start = startIndex;
		int segmentCount = getSegmentCount();
		int segmentIndex;
		if(start < 4) {
			start = 0;
			segmentIndex = 4 - start;
		} else {
			start -= 4;
			segmentIndex = 0;
		}
		int originalSegmentIndex = segmentIndex;
		seg0 = (start == 0 && segmentIndex < segmentCount) ? getSegment(segmentIndex++) : null;
		seg1 = (start <= 1 && segmentIndex < segmentCount) ? getSegment(segmentIndex++) : null;
		seg2 = (start <= 2 && segmentIndex < segmentCount) ? getSegment(segmentIndex++) : null;
		seg3 = (start <= 3 && segmentIndex < segmentCount) ? getSegment(segmentIndex++) : null;
		int macSegCount = (segmentIndex - originalSegmentIndex) << 1;
		if(!extended) {
			macSegCount -= 2;
		}
		if((seg1 != null && !seg1.matchesWithMask(0xff, 0xff)) || (seg2 != null && !seg2.matchesWithMask(0xfe00, 0xff00)) || macSegCount == 0) {
			return null;
		}
		MACAddressCreator creator = MACAddress.getAddressCreator();
		MACAddressSegment newSegs[] = creator.createSegmentArray(macSegCount);
		int macStartIndex = 0;
		if(seg0 != null) {
			seg0.getSplitSegments(newSegs, macStartIndex, creator);
			//toggle the u/l bit
			MACAddressSegment macSegment0 = newSegs[0];
			int lower0 = macSegment0.getLowerSegmentValue();
			int upper0 = macSegment0.getUpperSegmentValue();
			int mask2ndBit = 0x2;
			if(!macSegment0.matchesWithMask(mask2ndBit & lower0, mask2ndBit)) {
				return null;
			}
			//you can use matches with mask
			lower0 ^= mask2ndBit;//flip the universal/local bit
			upper0 ^= mask2ndBit;
			newSegs[0] = creator.createSegment(lower0, upper0, null);
			macStartIndex += 2;
		}
		if(seg1 != null) {
			seg1.getSplitSegments(newSegs, macStartIndex, creator);  //a ff fe b
			if(!extended) {
				newSegs[macStartIndex + 1] = MACAddressSegment.ZERO_SEGMENT;
			}
			macStartIndex += 2;
		}
		if(seg2 != null) {
			if(!extended) {
				if(seg1 != null) {
					macStartIndex -= 2;
					MACAddressSegment first = newSegs[macStartIndex];
					seg2.getSplitSegments(newSegs, macStartIndex, creator);
					newSegs[macStartIndex] = first;
				} else {
					seg2.getSplitSegments(newSegs, macStartIndex, creator);
					newSegs[macStartIndex] = MACAddressSegment.ZERO_SEGMENT;
				}
			} else {
				seg2.getSplitSegments(newSegs, macStartIndex, creator);
			}
			macStartIndex += 2;
		}
		if(seg3 != null) {
			seg3.getSplitSegments(newSegs, macStartIndex, creator);
		}
		return newSegs;
	}

	/**
	 * Produces an IPv4 address section from any sequence of bytes in this IPv6 address section
	 * 
	 * @param startIndex the byte index in this section to start from
	 * @param endIndex the byte index in this section to end at
	 * @throws IndexOutOfBoundsException
	 * @return
	 * 
	 * @see #getEmbeddedIPv4AddressSection()
	 * @see #getMixedAddressSection()
	 */
	public IPv4AddressSection getEmbeddedIPv4AddressSection(int startIndex, int endIndex) {
		if(startIndex == ((IPv6Address.MIXED_ORIGINAL_SEGMENT_COUNT - this.startIndex) << 1) && endIndex == (getSegmentCount() << 1)) {
			return getEmbeddedIPv4AddressSection();
		}
		IPv4AddressCreator creator = IPv4Address.network().getAddressCreator();
		IPv4AddressSegment[] segments = creator.createSegmentArray((endIndex - startIndex) >> 1);
		int i = startIndex, j = 0;
		if(i % IPv6Address.BYTES_PER_SEGMENT == 1) {
			IPv6AddressSegment ipv6Segment = getSegment(i++ / IPv6Address.BYTES_PER_SEGMENT);
			ipv6Segment.getSplitSegments(segments, j++ - 1, creator);
		}
		for(; i < endIndex; i <<= 1, j <<= 1) {
			IPv6AddressSegment ipv6Segment = getSegment(i / IPv6Address.BYTES_PER_SEGMENT);
			ipv6Segment.getSplitSegments(segments, j, creator);
		}
		return createSection(creator, segments);
	}
	
	/**
	 * Gets the IPv4 section corresponding to the lowest (least-significant) 4 bytes in the original address,
	 * which will correspond to between 0 and 4 bytes in this address.  Many IPv4 to IPv6 mapping schemes (but not all) use these 4 bytes for a mapped IPv4 address.
	 * 
	 * @see #getEmbeddedIPv4AddressSection(int, int)
	 * @see #getMixedAddressSection()
	 * @return the embedded IPv4 section or null
	 */
	public IPv4AddressSection getEmbeddedIPv4AddressSection() {
		if(embeddedIPv4Section == null) {
			synchronized(this) {
				if(embeddedIPv4Section == null) {
					int mixedCount = getSegmentCount() - Math.max(IPv6Address.MIXED_ORIGINAL_SEGMENT_COUNT - startIndex, 0);
					int lastIndex = getSegmentCount() - 1;
					IPv4AddressCreator creator = IPv4Address.network().getAddressCreator();
					IPv4AddressSegment[] mixed;
					if(mixedCount == 0) {
						mixed = creator.createSegmentArray(0);
					} else {
						mixed = (mixedCount == 1) ? 
							getSegment(lastIndex).split() : 
							IPv6AddressSegment.split(getSegment(lastIndex - 1), getSegment(lastIndex));
					}
					embeddedIPv4Section = createSection(creator, mixed);
				}
			}
		}
		return embeddedIPv4Section;
	}
	
	public IPv6AddressSection createNonMixedSection() {
		int mixedCount = getSegmentCount() - Math.max(IPv6Address.MIXED_ORIGINAL_SEGMENT_COUNT - startIndex, 0);
		if(mixedCount <= 0) {
			return this;
		}
		int nonMixedCount = Math.max(0, getSegmentCount() - mixedCount);
		IPv6AddressCreator creator = IPv6Address.network().getAddressCreator();
		IPv6AddressSegment[] nonMixed = creator.createSegmentArray(nonMixedCount);
		getSegments(0, nonMixedCount, nonMixed, 0);
		return creator.createSectionInternal(nonMixed, startIndex);
	}
	
	public IPv6v4MixedAddressSection getMixedAddressSection() {
		if(defaultMixedAddressSection == null) {
			synchronized(this) {
				if(defaultMixedAddressSection == null) {
					defaultMixedAddressSection = new IPv6v4MixedAddressSection(
							createNonMixedSection(),
							getEmbeddedIPv4AddressSection());
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
	
	@Override
	protected byte[] getBytesImpl(boolean low) {
		byte bytes[] = new byte[(getBitCount() + 7) >> 3];
		int segmentCount = getSegmentCount();
		for(int i = 0; i < segmentCount; i++) {
			IPv6AddressSegment seg = getSegment(i);
			int byteIndex = i << 1;
			int val = low ? seg.getLowerSegmentValue() : seg.getUpperSegmentValue();
			bytes[byteIndex] = (byte) (val >> 8);
			bytes[byteIndex + 1] = (byte) val;
		}
		return bytes;
	}
	
	/**
	 * Returns whether this subnet or address has alphabetic digits when printed.
	 * 
	 * Note that this method does not indicate whether any address contained within this subnet has alphabetic digits,
	 * only whether the subnet itself when printed has alphabetic digits.
	 * 
	 * @return whether the section has alphabetic digits when printed.
	 */
	public boolean hasUppercaseVariations(int base, boolean lowerOnly) {
		if(base > 10) {
			int count = getSegmentCount();
			for(int i = 0; i < count; i++) {
				IPv6AddressSegment seg = getSegment(i);
				if(seg.hasUppercaseVariations(base, lowerOnly)) {
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
	
	public IPv6AddressSection replace(IPv6AddressSection other, int index) {
		if(index > 0 && getSegment(index - 1).isPrefixed()) {
			throw new AddressTypeException(this, "ipaddress.error.index.exceeds.prefix.length");
		}
		IPv6AddressSection result = replace(this, other, getAddressCreator(), index, true);
		return result;
	}
	
	public IPv6AddressSection prepend(IPv6AddressSection other) {
		int otherSegmentCount = other.getSegmentCount();
		int newStartIndex = startIndex - otherSegmentCount;
		if(newStartIndex < 0) {
			throw new AddressTypeException(this, other, "ipaddress.error.exceeds.size");
		}
		if(otherSegmentCount == 0) {
			return this;
		}
		int segmentCount = getSegmentCount();
		if(startIndex == other.startIndex + otherSegmentCount && segmentCount == 0) {
			return other;
		}
		return append(other, this, getAddressCreator(newStartIndex), true);//will have start index newStartIndex
	}
	
	public IPv6AddressSection append(IPv6AddressSection other) {
		int segmentCount = getSegmentCount();
		int otherSegmentCount = other.getSegmentCount();
		if(startIndex + segmentCount + otherSegmentCount > IPv6Address.SEGMENT_COUNT) {
			throw new AddressTypeException(this, other, "ipaddress.error.exceeds.size");
		}
		if(otherSegmentCount == 0) {
			return this;
		}
		if(startIndex == other.startIndex && segmentCount == 0) {
			return other;
		}
		return append(this, other, getAddressCreator(), true);//will use same start index as this
	}
	
	@Override
	public boolean contains(AddressSection other) {
		return other instanceof IPv6AddressSection &&
				startIndex == ((IPv6AddressSection) other).startIndex && 
				super.contains((IPAddressSection) other);
	}
	
	@Override
	protected boolean isSameGrouping(AddressDivisionGrouping other) {
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
	
	/**
	 * Subtract the give subnet from this subnet, returning an array of sections for the result (the subnets will not be contiguous so an array is required).
	 * 
	 * Computes the subnet difference, the set of addresses in this address section but not in the provided section.
	 * 
	 * Keep in mind this is set subtraction, not subtraction of segment values.  We have a subnet of addresses and we are removing some of those addresses.
	 * 
	 * @param other
	 * @throws AddressTypeException if the two sections are not comparable
	 * @return the difference
	 */
	public IPv6AddressSection[] subtract(IPv6AddressSection other) {
		return subtract(this, other, getAddressCreator(), this::getSegment, (section, prefix) -> section.applyPrefixLength(prefix));
	}
	
	@Override
	public int getByteIndex(int networkPrefixLength) {
		return getByteIndex(networkPrefixLength, IPv6Address.BYTE_COUNT);
	}
	
	@Override
	public int getSegmentIndex(int networkPrefixLength) {
		return getSegmentIndex(networkPrefixLength, IPv6Address.BYTE_COUNT, IPv6Address.BYTES_PER_SEGMENT);
	}
	
	@Override
	public IPv6AddressNetwork getNetwork() {
		return IPv6Address.network();
	}

	@Override
	public IPv6AddressSection adjustPrefixBySegment(boolean nextSegment) {
		return (IPv6AddressSection) super.adjustPrefixBySegment(nextSegment);
	}
	
	@Override
	public IPv6AddressSection adjustPrefixLength(int adjustment) {
		return (IPv6AddressSection) adjustPrefixLength(this, adjustment, getAddressCreator(), getNetwork(), (section, i) -> section.getSegment(i));
	}
	
	@Override
	public IPv6AddressSection applyPrefixLength(int networkPrefixLength) {
		return setPrefixLength(networkPrefixLength, false, true);
	}
	
	@Override
	public IPv6AddressSection setPrefixLength(int networkPrefixLength) {
		return setPrefixLength(networkPrefixLength, true, false);
	}
	
	@Override
	public IPv6AddressSection setPrefixLength(int networkPrefixLength, boolean withZeros) {
		return setPrefixLength(networkPrefixLength, withZeros, false);
	}
	
	private IPv6AddressSection setPrefixLength(int networkPrefixLength, boolean withZeros, boolean noShrink) {
		return setPrefixLength(
				this,
				getAddressCreator(),
				networkPrefixLength,
				withZeros,
				noShrink,
				getNetwork(),
				(section, i) -> section.getSegment(i));
	}

	public IPv6AddressSection mask(IPv6AddressSection mask) throws AddressTypeException {
		super.checkSectionCount(mask);
		return getSubnetSegments(this, null, getAddressCreator(), true, this::getSegment, mask::getSegment);
	}
	
	@Override
	public IPv6AddressSection removePrefixLength() {
		return removePrefixLength(true);
	}
	
	@Override
	public IPv6AddressSection removePrefixLength(boolean zeroed) {
		return removePrefixLength(zeroed, true);
	}
	
	protected IPv6AddressSection removePrefixLength(boolean zeroed, boolean onlyPrefixZeroed) {
		return removePrefixLength(this, zeroed, onlyPrefixZeroed, getAddressCreator(), getNetwork(), (section, i) -> section.getSegment(i));
	}
	
	/**
	 * Applies the given mask to the network section of the address as indicated by the given prefix length.
	 * Useful for subnetting.  Once you have zeroed a section of the network you can insert bits 
	 * using {@link #bitwiseOr(IPv6AddressSection)} or {@link #replace(IPv6AddressSection, int)}
	 * 
	 * @param mask
	 * @param networkPrefixLength
	 * @return
	 * @throws AddressTypeException
	 */
	public IPv6AddressSection maskNetwork(IPv6AddressSection mask, int networkPrefixLength) throws AddressTypeException {
		super.checkSectionCount(mask);
		return getSubnetSegments(this, networkPrefixLength, getAddressCreator(), true, this::getSegment, mask::getSegment);
	}
	
	/**
	 * Does the bitwise disjunction with this address.  Useful when subnetting.
	 * Any existing prefix is dropped.
	 * 
	 * @param mask
	 * @return
	 * @throws AddressTypeException
	 */
	public IPv6AddressSection bitwiseOr(IPv6AddressSection mask) throws AddressTypeException {
		super.checkSectionCount(mask);
		return getOredSegments(this, null, getAddressCreator(), this::getSegment, mask::getSegment);
	}
	
	/**
	 * Does the bitwise disjunction with this address.  Useful when subnetting.
	 * 
	 * Any existing prefix length is dropped for the new prefix length and the mask is applied up to the end the new prefix length.
	 * 
	 * @param mask
	 * @return
	 * @throws AddressTypeException
	 */
	public IPv6AddressSection bitwiseOrNetwork(IPv6AddressSection mask, int networkPrefixLength) throws AddressTypeException {
		super.checkSectionCount(mask);
		return getOredSegments(this, networkPrefixLength, getAddressCreator(), this::getSegment, mask::getSegment);
	}
	
	@Override
	public IPv6AddressSection getNetworkSection(int networkPrefixLength) {
		return getNetworkSection(networkPrefixLength, true);
	}
	
	@Override
	public IPv6AddressSection getNetworkSection(int networkPrefixLength, boolean withPrefixLength) {
		int cidrSegmentCount = getNetworkSegmentCount(networkPrefixLength);
		return getNetworkSection(this, networkPrefixLength, cidrSegmentCount, withPrefixLength, getAddressCreator(), (i, prefix) -> getSegment(i).toNetworkSegment(prefix, withPrefixLength));
	}
	
	@Override
	public IPv6AddressSection getHostSection(int networkPrefixLength) {
		int cidrSegmentCount = getHostSegmentCount(networkPrefixLength);
		IPv6AddressCreator creator = getAddressCreator(startIndex + (getSegmentCount() - cidrSegmentCount));
		return getHostSection(this, networkPrefixLength, cidrSegmentCount, creator, (i, prefix) -> getSegment(i).toHostSegment(prefix));
	}
	
	////////////////string creation below ///////////////////////////////////////////////////////////////////////////////////////////

	@Override
	protected boolean hasNoStringCache() {
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
	
	@Override
	protected IPv6StringCache getStringCache() {
		return stringCache;
	}
	
	/**
	 * This produces the shortest valid string for the address.
	 */
	@Override
	public String toCompressedString() {
		String result;
		if(hasNoStringCache() || (result = getStringCache().compressedString) == null) {
			getStringCache().compressedString = result = toNormalizedString(IPv6StringCache.compressedParams);
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
		if(hasNoStringCache() || (result = stringCache.canonicalString) == null) {
			stringCache.canonicalString = result = toNormalizedString(IPv6StringCache.canonicalParams);
		}
		return result;
	}
	
	/**
	 * This produces the mixed IPv6/IPv4 string.  It is the shortest such string (ie fully compressed).
	 */
	public String toMixedString() {
		String result;
		if(hasNoStringCache() || (result = getStringCache().mixedString) == null) {
			getStringCache().mixedString = result = toNormalizedString(IPv6StringCache.mixedParams);
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
		if(hasNoStringCache() || (result = getStringCache().fullString) == null) {
			getStringCache().fullString = result = toNormalizedString(IPv6StringCache.fullParams);
		}
		return result;
	}
	
	@Override
	public String toCompressedWildcardString() {
		String result;
		if(hasNoStringCache() || (result = getStringCache().compressedWildcardString) == null) {
			getStringCache().compressedWildcardString = result = toNormalizedString(IPv6StringCache.wildcardCompressedParams);
		}
		return result;
	}
	
	@Override
	public String toPrefixLengthString() {
		String result;
		if(hasNoStringCache() || (result = getStringCache().networkPrefixLengthString) == null) {
			getStringCache().networkPrefixLengthString = result = toNormalizedString(IPv6StringCache.networkPrefixLengthParams);
		}
		return result;
	}
	
	@Override
	public String toSubnetString() {
		return toPrefixLengthString();
	}
	
	@Override
	public String toCanonicalWildcardString() {
		String result;
		if(hasNoStringCache() || (result = getStringCache().canonicalWildcardString) == null) {
			getStringCache().canonicalWildcardString = result = toNormalizedString(IPv6StringCache.wildcardCanonicalParams);
		}
		return result;
	}
	
	@Override
	public String toNormalizedWildcardString() {
		String result;
		if(hasNoStringCache() || (result = getStringCache().normalizedWildcardString) == null) {
			getStringCache().normalizedWildcardString = result = toNormalizedString(IPv6StringCache.wildcardNormalizedParams);
		}
		return result;
	}
	
	@Override
	public String toSQLWildcardString() {
		String result;
		if(hasNoStringCache() || (result = getStringCache().sqlWildcardString) == null) {
			getStringCache().sqlWildcardString = result = toNormalizedString(IPv6StringCache.sqlWildcardParams);
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
		if(hasNoStringCache() || (result = getStringCache().normalizedString) == null) {
			getStringCache().normalizedString = result = toNormalizedString(IPv6StringCache.normalizedParams);
		}
		return result;
	}
	
	/**
	 * The base 85 string is described by RFC 1924
	 * @return
	 */
	public String toBase85String() {
		String result;
		if(hasNoStringCache() || (result = getStringCache().base85String) == null) {
			getStringCache().base85String = result = toBase85String(null);
		}
		return result;
	}
	
	String toBase85String(String zone) {
		Integer prefixLength = getNetworkPrefixLength();
		AddressLargeDivision largeDiv;
		if(isDualString()) {
			largeDiv = new AddressLargeDivision(getBytes(), getUpperBytes(), getBitCount(), 85, prefixLength);
		} else {
			largeDiv = new AddressLargeDivision(getBytes(), getBitCount(), 85, prefixLength);
		}
		IPAddressStringDivisionSeries part = new IPAddressStringDivisionGrouping(new AddressDivisionBase[] { largeDiv }, prefixLength);
		return toNormalizedString(IPv6StringCache.base85Params, zone, part);
	}

	@Override
	protected void cacheNormalizedString(String str) {
		if(hasNoStringCache() || getStringCache().normalizedString == null) {
			getStringCache().normalizedString = str;
		}
	}
	
	@Override
	public String toReverseDNSLookupString() {
		String result;
		if(hasNoStringCache() || (result = getStringCache().reverseDNSString) == null) {
			IPStringCache stringCache = getStringCache();
			stringCache.reverseDNSString = result = toNormalizedString(IPv6StringCache.reverseDNSParams, "");
		}
		return result;
	}
	
	@Override
	protected String toBinaryString(CharSequence zone) {
		if(isDualString()) {
			IPAddressStringParams<IPAddressStringDivisionSeries> params = toIPParams(IPStringCache.binaryParams);
			return toNormalizedStringRange(params, getLower(), getUpper(), zone);
		}
		return toNormalizedString(IPStringCache.binaryParams, zone);
	}
	
	@Override
	protected String toHexString(boolean with0xPrefix, CharSequence zone) {
		if(isDualString()) {
			IPAddressStringParams<IPAddressStringDivisionSeries> params = toIPParams(with0xPrefix ? IPStringCache.hexPrefixedParams : IPStringCache.hexParams);
			return toNormalizedStringRange(params, getLower(), getUpper(), zone);
		}
		return toNormalizedString(with0xPrefix ? IPStringCache.hexPrefixedParams : IPStringCache.hexParams, zone);
	}
	
	@Override
	protected String toOctalString(boolean with0Prefix, CharSequence zone) {
		if(zone == null) {
			return super.toOctalString(with0Prefix, null);
		}
		IPAddressStringParams<IPAddressStringDivisionSeries> params = toIPParams(with0Prefix ? IPStringCache.octalPrefixedParams : IPStringCache.octalParams);
		if(isDualString()) {
			IPv6AddressSection lower = getLower();
			IPv6AddressSection upper = getUpper();
			IPAddressBitsDivision lowerDivs[] = lower.createNewDivisions(3, IPAddressBitsDivision::new, IPAddressBitsDivision[]::new);
			IPAddressStringDivisionSeries lowerPart = new IPAddressDivisionGrouping(lowerDivs);
			IPAddressBitsDivision upperDivs[] = upper.createNewDivisions(3, IPAddressBitsDivision::new, IPAddressBitsDivision[]::new);
			IPAddressStringDivisionSeries upperPart = new IPAddressDivisionGrouping(upperDivs);
			return toNormalizedStringRange(params, lowerPart, upperPart, zone);
		}
		IPAddressBitsDivision divs[] = createNewPrefixedDivisions(3, getNetworkPrefixLength(), IPAddressBitsDivision::new, IPAddressBitsDivision[]::new);
		IPAddressStringDivisionSeries part = new IPAddressDivisionGrouping(divs);
		return params.toString(part, zone);
	}

	@Override
	public String toNormalizedString(IPStringOptions options) {
		if(options instanceof IPv6StringOptions) {
			return toNormalizedString((IPv6StringOptions) options);
		}
		return super.toNormalizedString(options);
	}
	
	public String toNormalizedString(IPv6StringOptions options) {
		return toNormalizedString(options, (String) null);
	}
	
	private String toNormalizedMixedString(IPv6v4MixedParams mixedParams, CharSequence zone) {
		IPv6v4MixedAddressSection mixed = getMixedAddressSection();
		String result = mixedParams.toString(mixed, zone);
		return result;
	}
	
	String toNormalizedString(IPStringOptions options, CharSequence zone) {
		if(zone == null) {
			return toNormalizedString(options);
		}
		if(options instanceof IPv6StringOptions) {
			return toNormalizedString((IPv6StringOptions) options, zone);
		}
		IPAddressStringParams<IPAddressStringDivisionSeries> params = toIPParams(options);
		return params.toString(this, zone);
	}
	
	public String toNormalizedString(IPv6StringOptions options, CharSequence zone) {
		IPv6StringParams stringParams;
		if(options.compressOptions == null) {
			IPAddressStringWriter<?> cachedParams = (IPAddressStringWriter<?>) getCachedParams(options);
			if(cachedParams == null) {
				stringParams = options.from(this);
				if(options.makeMixed()) {
					IPv6v4MixedParams mixedParams = new IPv6v4MixedParams(stringParams, options.ipv4Opts);
					setCachedParams(options, mixedParams);
					return toNormalizedMixedString(mixedParams, zone);
				} else {
					setCachedParams(options, stringParams);
				}
			} else {
				if(cachedParams instanceof IPv6v4MixedParams) {
					return toNormalizedMixedString((IPv6v4MixedParams) cachedParams, zone);
				}
				stringParams = (IPv6StringParams) cachedParams;
			}
		} else {
			//no caching is possible due to the compress options
			stringParams = options.from(this);
			if(options.makeMixed() && stringParams.nextUncompressedIndex <= IPv6Address.MIXED_ORIGINAL_SEGMENT_COUNT - startIndex) {//the mixed section is not compressed
				return toNormalizedMixedString(new IPv6v4MixedParams(stringParams, options.ipv4Opts), zone);
			}
		}
		return stringParams.toString(this, zone);
	}
	
	public static String toNormalizedString(IPStringOptions options, CharSequence zone, IPAddressStringDivisionSeries part) {
		AddressStringParams<IPAddressStringDivisionSeries> params = toParams(options);
		String result = params.toString(part, zone);
		return result;
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

	IPv6StringCollection toStringCollection(IPv6StringBuilderOptions opts, CharSequence zone) {
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
	public IPAddressStringDivisionSeries[] getParts(IPStringBuilderOptions opts) {
		return getParts(IPv6StringBuilderOptions.from(opts));
	}
	
	public IPAddressStringDivisionSeries[] getParts(IPv6StringBuilderOptions opts) {
		if(opts.includes(IPv6StringBuilderOptions.MIXED)) {
			if(opts.includes(IPStringBuilderOptions.BASIC)) {
				return new IPAddressStringDivisionSeries[] { this, getMixedAddressSection() };
			}
			return new IPAddressStringDivisionSeries[] { getMixedAddressSection() };
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
	public static class IPv6StringOptions extends IPStringOptions {
		public final IPStringOptions ipv4Opts;

		//can be null, which means no compression
		public final CompressOptions compressOptions;
		
		
		IPv6StringOptions(
				int base,
				boolean expandSegments,
				WildcardOption wildcardOption,
				Wildcards wildcards,
				String segmentStrPrefix,
				boolean makeMixed,
				IPStringOptions ipv4Opts,
				CompressOptions compressOptions,
				Character separator,
				char zoneSeparator,
				String addressPrefix,
				String addressSuffix,
				boolean reverse,
				boolean splitDigits,
				boolean uppercase) {
			super(base, expandSegments, wildcardOption, wildcards, segmentStrPrefix, separator, zoneSeparator, addressPrefix, addressSuffix, reverse, splitDigits, uppercase);
			this.compressOptions = compressOptions;
			if(makeMixed) {
				if(ipv4Opts == null) {
					ipv4Opts = new IPv4StringOptions.Builder().
							setExpandedSegments(expandSegments).setWildcardOption(wildcardOption).setWildcards(wildcards).toParams();
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
			result.expandSegments(expandSegments);
			result.setWildcardOption(wildcardOption);
			result.setWildcards(wildcards);
			result.setSeparator(separator);
			result.setAddressSuffix(addrSuffix);
			result.setAddressLabel(addrLabel);
			result.setReverse(reverse);
			result.setSplitDigits(splitDigits);
			result.setZoneSeparator(zoneSeparator);
			result.setUppercase(uppercase);
			result.setRadix(base);
			result.setSegmentStrPrefix(segmentStrPrefix);
			return result;
		}
		
		public static IPv6StringOptions from(IPStringOptions opts) {
			if(opts instanceof IPv6StringOptions) {
				return (IPv6StringOptions) opts;
			}
			return new IPv6StringOptions(
					opts.base,
					opts.expandSegments,
					opts.wildcardOption,
					opts.wildcards,
					opts.segmentStrPrefix,
					false,
					null,
					null,
					opts.separator,
					IPv6Address.ZONE_SEPARATOR,
					opts.addrLabel,
					opts.addrSuffix,
					opts.reverse,
					opts.splitDigits,
					opts.uppercase);
		}
		
		public static class Builder extends IPStringOptions.Builder {
			private boolean makeMixed;
			private IPStringOptions ipv4Options;
			
			//default is null, which means no compression
			private CompressOptions compressOptions;
			
			
			public Builder() {
				super(IPv6Address.DEFAULT_TEXTUAL_RADIX, IPv6Address.SEGMENT_SEPARATOR);
			}
			
			public Builder setCompressOptions(CompressOptions compressOptions) {
				this.compressOptions = compressOptions;
				return this;
			}
			
			public Builder setMakeMixed(boolean makeMixed) {
				this.makeMixed = makeMixed;
				return this;
			}
			
			public Builder setMakeMixed(IPStringOptions ipv4Options) {
				this.makeMixed = true;
				this.ipv4Options = ipv4Options;
				return this;
			}
			
			@Override
			public Builder setWildcardOptions(WildcardOptions wildcardOptions) {
				return (Builder) super.setWildcardOptions(wildcardOptions);
			}
			
			@Override
			public Builder setExpandedSegments(boolean expandSegments) {
				return (Builder) super.setExpandedSegments(expandSegments);
			}
			
			@Override
			public Builder setRadix(int base) {
				return (Builder) super.setRadix(base);
			}
			
			@Override
			public Builder setSeparator(Character separator) {
				return (Builder) super.setSeparator(separator);
			}
			
			@Override
			public Builder setZoneSeparator(char separator) {
				return (Builder) super.setZoneSeparator(separator);
			}
			
			@Override
			public Builder setAddressSuffix(String suffix) {
				return (Builder) super.setAddressSuffix(suffix);
			}
			
			@Override
			public Builder setSegmentStrPrefix(String prefix) {
				return (Builder) super.setSegmentStrPrefix(prefix);
			}
			
			@Override
			public Builder setReverse(boolean reverse) {
				return (Builder) super.setReverse(reverse);
			}
			
			@Override
			public Builder setUppercase(boolean upper) {
				return (Builder) super.setUppercase(upper);
			}
			
			@Override
			public Builder setSplitDigits(boolean splitDigits) {
				return (Builder) super.setSplitDigits(splitDigits);
			}
			
			@Override
			public IPv6StringOptions toParams() {
				return new IPv6StringOptions(base, expandSegments, wildcardOption, wildcards, segmentStrPrefix, makeMixed, ipv4Options, compressOptions, separator, zoneSeparator, addrLabel, addrSuffix, reverse, splitDigits, uppercase);
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
	
	/**
	 * Each IPv6StringParams has settings to write exactly one IPv6 address section string
	 * 
	 * @author sfoley
	 *
	 */
	static class IPv6StringParams extends IPAddressStringParams<IPv6AddressSection> {
		
		int firstCompressedSegmentIndex, nextUncompressedIndex; //the start and end of any compressed section
		
		boolean hostCompressed; //whether the host was compressed, which means we must print the network prefix
		
		IPv6StringParams() {
			this(-1, 0);
		}
		
		IPv6StringParams(int firstCompressedSegmentIndex, int compressedCount) {
			this(false, firstCompressedSegmentIndex, compressedCount, false, IPv6Address.SEGMENT_SEPARATOR, IPv6Address.ZONE_SEPARATOR);
		}
		
		private IPv6StringParams(
				boolean expandSegments,
				int firstCompressedSegmentIndex,
				int compressedCount,
				boolean uppercase, 
				char separator,
				char zoneSeparator) {
			super(IPv6Address.DEFAULT_TEXTUAL_RADIX, separator, uppercase, zoneSeparator);
			this.expandSegments(expandSegments);
			this.firstCompressedSegmentIndex = firstCompressedSegmentIndex;
			this.nextUncompressedIndex = firstCompressedSegmentIndex + compressedCount;
		}
		
		public boolean endIsCompressed(IPAddressStringDivisionSeries addr) {
			return nextUncompressedIndex >= addr.getDivisionCount();
		}
		
		public boolean isCompressed(IPAddressStringDivisionSeries addr) {
			return firstCompressedSegmentIndex >= 0;
		}
		
		@Override
		public int getTrailingSeparatorCount(IPv6AddressSection addr) {
			return getTrailingSepCount(addr);
		}
		
		public int getTrailingSepCount(IPAddressStringDivisionSeries addr) {
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
		public int getStringLength(IPv6AddressSection addr) {
			int count = getSegmentsStringLength(addr);
			if(!isReverse() && (!preferWildcards() || hostCompressed)) {
				count += getPrefixStringLength(addr);
			}
			//count += getZoneLength();
			count += getAddressSuffixLength();
			count += getAddressLabelLength();
			return count;
		}
		
		@Override
		public StringBuilder append(StringBuilder builder, IPv6AddressSection addr, CharSequence zone) {
			appendLabel(builder);
			appendSegments(builder, addr);
			/* 
			 * Our order is zone, then suffix, then prefix length.  This is documented in more detail for the IPv6-only case.
			 */
			if(zone != null) {
				appendZone(builder, zone);
			}
			appendSuffix(builder);
			if(!isReverse() && (!preferWildcards() || hostCompressed)) {
				appendPrefixIndicator(builder, addr);
			}
			return builder;
		}

		 /**
		 * @see inet.ipaddr.format.util.IPAddressPartStringCollection.IPAddressStringParams#appendSegments(java.lang.StringBuilder, inet.ipaddr.format.IPAddressStringDivisionSeries)
		 */
		@Override
		public StringBuilder appendSegments(StringBuilder builder, IPv6AddressSection addr) {
			int divisionCount = addr.getDivisionCount();
			if(divisionCount <= 0) {
				return builder;
			}
			int lastIndex = divisionCount - 1;
			Character separator = getSeparator();
			boolean reverse = isReverse();
			int i = 0;
			while(true) {
				int segIndex = reverse ? lastIndex - i : i;
				if(segIndex < firstCompressedSegmentIndex || segIndex >= nextUncompressedIndex) {
					AddressStringDivision seg = addr.getDivision(segIndex);
					appendSegment(segIndex, seg, builder);
					if(++i > lastIndex) {
						break;
					}
					if(separator != null) {
						builder.append(separator);
					}
				} else {
					if(segIndex == (reverse ? nextUncompressedIndex - 1 :  firstCompressedSegmentIndex) && separator != null) { //the segment is compressed
						builder.append(separator);
						if(i == 0) {//when compressing the front we use two separators
							builder.append(separator);
						}
					} //else we are in the middle of a compressed set of segments, so nothing to write
					if(++i > lastIndex) {
						break;
					}
				}
			}
			return builder;
		}

		@Override
		public int getSegmentsStringLength(IPv6AddressSection part) {
			int count = 0;
			int divCount = part.getDivisionCount();
			if(divCount != 0) {
				Character separator = getSeparator();
				int i = 0;
				while(true) {
					if(i < firstCompressedSegmentIndex || i >= nextUncompressedIndex) {
						IPAddressDivision seg = part.getDivision(i);
						count += appendSegment(i, seg, null);
						if(++i >= divCount) {
							break;
						}
						if(separator != null) {
							count++;
						}
					} else {
						if(i == firstCompressedSegmentIndex && separator != null) { //the segment is compressed
							count++;
							if(i == 0) {//when compressing the front we use two separators
								count++;
							}
						} //else we are in the middle of a compressed set of segments, so nothing to write
						if(++i >= divCount) {
							break;
						}
					}
				}
			}
			return count;
		}
		
		@Override
		public IPv6StringParams clone() {
			return (IPv6StringParams) super.clone();
		}
	}

	public static class IPv6v4MixedAddressSection extends IPAddressDivisionGrouping {

		private static final long serialVersionUID = 3L;
		
		private final IPv6AddressSection ipv6Section;
		private final IPv4AddressSection ipv4Section;
		private String string;
		
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
			ipv6Section.getSegments(0, ipv6Len, allSegs, 0);
			ipv4Section.getSegments(0, ipv4Len, allSegs, ipv6Len);
			return allSegs;
		}

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
				IPStringOptions ipv4Opts = mixedParams.ipv4Opts;
				IPv6v4MixedParams parms = new IPv6v4MixedParams(ipv6Params, ipv4Opts);
				string = parms.toString(this);
			}
			return string;
		}
		
		@Override
		protected boolean isSameGrouping(AddressDivisionGrouping o) {
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
	
	static class IPv6v4MixedParams implements IPAddressStringWriter<IPv6v4MixedAddressSection>, Cloneable {
		private IPAddressStringParams<IPAddressStringDivisionSeries> ipv4Params; //params for the IPv4 part of a mixed IPv6/IPv4 address a:b:c:d:e:f:1.2.3.4
		private IPv6StringParams ipv6Params;
		
		@SuppressWarnings("unchecked")
		IPv6v4MixedParams(IPv6AddressSectionString ipv6Variation, IPAddressPartConfiguredString<?, ?> ipv4Variation) {
			this.ipv4Params = (IPAddressStringParams<IPAddressStringDivisionSeries>) ipv4Variation.stringParams;
			this.ipv6Params = ipv6Variation.stringParams;
		}
		
		IPv6v4MixedParams(IPv6StringParams ipv6Params, IPStringOptions ipv4Opts) {
			this.ipv4Params = IPAddressSection.toIPParams(ipv4Opts);
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
		
		public int getStringLength(IPv6v4MixedAddressSection addr, CharSequence zone) {
			int ipv6length = ipv6Params.getSegmentsStringLength(addr.ipv6Section);
			int ipv4length = ipv4Params.getSegmentsStringLength(addr.ipv4Section);
			int length = ipv6length + ipv4length;
			if(ipv6Params.nextUncompressedIndex < addr.ipv6Section.getSegmentCount()) {
				length++;
			}
			length += getPrefixStringLength(addr);
			length += ipv6Params.getZoneLength(zone);
			length += ipv6Params.getAddressSuffixLength();
			length += ipv6Params.getAddressLabelLength();
			return length;
		}
		
		@Override
		public String toString(IPv6v4MixedAddressSection addr) {
			return toString(addr, null);
		}
		
		@Override
		public String toString(IPv6v4MixedAddressSection addr, CharSequence zone) {
			int length = getStringLength(addr, zone);
			StringBuilder builder = new StringBuilder(length);
			append(builder, addr, zone);
			AddressStringParams.checkLengths(length, builder);
			return builder.toString();
		}
		
		@Override
		public int getDivisionStringLength(AddressStringDivision seg) {
			return ipv6Params.getDivisionStringLength(seg);
		}
		
		@Override
		public StringBuilder appendDivision(StringBuilder builder, AddressStringDivision seg) {
			return ipv6Params.appendDivision(builder, seg);
		}
		
		public StringBuilder append(StringBuilder builder, IPv6v4MixedAddressSection addr, CharSequence zone) {
			ipv6Params.appendLabel(builder);
			ipv6Params.appendSegments(builder, addr.ipv6Section);
			if(ipv6Params.nextUncompressedIndex < addr.ipv6Section.getSegmentCount()) {
				builder.append(ipv6Params.getTrailingSegmentSeparator());
			}
			ipv4Params.appendSegments(builder, addr.ipv4Section);
			
			/* 
			 * rfc 4038: for bracketed addresses, zone is inside and prefix outside, putting prefix after zone. 
			 * 
			 * Suffixes are things like .in-addr.arpa, .ip6.arpa, .ipv6-literal.net
			 * which generally convert an address string to a host
			 * As with our HostName, we support host/prefix in which case the prefix is applied
			 * to the resolved address.
			 * 
			 * So in summary, our order is zone, then suffix, then prefix length.
			 */
			ipv6Params.appendZone(builder, zone);
			ipv6Params.appendSuffix(builder);
			appendPrefixIndicator(builder, addr);
			return builder;
		}

		protected int getPrefixStringLength(IPv6v4MixedAddressSection addr) {
			if(requiresPrefixIndicator(addr.ipv6Section) || requiresPrefixIndicator(addr.ipv4Section)) {
				return IPAddressStringParams.getPrefixStringLength(addr);
			}
			return 0;
		}
		
		public void appendPrefixIndicator(StringBuilder builder, IPv6v4MixedAddressSection addr) {
			if(requiresPrefixIndicator(addr.ipv6Section) || requiresPrefixIndicator(addr.ipv4Section)) {
				ipv6Params.appendPrefixIndicator(builder, addr);
			}
		}
		
		protected boolean requiresPrefixIndicator(IPv4AddressSection ipv4Section)    {
			return ipv4Section.isPrefixed() && !ipv4Params.preferWildcards();
		}
		
		protected boolean requiresPrefixIndicator(IPv6AddressSection ipv6Section)    {
			return ipv6Section.isPrefixed() && (!ipv6Params.preferWildcards() || ipv6Params.hostCompressed);
		}
		
		@Override
		public IPv6v4MixedParams clone() {
			try {
				IPv6v4MixedParams params = (IPv6v4MixedParams) super.clone();
				params.ipv6Params = ipv6Params.clone();
				params.ipv4Params = ipv4Params.clone();
				return params;
			} catch(CloneNotSupportedException e) {
				 return null;
			}
		}
	}

	static class IPv6AddressSectionStringCollection extends IPAddressPartStringSubCollection<IPv6AddressSection, IPv6StringParams, IPv6AddressSectionString> {
		private final CharSequence zone;
		
		IPv6AddressSectionStringCollection(IPv6AddressSection addr, CharSequence zone) {
			super(addr);
			this.zone = zone;
		}
		
		@Override
		public Iterator<IPv6AddressSectionString> iterator() {
			return new IPAddressConfigurableStringIterator() {
				@Override
				public IPv6AddressSectionString next() {
					return new IPv6AddressSectionString(part, iterator.next(), zone); 
				}
			};
		}
	}
	
	static class IPv6v4MixedStringCollection
		extends IPAddressPartStringSubCollection<IPv6v4MixedAddressSection, IPv6v4MixedParams, IPAddressPartConfiguredString<IPv6v4MixedAddressSection, IPv6v4MixedParams>> {
	
		private final CharSequence zone;
		
		public IPv6v4MixedStringCollection(IPv6v4MixedAddressSection part, CharSequence zone) {
			super(part);
			this.zone = zone;
		}
		
		@Override
		public Iterator<IPAddressPartConfiguredString<IPv6v4MixedAddressSection, IPv6v4MixedParams>> iterator() {
			return new IPAddressConfigurableStringIterator() {
				@Override
				public IPAddressPartConfiguredString<IPv6v4MixedAddressSection, IPv6v4MixedParams> next() {
					return new IPAddressPartConfiguredString<IPv6v4MixedAddressSection, IPv6v4MixedParams>(part, iterator.next()) {
						
						@Override
						public String getString() {
							if(string == null) {
								string = stringParams.toString(addr, zone);
							}
							return string;
						}
					};
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
		
			IPv6StringBuilder(IPv6AddressSection address, IPv6StringBuilderOptions opts, CharSequence zone) {
				super(address,  opts, new IPv6AddressSectionStringCollection(address, zone));
			}
			
			private void addUppercaseVariations(ArrayList<IPv6StringParams> allParams, int base) {
				boolean lowerOnly = true; //by default we use NETWORK_ONLY wildcards (we use prefix notation otherwise) so here we check lower values only for alphabetic
				if(options.includes(IPv6StringBuilderOptions.UPPERCASE) && addressSection.hasUppercaseVariations(base, lowerOnly)) {
					int len = allParams.size();
					for(int j=0; j<len; j++) {
						IPv6StringParams clone = allParams.get(j);
						clone = clone.clone();
						clone.setUppercase(true);
						allParams.add(clone);
					}
				}
			}
			
			private void addAllExpansions(int firstCompressedIndex, int count, int segmentCount) {
				IPv6StringParams stringParams = new IPv6StringParams(firstCompressedIndex, count);
				int base = stringParams.getRadix();
				final ArrayList<IPv6StringParams> allParams = new ArrayList<>();
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
			private final CharSequence zone;
			
			IPv6v4MixedStringBuilder(IPv6v4MixedAddressSection address, IPv6StringBuilderOptions opts, CharSequence zone) {
				super(address, opts, new IPv6v4MixedStringCollection(address, zone));
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
		private final CharSequence zone;
		
		IPv6AddressSectionString(IPv6AddressSection addr, IPv6StringParams stringParams, CharSequence zone) {
			super(addr, stringParams);
			this.zone = zone;
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
		
		@Override
		public String getString() {
			if(string == null) {
				string = stringParams.toString(addr, zone);
			}
			return string;
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
