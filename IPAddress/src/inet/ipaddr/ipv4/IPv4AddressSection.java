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

package inet.ipaddr.ipv4;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import inet.ipaddr.Address.SegmentValueProvider;
import inet.ipaddr.AddressSection;
import inet.ipaddr.AddressTypeException;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressConverter.DefaultAddressConverter;
import inet.ipaddr.IPAddressSection;
import inet.ipaddr.IPAddressSection.WildcardOptions.WildcardOption;
import inet.ipaddr.format.AddressCreator;
import inet.ipaddr.format.AddressDivisionGrouping;
import inet.ipaddr.format.AddressDivisionGrouping.StringOptions.Wildcards;
import inet.ipaddr.format.AddressStringDivision;
import inet.ipaddr.format.IPAddressDivision;
import inet.ipaddr.format.IPAddressDivisionGrouping;
import inet.ipaddr.format.IPAddressStringDivisionSeries;
import inet.ipaddr.format.util.IPAddressPartConfiguredString;
import inet.ipaddr.format.util.IPAddressPartStringCollection;
import inet.ipaddr.format.util.IPAddressPartStringSubCollection;
import inet.ipaddr.ipv4.IPv4AddressNetwork.IPv4AddressCreator;
import inet.ipaddr.ipv4.IPv4AddressSection.IPv4StringCollection.IPv4AddressSectionStringCollection;
import inet.ipaddr.ipv4.IPv4AddressSection.IPv4StringCollection.IPv4StringBuilder;
import inet.ipaddr.ipv6.IPv6Address.IPv6AddressConverter;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringBuilderOptions;

/**
 * 
 * @author sfoley
 *
 */
public class IPv4AddressSection extends IPAddressSection implements Iterable<IPv4AddressSection> {

	private static final long serialVersionUID = 3L;

	static class IPv4StringCache extends IPStringCache {
		//a set of pre-defined string types
		private static final IPStringOptions fullParams;
		private static final IPStringOptions normalizedWildcardParams;
		private static final IPStringOptions sqlWildcardParams;
		private static final IPStringOptions inetAtonOctalParams;
		private static final IPStringOptions inetAtonHexParams;
		private static final IPStringOptions canonicalParams;

		static final IPStringOptions reverseDNSParams;
		
		static {
			WildcardOptions allWildcards = new WildcardOptions(WildcardOptions.WildcardOption.ALL);
			WildcardOptions allSQLWildcards = new WildcardOptions(WildcardOptions.WildcardOption.ALL, new Wildcards(IPAddress.SEGMENT_SQL_WILDCARD_STR, IPAddress.SEGMENT_SQL_SINGLE_WILDCARD_STR));
			WildcardOptions wildcardsRangeOnlyNetworkOnly = new WildcardOptions(WildcardOptions.WildcardOption.NETWORK_ONLY, new Wildcards(IPAddress.RANGE_SEPARATOR_STR));
			fullParams = new IPv4StringOptions.Builder().setExpandedSegments(true).setWildcardOptions(wildcardsRangeOnlyNetworkOnly).toParams();
			normalizedWildcardParams = new IPv4StringOptions.Builder().setWildcardOptions(allWildcards).toParams();
			sqlWildcardParams = new IPv4StringOptions.Builder().setWildcardOptions(allSQLWildcards).toParams();
			inetAtonOctalParams = new IPv4StringOptions.Builder().setRadix(IPv4Address.inet_aton_radix.OCTAL.getRadix()).setSegmentStrPrefix(IPv4Address.inet_aton_radix.OCTAL.getSegmentStrPrefix()).toParams();
			inetAtonHexParams = new IPv4StringOptions.Builder().setRadix(IPv4Address.inet_aton_radix.HEX.getRadix()).setSegmentStrPrefix(IPv4Address.inet_aton_radix.HEX.getSegmentStrPrefix()).toParams();
			canonicalParams = new IPv4StringOptions.Builder(IPv4Address.DEFAULT_TEXTUAL_RADIX, IPv4Address.SEGMENT_SEPARATOR).toParams();
			reverseDNSParams = new IPv4StringOptions.Builder().setWildcardOptions(allWildcards).setReverse(true).setAddressSuffix(IPv4Address.REVERSE_DNS_SUFFIX).toParams();
		}
		
		public String octalString;
		public String hexString;
	}
	
	static class AddressCache extends SectionCache<IPv4Address> {}
	
	transient IPv4StringCache stringCache;
	
	private transient SectionCache<IPv4AddressSection> sectionCache;

	/**
	 * @param segments an array containing the segments.  Segments that are entirely part of the host section need not be provided, although the array must be the correct length.
	 * @param networkPrefixLength
	 */
	public IPv4AddressSection(IPv4AddressSegment[] segments, Integer networkPrefixLength) {
		this(toPrefixedSegments(networkPrefixLength, segments, IPv4Address.BITS_PER_SEGMENT, getIPv4SegmentCreator(), IPv4AddressSegment::toNetworkSegment, true), false);
		
	}
	
	public IPv4AddressSection(IPv4AddressSegment segments[]) {
		this(segments, true);
	}
	
	/**
	 * Constructs a single segment section.
	 * 
	 * @param segment
	 */
	public IPv4AddressSection(IPv4AddressSegment segment) {
		this(new IPv4AddressSegment[] {segment}, false);
	}
	
	IPv4AddressSection(IPv4AddressSegment segments[], boolean cloneSegments) {
		super(segments, null, cloneSegments, false);
		if(segments.length > IPv4Address.SEGMENT_COUNT) {
			throw new IllegalArgumentException(getMessage("ipaddress.error.exceeds.size") + ' ' + segments.length);
		}
	}
	
	public IPv4AddressSection(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefix) {
		super(toSegments(lowerValueProvider, upperValueProvider, IPv4Address.SEGMENT_COUNT, IPv4Address.BYTES_PER_SEGMENT, IPv4Address.BITS_PER_SEGMENT, IPv4Address.MAX_VALUE_PER_SEGMENT, getIPv4SegmentCreator(), prefix), null, false, false);
	}
	
	public IPv4AddressSection(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider) {
		this(lowerValueProvider, upperValueProvider, null);
	}

	IPv4AddressSection(byte bytes[], Integer prefix, boolean cloneBytes) {
		super(toSegments(bytes, IPv4Address.SEGMENT_COUNT, IPv4Address.BYTES_PER_SEGMENT, IPv4Address.BITS_PER_SEGMENT, IPv4Address.MAX_VALUE_PER_SEGMENT, getIPv4SegmentCreator(), prefix), bytes, false, cloneBytes);
		if(bytes.length > IPv4Address.BYTE_COUNT) {
			throw new IllegalArgumentException(getMessage("ipaddress.error.exceeds.size") + ' ' + bytes.length);
		}
	}
	
	public IPv4AddressSection(int value, Integer prefix) {
		super(toSegments(value, IPv4Address.BYTE_COUNT, IPv4Address.SEGMENT_COUNT, IPv4Address.BYTES_PER_SEGMENT, IPv4Address.BITS_PER_SEGMENT, IPv4Address.MAX_VALUE_PER_SEGMENT, getIPv4SegmentCreator(), prefix), null, false, false);
	}
	
	public IPv4AddressSection(int value) {
		super(toSegments(value, IPv4Address.BYTE_COUNT, IPv4Address.SEGMENT_COUNT, IPv4Address.BYTES_PER_SEGMENT, IPv4Address.BITS_PER_SEGMENT, IPv4Address.MAX_VALUE_PER_SEGMENT, getIPv4SegmentCreator(), null), null, false, false);
	}
	
	public IPv4AddressSection(byte bytes[], Integer prefix) {
		this(bytes, prefix, true);
	}
	
	public IPv4AddressSection(byte bytes[]) {
		this(bytes, null, true);
	}
	
	@Override
	public IPv4AddressSegment[] getSegments() {
		return (IPv4AddressSegment[]) divisions.clone();
	}

	@Override
	public IPv4AddressSection getSection(int index) {
		return getSection(index, getSegmentCount());
	}

	@Override
	public IPv4AddressSection getSection(int index, int endIndex) {
		return getSection(index, endIndex, this, getAddressCreator());
	}

	private IPv4AddressSection getLowestOrHighestSection(boolean lowest) {
		return getLowestOrHighestSection(
			this,
			getAddressCreator(),
			lowest,
			i -> lowest ? getSegment(i).getLower() : getSegment(i).getUpper(),
			() -> getSectionCache(this, () -> sectionCache, () -> sectionCache = new SectionCache<IPv4AddressSection>()));
	}

	IPv4Address getLowestOrHighest(IPv4Address addr, boolean lowest) {
		return getLowestOrHighestAddress(
			addr,
			getAddressCreator(),
			lowest,
			() -> getLowestOrHighestSection(lowest),
			() -> getSectionCache(addr, () -> addr.sectionCache, () -> addr.sectionCache = new AddressCache()));
	}
	
	@Override
	public IPv4AddressSection getLower() {
		return getLowestOrHighestSection(true);
	}
	
	@Override
	public IPv4AddressSection getUpper() {
		return getLowestOrHighestSection(false);
	}
	
	@Override
	public IPv4AddressSection reverseBits(boolean perByte) {
		return reverseBits(perByte, this, getAddressCreator(), i -> getSegment(i).reverseBits(perByte), true);
	}
	
	@Override
	public IPv4AddressSection reverseBytes() {
		return reverseSegments();
	}
	
	@Override
	public IPv4AddressSection reverseBytesPerSegment() {
		if(!isPrefixed()) {
			return this;
		}
		return reverseBytes(true, this, getAddressCreator(), i -> getSegment(i).reverseBytes(), true);
	}
	
	@Override
	public IPv4AddressSection reverseSegments() {
		if(getSegmentCount() <= 1) {
			if(isPrefixed()) {
				return removePrefixLength(false);
			}
			return this;
		}
		return reverseSegments(this, getAddressCreator(), (i) -> getSegment(i).removePrefixLength(false), true);
	}
	
	@Override
	public Iterable<IPv4AddressSection> getIterable() {
		return this;
	}
	
	@Override
	public Iterator<IPv4AddressSection> iterator() {
		boolean useOriginal = !isMultiple() && !isPrefixed();
		return iterator(
				useOriginal,
				this,
				getAddressCreator(),
				useOriginal ? null : segmentsIterator());
	}

	@Override
	public Iterator<IPv4AddressSegment[]> segmentsIterator() {
		return super.iterator(getSegmentCreator(), () -> getLower().getSegments(), index -> getSegment(index).iterator());
	}

	protected Iterator<IPv4Address> iterator(
			IPv4Address original,
			AddressCreator<IPv4Address, ?, ?, IPv4AddressSegment> creator) {
		boolean useOriginal = !isMultiple() && !isPrefixed();
		return iterator(
				original, 
				creator,//using a lambda for this one results in a big performance hit
				useOriginal,
				useOriginal ? null : iterator(creator, () -> (IPv4AddressSegment[]) getLower().divisions, index -> getSegment(index).iterator())
			);
	}
	
	@Override
	protected BigInteger getCountImpl() {
		int segCount = getSegmentCount();
		if(!isMultiple()) {
			return BigInteger.ONE;
		}
		long result = getSegment(0).getValueCount();
		for(int i = 1; i < segCount; i++) {
			result *= getSegment(i).getValueCount();
		}
		return BigInteger.valueOf(result);
	}

	private IPv4AddressCreator getSegmentCreator() {
		return getIPv4SegmentCreator();
	}

	private IPv4AddressCreator getAddressCreator() {
		return getIPv4SegmentCreator();
	}
	
	private static IPv4AddressCreator getIPv4SegmentCreator() {
		return IPv4Address.network().getAddressCreator();
	}
	
	@Override
	public IPv4AddressSegment getSegment(int index) {
		return (IPv4AddressSegment) super.getSegment(index);
	}

	public void getSegments(Collection<? super IPv4AddressSegment> segs) {
		getSegments(0, getSegmentCount(), segs);
	}

	public void getSegments(int start, int end, Collection<? super IPv4AddressSegment> segs) {
		for(int i = start; i < end; i++) {
			segs.add(getSegment(i));
		}
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
	protected byte[] getBytesImpl(boolean low) {
		byte bytes[] = new byte[(getBitCount() + 7) >> 3];
		int segmentCount = getSegmentCount();
		for(int i = 0; i < segmentCount; i++) {
			IPv4AddressSegment seg = getSegment(i);
			int val = low ? seg.getLowerSegmentValue() : seg.getUpperSegmentValue();
			bytes[i] = (byte) val;
		}
		return bytes;
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
	protected boolean isSameGrouping(AddressDivisionGrouping other) {
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
	
	public IPv4AddressSection replace(IPv4AddressSection other, int index) {
		if(index > 0 && getSegment(index - 1).isPrefixed()) {
			throw new AddressTypeException(this, "ipaddress.error.index.exceeds.prefix.length");
		}
		IPv4AddressSection result = replace(this, other, getAddressCreator(), index, true);
		return result;
	}
	
	public IPv4AddressSection prepend(IPv4AddressSection other) {
		IPv4AddressSection result = appendPreamble(other);
		if(result != null) {
			return result;
		}
		return append(other, this, getAddressCreator(), true);
	}

	public IPv4AddressSection append(IPv4AddressSection other) {
		IPv4AddressSection result = appendPreamble(other);
		if(result != null) {
			return result;
		}
		return append(this, other, getAddressCreator(), true);
	}

	private IPv4AddressSection appendPreamble(IPv4AddressSection other) {
		int segmentCount = getSegmentCount();
		int otherSegmentCount = other.getSegmentCount();
		if(segmentCount + otherSegmentCount > IPv4Address.SEGMENT_COUNT) {
			throw new AddressTypeException(this, other, "ipaddress.error.exceeds.size");
		}
		if(otherSegmentCount == 0) {
			return this;
		}
		if(segmentCount == 0) {
			return other;
		}
		return null;
	}
	
	@Override
	public boolean contains(AddressSection other) {
		return other instanceof IPv4AddressSection && super.contains((IPAddressSection) other);
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
	public IPv4AddressSection[] subtract(IPv4AddressSection other) {
		return subtract(this, other, getAddressCreator(), this::getSegment, (section, prefix) -> section.applyPrefixLength(prefix));
	}
	
	@Override
	public int getByteIndex(int networkPrefixLength) {
		return getByteIndex(networkPrefixLength, IPv4Address.BYTE_COUNT);
	}
	
	@Override
	public int getSegmentIndex(int networkPrefixLength) {
		return getByteIndex(networkPrefixLength);
	}
	
	@Override
	public IPv4AddressNetwork getNetwork() {
		return IPv4Address.network();
	}
	
	@Override
	public IPv4AddressSection adjustPrefixBySegment(boolean nextSegment) {
		return (IPv4AddressSection) super.adjustPrefixBySegment(nextSegment);
	}

	@Override
	public IPv4AddressSection adjustPrefixLength(int adjustment) {
		return (IPv4AddressSection) adjustPrefixLength(this, adjustment, getAddressCreator(), getNetwork(), (section, i) -> section.getSegment(i));
	}
	
	@Override
	public IPv4AddressSection applyPrefixLength(int networkPrefixLength) {
		return setPrefixLength(networkPrefixLength, false, true);
	}
	
	@Override
	public IPv4AddressSection setPrefixLength(int networkPrefixLength) {
		return setPrefixLength(networkPrefixLength, true, false);
	}
	
	@Override
	public IPv4AddressSection setPrefixLength(int networkPrefixLength, boolean withZeros) {
		return setPrefixLength(networkPrefixLength, withZeros, false);
	}
	
	private IPv4AddressSection setPrefixLength(int networkPrefixLength, boolean withZeros, boolean noShrink) {
		return setPrefixLength(
				this,
				getAddressCreator(),
				networkPrefixLength,
				withZeros,
				noShrink,
				getNetwork(),
				(section, i) -> section.getSegment(i));
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
	public IPv4AddressSection bitwiseOrNetwork(IPv4AddressSection mask, int networkPrefixLength) throws AddressTypeException {
		super.checkSectionCount(mask);
		return getOredSegments(this, networkPrefixLength, getAddressCreator(), this::getSegment, mask::getSegment);
	}
	
	/**
	 * Does the bitwise disjunction with this address.  Useful when subnetting.
	 * @param mask
	 * @return
	 * @throws AddressTypeException
	 */
	public IPv4AddressSection bitwiseOr(IPv4AddressSection mask) throws AddressTypeException {
		super.checkSectionCount(mask);
		return getOredSegments(this, null, getAddressCreator(), this::getSegment, mask::getSegment);
	}

	@Override
	public IPv4AddressSection removePrefixLength() {
		return removePrefixLength(true);
	}
	
	@Override
	public IPv4AddressSection removePrefixLength(boolean zeroed) {
		return removePrefixLength(zeroed, true);
	}
	
	protected IPv4AddressSection removePrefixLength(boolean zeroed, boolean onlyPrefixZeroed) {
		return removePrefixLength(this, zeroed, onlyPrefixZeroed, getAddressCreator(), getNetwork(), (section, i) -> section.getSegment(i));
	}

	public IPv4AddressSection mask(IPv4AddressSection mask) throws AddressTypeException {
		super.checkSectionCount(mask);
		return getSubnetSegments(this, null, getAddressCreator(), true, this::getSegment, mask::getSegment);
	}
	
	/**
	 * Applies the given mask to the network section of the address as indicated by the given prefix length.
	 * Useful for subnetting.  Once you have zeroed a section of the network you can insert bits 
	 * using {@link #bitwiseOr(IPv4AddressSection)} or {@link #replace(IPv4AddressSection, int)}
	 * 
	 * @param mask
	 * @param networkPrefixLength
	 * @return
	 * @throws AddressTypeException
	 */
	public IPv4AddressSection maskNetwork(IPv4AddressSection mask, int networkPrefixLength) throws AddressTypeException {
		super.checkSectionCount(mask);
		return getSubnetSegments(this, networkPrefixLength, getAddressCreator(), true, this::getSegment, mask::getSegment);
	}
	
	@Override
	public IPv4AddressSection getNetworkSection(int networkPrefixLength) {
		return getNetworkSection(networkPrefixLength, true);
	}
	
	@Override
	public IPv4AddressSection getNetworkSection(int networkPrefixLength, boolean withPrefixLength) {
		int cidrSegmentCount = getNetworkSegmentCount(networkPrefixLength);
		return getNetworkSection(this, networkPrefixLength, cidrSegmentCount, withPrefixLength, getAddressCreator(), (i, prefix) -> getSegment(i).toNetworkSegment(prefix, withPrefixLength));
	}
	
	@Override
	public IPv4AddressSection getHostSection(int networkPrefixLength) {
		int cidrSegmentCount = getHostSegmentCount(networkPrefixLength);
		return getHostSection(this, networkPrefixLength, cidrSegmentCount, getAddressCreator(), (i, prefix) -> getSegment(i).toHostSegment(prefix));
	}

	@Override
	protected boolean hasNoStringCache() {
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
	
	@Override
	protected IPv4StringCache getStringCache() {
		return stringCache;
	}
	
	/**
	 * This produces a canonical string.
	 */
	@Override
	public String toCanonicalString() {
		String result;
		if(hasNoStringCache() || (result = stringCache.canonicalString) == null) {
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
		if(hasNoStringCache() || (result = stringCache.fullString) == null) {
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
	protected void cacheNormalizedString(String str) {
		if(hasNoStringCache() || stringCache.canonicalString == null) {
			stringCache.canonicalString = str;
		}
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
	public String toPrefixLengthString() {
		return toCanonicalString();
	}
	
	public String toInetAtonString(IPv4Address.inet_aton_radix radix) {
		String result;
		if(radix == IPv4Address.inet_aton_radix.OCTAL) {
			if(hasNoStringCache() || (result = stringCache.octalString) == null) {
				stringCache.octalString = result = toNormalizedString(IPv4StringCache.inetAtonOctalParams);
			}
		} else if(radix == IPv4Address.inet_aton_radix.HEX) {
			if(hasNoStringCache() || (result = stringCache.hexString) == null) {
				stringCache.hexString = result = toNormalizedString(IPv4StringCache.inetAtonHexParams);
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
		IPStringOptions stringParams;
		if(radix == IPv4Address.inet_aton_radix.OCTAL) {
			stringParams = IPv4StringCache.inetAtonOctalParams;
		} else if(radix == IPv4Address.inet_aton_radix.HEX) {
			stringParams = IPv4StringCache.inetAtonHexParams;
		} else {
			stringParams = IPv4StringCache.canonicalParams;
		}
		return toNormalizedString(stringParams, joinedCount);
	}
	
	@Override
	public String toNormalizedWildcardString() {
		String result;
		if(hasNoStringCache() || (result = stringCache.normalizedWildcardString) == null) {
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
		if(hasNoStringCache() || (result = stringCache.sqlWildcardString) == null) {
			stringCache.sqlWildcardString = result = toNormalizedString(IPv4StringCache.sqlWildcardParams);
		}
		return result;
	}
	
	@Override
	public String toReverseDNSLookupString() {
		String result;
		if(hasNoStringCache() || (result = stringCache.reverseDNSString) == null) {
			stringCache.reverseDNSString = result = toNormalizedString(IPv4StringCache.reverseDNSParams);
		}
		return result;
	} 
	
	public String toNormalizedString(IPStringOptions stringParams, int joinCount) {
		if(joinCount <= 0) {
			return toNormalizedString(stringParams);
		}
		int thisCount = getSegmentCount();
		if(thisCount <= 1) {
			return toNormalizedString(stringParams);
		}
		IPAddressStringDivisionSeries equivalentPart = toJoinedSegments(joinCount);
		return toNormalizedString(stringParams, equivalentPart);
	}
	
	public IPAddressDivisionGrouping toJoinedSegments(int joinCount) {
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
		IPAddressDivisionGrouping equivalentPart = new IPAddressDivisionGrouping(segs);
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
					throw new AddressTypeException(firstRange, firstSegIndex, thisSeg, firstJoinedIndex + j, "ipaddress.error.segmentMismatch");
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
		IPAddressStringDivisionSeries parts[] = getParts(opts);
		for(IPAddressStringDivisionSeries part : parts) {
			IPv4StringBuilder builder = new IPv4StringBuilder(part, opts, new IPv4AddressSectionStringCollection(part));
			IPv4AddressSectionStringCollection subCollection = builder.getVariations();
			collection.add(subCollection);
		}
		return collection;
	}
	
	@Override
	public IPAddressStringDivisionSeries[] getParts(IPStringBuilderOptions options) {
		return getParts(IPv4StringBuilderOptions.from(options));
	}
	
	public IPAddressStringDivisionSeries[] getParts(IPv4StringBuilderOptions options) {
		if(!options.includesAny(IPv4StringBuilderOptions.ALL_JOINS)) {
			return super.getParts(options);
		}
		ArrayList<IPAddressStringDivisionSeries> parts = new ArrayList<>(IPv4Address.SEGMENT_COUNT);
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
		return parts.toArray(new IPAddressStringDivisionSeries[parts.size()]);
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
	
	/**
	 * Represents a clear way to create a specific type of string.
	 * 
	 * @author sfoley
	 */
	public static class IPv4StringOptions extends IPStringOptions {
		
		protected IPv4StringOptions(
				int base,
				boolean expandSegments,
				WildcardOption wildcardOption,
				Wildcards wildcards,
				String segmentStrPrefix,
				Character separator,
				//char zoneSeparator,
				String label,
				String suffix,
				boolean reverse,
				boolean splitDigits,
				boolean uppercase) {
			super(base, expandSegments, wildcardOption, wildcards, segmentStrPrefix, separator, ' ', label, suffix, reverse, splitDigits, uppercase);
		}
		
		public static class Builder extends IPStringOptions.Builder {
			
			public Builder() {
				this(IPv4Address.DEFAULT_TEXTUAL_RADIX, IPv4Address.SEGMENT_SEPARATOR);
			}
			
			protected Builder(int base, char separator) {
				super(base, separator);
			}
			
			@Override
			public IPv4StringOptions toParams() {
				return new IPv4StringOptions(base, expandSegments, wildcardOption, wildcards, segmentStrPrefix, separator, addrLabel, addrSuffix, reverse, splitDigits, uppercase);
			}
		}
	}
	/**
	 * Each IPv4StringParams instance has settings to write exactly one IPv4 address section string.
	 * Using this class allows us to avoid referencing StringParams<IPAddressPart> everywhere,
	 * but in reality this class has no functionality of its own.
	 * 
	 * @author sfoley
	 *
	 */
	private static class IPv4StringParams extends IPAddressStringParams<IPAddressStringDivisionSeries> {
		
		IPv4StringParams(int radix) {
			super(radix, IPv4Address.SEGMENT_SEPARATOR, false);
		}
		
		@Override
		public IPv4StringParams clone() {
			return (IPv4StringParams) super.clone();
		}
	}

	static class IPv4StringCollection extends IPAddressPartStringCollection {
		
		@Override
		protected void addAll(IPAddressPartStringCollection collections) {
			super.addAll(collections);
		}
		
		static class IPv4AddressSectionStringCollection extends IPAddressPartStringSubCollection<IPAddressStringDivisionSeries, IPv4StringParams, IPAddressPartConfiguredString<IPAddressStringDivisionSeries, IPv4StringParams>> {
			IPv4AddressSectionStringCollection(IPAddressStringDivisionSeries addr) {
				super(addr);
			}
			
			@Override
			public Iterator<IPAddressPartConfiguredString<IPAddressStringDivisionSeries, IPv4StringParams>> iterator() {
				return new IPAddressConfigurableStringIterator() {
					@Override
					public IPAddressPartConfiguredString<IPAddressStringDivisionSeries, IPv4StringParams> next() {
						return new IPAddressPartConfiguredString<IPAddressStringDivisionSeries, IPv4StringParams>(part, iterator.next()); 
					}
				};
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
			extends AddressPartStringBuilder<IPAddressStringDivisionSeries, IPv4StringParams, IPAddressPartConfiguredString<IPAddressStringDivisionSeries, IPv4StringParams>, IPv4AddressSectionStringCollection, IPv4StringBuilderOptions> {
			
			private IPv4StringBuilder(IPAddressStringDivisionSeries address, IPv4StringBuilderOptions options, IPv4AddressSectionStringCollection collection) {
				super(address, options, collection);
			}
			
			/**
			 * 
			 * @return whether this section in decimal appears the same as this segment in octal.
			 * 	This is true if all the values lies between 0 and 8 (so the octal and decimal values are the same)
			 */
			public static boolean isDecimalSameAsOctal(IPAddressStringDivisionSeries part) {
				int count = part.getDivisionCount();
				for(int i = 0; i < count; i++) {
					AddressStringDivision seg = part.getDivision(i);
					//we return true in cases where all segments are between 0 and 7, in which case the octal and decimal digits are the same.
					if(!seg.isBoundedBy(8)) {
						return false;
					}
				}
				return true;	
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
					hasDecimalOctalDups = options.includes(IPStringBuilderOptions.LEADING_ZEROS_PARTIAL_SOME_SEGMENTS) && IPv4Address.inet_aton_radix.OCTAL.getSegmentStrPrefix().equals("0") && isDecimalSameAsOctal(addressSection);
				}
				for(int radix : radices) {
					ArrayList<IPv4StringParams> radixParams = new ArrayList<>();
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
							IPv4StringParams expandParams = new IPv4StringParams(IPv4Address.DEFAULT_TEXTUAL_RADIX);
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
