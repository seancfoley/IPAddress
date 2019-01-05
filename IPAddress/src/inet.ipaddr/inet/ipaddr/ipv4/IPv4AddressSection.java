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

package inet.ipaddr.ipv4;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.function.IntUnaryOperator;

import inet.ipaddr.Address;
import inet.ipaddr.Address.SegmentValueProvider;
import inet.ipaddr.AddressNetwork.PrefixConfiguration;
import inet.ipaddr.AddressSection;
import inet.ipaddr.AddressValueException;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressConverter.DefaultAddressConverter;
import inet.ipaddr.IPAddressSection;
import inet.ipaddr.IPAddressSection.WildcardOptions.WildcardOption;
import inet.ipaddr.IPAddressSegment;
import inet.ipaddr.IPAddressSegmentSeries;
import inet.ipaddr.IncompatibleAddressException;
import inet.ipaddr.PrefixLenException;
import inet.ipaddr.SizeMismatchException;
import inet.ipaddr.format.AddressDivisionGroupingBase;
import inet.ipaddr.format.standard.AddressCreator;
import inet.ipaddr.format.standard.AddressDivisionGrouping.StringOptions.Wildcards;
import inet.ipaddr.format.standard.IPAddressDivision;
import inet.ipaddr.format.standard.IPAddressDivisionGrouping;
import inet.ipaddr.format.string.AddressStringDivision;
import inet.ipaddr.format.string.IPAddressStringDivisionSeries;
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

	private static final long serialVersionUID = 4L;
	
	private static final long MAX_VALUES[] = new long[] {0, IPv4Address.MAX_VALUE_PER_SEGMENT, 0xffff, 0xffffff, 0xffffffffL};

	static class IPv4StringCache extends IPStringCache {
		// a set of pre-defined string types
		static final IPStringOptions fullParams;
		static final IPStringOptions normalizedWildcardParams;
		static final IPStringOptions sqlWildcardParams;
		static final IPStringOptions inetAtonOctalParams;
		static final IPStringOptions inetAtonHexParams;
		static final IPStringOptions canonicalParams;

		static final IPStringOptions reverseDNSParams;
		
		static {
			WildcardOptions allWildcards = new WildcardOptions(WildcardOptions.WildcardOption.ALL);
			WildcardOptions allSQLWildcards = new WildcardOptions(WildcardOptions.WildcardOption.ALL, new Wildcards(IPAddress.SEGMENT_SQL_WILDCARD_STR, IPAddress.SEGMENT_SQL_SINGLE_WILDCARD_STR));
			WildcardOptions wildcardsRangeOnlyNetworkOnly = new WildcardOptions(WildcardOptions.WildcardOption.NETWORK_ONLY, new Wildcards(IPAddress.RANGE_SEPARATOR_STR));
			fullParams = new IPv4StringOptions.Builder().setExpandedSegments(true).setWildcardOptions(wildcardsRangeOnlyNetworkOnly).toOptions();
			normalizedWildcardParams = new IPv4StringOptions.Builder().setWildcardOptions(allWildcards).toOptions();
			sqlWildcardParams = new IPv4StringOptions.Builder().setWildcardOptions(allSQLWildcards).toOptions();
			inetAtonOctalParams = new IPv4StringOptions.Builder().setRadix(IPv4Address.inet_aton_radix.OCTAL.getRadix()).setSegmentStrPrefix(IPv4Address.inet_aton_radix.OCTAL.getSegmentStrPrefix()).toOptions();
			inetAtonHexParams = new IPv4StringOptions.Builder().setRadix(IPv4Address.inet_aton_radix.HEX.getRadix()).setSegmentStrPrefix(IPv4Address.inet_aton_radix.HEX.getSegmentStrPrefix()).toOptions();
			canonicalParams = new IPv4StringOptions.Builder(IPv4Address.DEFAULT_TEXTUAL_RADIX, IPv4Address.SEGMENT_SEPARATOR).toOptions();
			reverseDNSParams = new IPv4StringOptions.Builder().setWildcardOptions(allWildcards).setReverse(true).setAddressSuffix(IPv4Address.REVERSE_DNS_SUFFIX).toOptions();
		}
		
		public String octalString;
		public String hexString;
	}
	
	static class AddressCache extends SectionCache<IPv4Address> {}
	
	transient IPv4StringCache stringCache;
	
	private transient SectionCache<IPv4AddressSection> sectionCache;

	/**
	 * Constructs a single segment section.
	 * 
	 * @param segment
	 */
	public IPv4AddressSection(IPv4AddressSegment segment) {
		this(new IPv4AddressSegment[] {segment}, false);
	}
	
	public IPv4AddressSection(IPv4AddressSegment segments[]) throws AddressValueException {
		this(segments, true);
	}
	
	/**
	 * @param segments an array containing the segments.  Segments that are entirely part of the host section need not be provided, although the array must be the correct length.
	 * @param networkPrefixLength
	 */
	public IPv4AddressSection(IPv4AddressSegment[] segments, Integer networkPrefixLength) throws AddressValueException {
		this(segments, true, networkPrefixLength, false);
	}
	
	protected IPv4AddressSection(IPv4AddressSegment[] segments, boolean cloneSegments, Integer networkPrefixLength, boolean singleOnly) throws AddressValueException {
		this(segments, cloneSegments, networkPrefixLength == null);
		if(networkPrefixLength != null) {
			int max = segments.length << 3;
			if(networkPrefixLength > max) {
				if(networkPrefixLength > IPv4Address.BIT_COUNT) {
					throw new PrefixLenException(networkPrefixLength);
				}
				networkPrefixLength = max;
			}
			if(segments.length > 0) {
				if(cachedPrefixLength != NO_PREFIX_LENGTH && cachedPrefixLength < networkPrefixLength) {
					networkPrefixLength = cachedPrefixLength;
				}
				IPv4AddressNetwork network = getNetwork();
				setPrefixedSegments(
						network,
						networkPrefixLength,
						getSegmentsInternal(),
						IPv4Address.BITS_PER_SEGMENT,
						IPv4Address.BYTES_PER_SEGMENT,
						network.getAddressCreator(), 
						!singleOnly && isPrefixSubnet(segments, networkPrefixLength, network, false) ? IPv4AddressSegment::toNetworkSegment : IPv4AddressSegment::toPrefixedSegment);
				cachedPrefixLength = networkPrefixLength;
			}
		} 
	}
	
	protected IPv4AddressSection(IPv4AddressSegment segments[], boolean cloneSegments) throws AddressValueException {
		this(segments, cloneSegments, true);
	}
	
	IPv4AddressSection(IPv4AddressSegment segments[], boolean cloneSegments, boolean normalizeSegments) throws AddressValueException {
		super(segments, cloneSegments, true);
		if(normalizeSegments && isPrefixed()) {
			normalizePrefixBoundary(getNetworkPrefixLength(), getSegmentsInternal(), IPv4Address.BITS_PER_SEGMENT, IPv4Address.BYTES_PER_SEGMENT, IPv4AddressSegment::toPrefixedSegment);
		}
		if(segments.length > IPv4Address.SEGMENT_COUNT) {
			throw new AddressValueException(segments.length);
		}
	}
	
	public IPv4AddressSection(SegmentValueProvider valueProvider, int segmentCount, Integer networkPrefixLength) throws AddressValueException {
		this(valueProvider, valueProvider, segmentCount, networkPrefixLength);
	}
	
	public IPv4AddressSection(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, int segmentCount, Integer networkPrefixLength) throws AddressValueException {
		super(new IPv4AddressSegment[segmentCount], false, false);
		IPv4AddressSegment segs[] = getSegmentsInternal();
		IPv4AddressNetwork network = getNetwork();
		createSegments(
				segs,
				lowerValueProvider,
				upperValueProvider,
				IPv4Address.BYTES_PER_SEGMENT,
				IPv4Address.BITS_PER_SEGMENT,
				network,
				networkPrefixLength);
		if(networkPrefixLength != null) {
			if(networkPrefixLength > IPv4Address.BIT_COUNT) {
				throw new PrefixLenException(networkPrefixLength);
			}
			if(network.getPrefixConfiguration().zeroHostsAreSubnets() && isPrefixSubnet(segs, networkPrefixLength, network, false)) {
				setPrefixedSegments(
						network,
						networkPrefixLength,
						getSegmentsInternal(),
						IPv4Address.BITS_PER_SEGMENT,
						IPv4Address.BYTES_PER_SEGMENT,
						network.getAddressCreator(),
						IPv4AddressSegment::toNetworkSegment);
			}
			cachedPrefixLength = networkPrefixLength;
		} else {
			cachedPrefixLength = NO_PREFIX_LENGTH;
		}
	}
	
	public IPv4AddressSection(SegmentValueProvider valueProvider, int segmentCount) throws AddressValueException {
		this(valueProvider, valueProvider, segmentCount);
	}
	
	public IPv4AddressSection(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, int segmentCount) {
		this(lowerValueProvider, upperValueProvider, segmentCount, null);
	}

	protected IPv4AddressSection(byte bytes[], int segmentCount, Integer networkPrefixLength, boolean cloneBytes, boolean singleOnly) throws AddressValueException {
		this(bytes, 0, bytes.length, segmentCount, networkPrefixLength, cloneBytes, singleOnly);
	}

	protected IPv4AddressSection(byte bytes[], int byteStartIndex, int byteEndIndex, int segmentCount, Integer networkPrefixLength, boolean cloneBytes, boolean singleOnly) throws AddressValueException {
		super(new IPv4AddressSegment[segmentCount >= 0 ? segmentCount : Math.max(0, byteEndIndex - byteStartIndex)], false, false);
		IPv4AddressSegment segs[] = getSegmentsInternal();
		IPv4AddressNetwork network = getNetwork();
		toSegments(
			segs,
			bytes,
			byteStartIndex,
			byteEndIndex,
			IPv4Address.BYTES_PER_SEGMENT,
			IPv4Address.BITS_PER_SEGMENT,
			network,
			networkPrefixLength);
		boolean byteLengthIsExact = bytes.length == segs.length;
		if(networkPrefixLength != null) {
			if(networkPrefixLength < 0) {
				throw new PrefixLenException(networkPrefixLength);
			}
			int max = segs.length << 3;
			if(networkPrefixLength > max) {
				if(networkPrefixLength > IPv4Address.BIT_COUNT) {
					throw new PrefixLenException(networkPrefixLength);
				}
				networkPrefixLength = max;
			}
			if(segs.length > 0) {
				PrefixConfiguration prefConf = network.getPrefixConfiguration();
				if(prefConf.zeroHostsAreSubnets()) {
					if(isPrefixSubnet(segs, networkPrefixLength, network, false) && !singleOnly) {
						setPrefixedSegments(
								network,
								networkPrefixLength,
								segs,
								IPv4Address.BITS_PER_SEGMENT,
								IPv4Address.BYTES_PER_SEGMENT,
								network.getAddressCreator(),
								IPv4AddressSegment::toNetworkSegment);
					} else if(byteLengthIsExact && networkPrefixLength >= getBitCount()) {
						setBytes(cloneBytes ? bytes.clone() : bytes);
					}
				} else if(byteLengthIsExact && (prefConf.prefixedSubnetsAreExplicit() || networkPrefixLength >= getBitCount())) {
					setBytes(cloneBytes ? bytes.clone() : bytes);
				}
			} else if(byteLengthIsExact) {
				setBytes(bytes);
			}
			cachedPrefixLength = networkPrefixLength;
		} else {
			cachedPrefixLength = NO_PREFIX_LENGTH;
			if(byteLengthIsExact) {
				setBytes(cloneBytes ? bytes.clone() : bytes);
			}
		}
	}
	
	protected IPv4AddressSection(byte bytes[], int byteStartIndex, int byteEndIndex, int segmentCount, Integer prefix) throws AddressValueException {
		this(bytes, byteStartIndex, byteEndIndex, segmentCount, prefix, true, false);
	}
	
	public IPv4AddressSection(byte bytes[], Integer prefix) throws AddressValueException {
		this(bytes, bytes.length, prefix, true, false);
	}
	
	public IPv4AddressSection(byte bytes[]) throws AddressValueException {
		this(bytes, bytes.length, null, true, false);
	}
	
	public IPv4AddressSection(byte bytes[], int byteStartIndex, int byteEndIndex, Integer prefix) throws AddressValueException {
		this(bytes, byteStartIndex, byteEndIndex, -1, prefix, true, false);
	}
	
	public IPv4AddressSection(byte bytes[], int byteStartIndex, int byteEndIndex) throws AddressValueException {
		this(bytes, byteStartIndex, byteEndIndex, -1, null, true, false);
	}
	
	public IPv4AddressSection(int value, Integer networkPrefixLength) throws AddressValueException {
		super(new IPv4AddressSegment[IPv4Address.SEGMENT_COUNT], false, false);
		IPv4AddressSegment segs[] = getSegmentsInternal();
		IPv4AddressNetwork network = getNetwork();
		createSegments(
				segs,
				0,
				value,
				IPv4Address.BITS_PER_SEGMENT,
				network,
				networkPrefixLength);
		if(networkPrefixLength != null) {
			if(networkPrefixLength > IPv4Address.BIT_COUNT) {
				throw new PrefixLenException(networkPrefixLength);
			}
			if(network.getPrefixConfiguration().zeroHostsAreSubnets() && isPrefixSubnet(segs, networkPrefixLength, network, false)) {
				setPrefixedSegments(
						network,
						networkPrefixLength,
						getSegmentsInternal(),
						IPv4Address.BITS_PER_SEGMENT,
						IPv4Address.BYTES_PER_SEGMENT,
						network.getAddressCreator(),
						IPv4AddressSegment::toNetworkSegment);
			}
			cachedPrefixLength = networkPrefixLength;
		} else {
			cachedPrefixLength = NO_PREFIX_LENGTH;
		}
	}
	
	public IPv4AddressSection(int value) {
		this(value, null);
	}
	
	@Override
	public IPv4AddressSegment[] getSegments() {
		return (IPv4AddressSegment[]) getDivisionsInternal().clone();
	}

	@Override
	public IPv4AddressSection getSection() {
		return this;
	}
	
	@Override
	public IPv4AddressSection getSection(int index) {
		return getSection(index, getSegmentCount());
	}

	@Override
	public IPv4AddressSection getSection(int index, int endIndex) {
		return getSection(index, endIndex, this, getAddressCreator());
	}
	
	private IPv4AddressSection getLowestOrHighestSection(boolean lowest, boolean excludeZeroHost) {
		IPv4AddressSection result = getSingleLowestOrHighestSection(this);
		if(result == null) {
			SectionCache<IPv4AddressSection> cache = sectionCache;
			if(cache == null || (lowest ? (excludeZeroHost ? ((result = cache.lowerNonZeroHost) == null && !cache.lowerNonZeroHostIsNull) : (result = cache.lower) == null) : (result = cache.upper) == null)) {
				synchronized(this) {
					cache = sectionCache;
					boolean create = (cache == null);
					if(create) {
						sectionCache = cache = new SectionCache<IPv4AddressSection>();
					} else {
						if(lowest) {
							if(excludeZeroHost) {
								create = (result = cache.lowerNonZeroHost) == null && !cache.lowerNonZeroHostIsNull;
							} else {
								create = (result = cache.lower) == null;
							}
						} else {
							create = (result = cache.upper) == null;
						}
					}
					if(create) {
						result = getLowestOrHighestSection(
								this,
								getAddressCreator(), 
								this::segmentsNonZeroHostIterator,
								i -> lowest ? getSegment(i).getLower() : getSegment(i).getUpper(),
								lowest,
								excludeZeroHost);
						if(result == null) {
							cache.lowerNonZeroHostIsNull = true;
						} else if(lowest) {
							if(excludeZeroHost) {
								 cache.lowerNonZeroHost = result;
							} else {
								cache.lower = result;
							}
						} else {
							cache.upper = result;
						}
					}
				}
			}
		} else if(excludeZeroHost && includesZeroHost()) {
			return null;
		}
		return result;
	}
	
	IPv4Address getLowestOrHighest(IPv4Address addr, boolean lowest, boolean excludeZeroHost) {
		IPv4AddressSection sectionResult = getLowestOrHighestSection(lowest, excludeZeroHost);
		if(sectionResult == this) {
			return addr;
		} else if(sectionResult == null) {
			return null;
		}
		IPv4Address result = null;
		AddressCache cache = addr.sectionCache;
		if(cache == null || 
				(result = lowest ? (excludeZeroHost ? cache.lowerNonZeroHost : cache.lower) : cache.upper) == null) {
			synchronized(this) {
				cache = addr.sectionCache;
				boolean create = (cache == null);
				if(create) {
					cache = addr.sectionCache = new AddressCache();
				} else {
					if(lowest) {
						if(excludeZeroHost) {
							create = (result = cache.lowerNonZeroHost) == null;
							//	create = (result = cache.lowerNonZeroHost) == null && !cache.lowerNonZeroHostIsNull;
						} else {
							create = (result = cache.lower) == null;
						}
					} else {
						create = (result = cache.upper) == null;
					}
				}
				if(create) {
					result = getAddressCreator().createAddress(sectionResult);
					if(lowest) {
						if(excludeZeroHost) {
							 cache.lowerNonZeroHost = result;
						} else {
							cache.lower = result;
						}
					} else {
						cache.upper = result;
					}
				}
			}
		}
		return result;
	}
	
	@Override
	public IPv4AddressSection getLowerNonZeroHost() {
		return getLowestOrHighestSection(true, true);
	}
	
	@Override
	public IPv4AddressSection getLower() {
		return getLowestOrHighestSection(true, false);
	}
	
	@Override
	public IPv4AddressSection getUpper() {
		return getLowestOrHighestSection(false, false);
	}
	
	public int intValue() {
		return getIntValue(true);
	}
	
	public int upperIntValue() {
		return getIntValue(false);
	}
	
	public long longValue() {
		return intValue() & 0xffffffffL;
	}
	
	public long upperLongValue() {
		return upperIntValue() & 0xffffffffL;
	}
	
	private int getIntValue(boolean lower) {
		int segCount = getSegmentCount();
		int result = 0;
		for(int i = 0; i < segCount; i++) {
			IPv4AddressSegment seg = getSegment(i);
			result = (result << IPv4Address.BITS_PER_SEGMENT) | (lower ? seg.getSegmentValue() : seg.getUpperSegmentValue());
		}
		return result;
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
		return withoutPrefixLength();
	}
	
	@Override
	public IPv4AddressSection reverseSegments() {
		if(getSegmentCount() <= 1) {
			if(isPrefixed()) {
				return withoutPrefixLength();
			}
			return this;
		}
		return reverseSegments(this, getAddressCreator(), (i) -> getSegment(i).withoutPrefixLength(), true);
	}
	
	@Override
	protected IPv4AddressSegment[] getSegmentsInternal() {
		return (IPv4AddressSegment[])  super.getDivisionsInternal();
	}

	@Override
	public Iterable<IPv4AddressSection> getIterable() {
		return this;
	}
	
	private Iterator<IPv4AddressSection> iterator(boolean excludeZeroHosts) {
		boolean isAllSubnets = getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets();
		boolean useOriginal = !isMultiple() && (!isAllSubnets || !isPrefixed());
		IPv4AddressSection original;
		if(useOriginal && excludeZeroHosts && includesZeroHost()) {
			original = null;
		} else {
			original = this;
		}
		return iterator(
				useOriginal,
				original,
				getAddressCreator(),
				useOriginal ? null : segmentsIterator(excludeZeroHosts),
				isAllSubnets ? null : getPrefixLength());
	}
	
	@Override
	public Iterator<IPv4AddressSection> nonZeroHostIterator() {
		return iterator(true);
	}
	
	@Override
	public Iterator<IPv4AddressSection> iterator() {
		return iterator(false);
	}
	
	@Override
	public Iterator<IPv4AddressSection> prefixIterator() {
		return prefixIterator(false);
	}
	
	@Override
	public Iterator<IPv4AddressSection> prefixBlockIterator() {
		return prefixIterator(true);
	}
	
	private Iterator<IPv4AddressSection> prefixIterator(boolean isBlockIterator) {
		Integer prefLength = getPrefixLength();
		if(prefLength == null || prefLength > getBitCount()) {
			return iterator();
		}
		IPv4AddressCreator creator = getAddressCreator();
		boolean useOriginal = isBlockIterator ? isSinglePrefixBlock() : getIPv4PrefixCount() == 1;
		return iterator(
				useOriginal,
				this,
				creator,
				useOriginal ?
						null :
						iterator(
							getSegmentCount(),
							creator,
							null, //when no prefix we defer to other iterator, when there is one we use the whole original section in the encompassing iterator and not just the original segments
							index -> getSegment(index).iterator(),
							null, 
							getNetworkSegmentIndex(prefLength, IPv4Address.BYTES_PER_SEGMENT, IPv4Address.BITS_PER_SEGMENT), 
							getHostSegmentIndex(prefLength, IPv4Address.BYTES_PER_SEGMENT, IPv4Address.BITS_PER_SEGMENT), 
							isBlockIterator ? index -> getSegment(index).prefixBlockIterator() : index -> getSegment(index).prefixIterator()),
				prefLength);
	}
	
	@Override
	public Iterator<IPv4AddressSection> blockIterator(int segmentCount) {
		if(segmentCount < 0) {
			throw new IllegalArgumentException();
		}
		if(segmentCount >= getSegmentCount()) {
			return iterator();
		}
		IPv4AddressCreator creator = getAddressCreator();
		boolean useOriginal = true;
		for(int i = 0; i < segmentCount; i++) {
			if(getSegment(i).isMultiple()) {
				useOriginal = false;
				break;
			}
		}
		boolean isAllSubnets = getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets();
		return iterator(
				useOriginal,
				this,
				creator,
				useOriginal ?
						null :
						iterator(
							getSegmentCount(),
							creator,
							null, //when no prefix we defer to other iterator, when there is one we use the whole original section in the encompassing iterator and not just the original segments
							index -> getSegment(index).iterator(!isAllSubnets),
							null, 
							segmentCount - 1, 
							segmentCount, 
							index -> getSegment(index).identityIterator()),
				isAllSubnets ? null : getPrefixLength());
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv4AddressSection> sequentialBlockIterator() {
		return (Iterator<IPv4AddressSection>) super.sequentialBlockIterator();
	}

	private Iterator<IPv4AddressSegment[]> segmentsIterator(boolean excludeZeroHosts) {
		boolean isAllSubnets = getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets();
		return iterator(getSegmentCount(), getSegmentCreator(), isMultiple() ? null : () -> getLower().getSegments(), index -> getSegment(index).iterator(!isAllSubnets), excludeZeroHosts ? this::isZeroHost : null);
	}
	
	@Override
	public Iterator<IPv4AddressSegment[]> segmentsNonZeroHostIterator() {
		return segmentsIterator(true);
	}
	
	@Override
	public Iterator<IPv4AddressSegment[]> segmentsIterator() {
		return segmentsIterator(false);
	}

	protected Iterator<IPv4Address> iterator(IPv4Address original,
			AddressCreator<IPv4Address, ?, ?, IPv4AddressSegment> creator,
			boolean excludeZeroHosts) {
		boolean isAllSubnets = getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets();
		boolean useOriginal = !isMultiple() && (!isAllSubnets || !isPrefixed());
		useOriginal &= !excludeZeroHosts || !original.includesZeroHost();
		return iterator(
				useOriginal ? original : null,
				creator, // using a lambda for this one results in a big performance hit
				useOriginal ? null : 
					iterator(
							getSegmentCount(),
							creator,
							isMultiple() ? null : () -> getLower().getSegmentsInternal(),
							index -> getSegment(index).iterator(!isAllSubnets),
							excludeZeroHosts ? this::isZeroHost : null),
				isAllSubnets ? null : getPrefixLength());
	}
	
	Iterator<IPv4Address> prefixBlockIterator(IPv4Address original, AddressCreator<IPv4Address, ?, ?, IPv4AddressSegment> creator, boolean isBlockIterator) {
		Integer prefLength = getPrefixLength();
		if(prefLength == null || prefLength > getBitCount()) {
			return iterator(original, creator, false);
		}
		return prefixIterator(original, creator, isBlockIterator, prefLength);
	}
	
	Iterator<IPv4Address> prefixIterator(IPv4Address original, AddressCreator<IPv4Address, ?, ?, IPv4AddressSegment> creator, boolean isBlockIterator, int prefLength) {
		if(prefLength > getBitCount() || prefLength < 0) {
			throw new PrefixLenException(original, prefLength);
		}
		boolean useOriginal = isBlockIterator ? isSinglePrefixBlock() : getIPv4PrefixCount() == 1;
		return iterator(
				useOriginal ? original : null, 
				creator, // using a lambda for this one results in a big performance hit
				useOriginal ? null :
					iterator(
							getSegmentCount(),
							creator,
							null, // when no prefix we defer to other iterator, when there is one we use the whole original address in the encompassing iterator and not just the original segments
							index -> getSegment(index).iterator(),
							null,
							getNetworkSegmentIndex(prefLength, IPv4Address.BYTES_PER_SEGMENT, IPv4Address.BITS_PER_SEGMENT), 
							getHostSegmentIndex(prefLength, IPv4Address.BYTES_PER_SEGMENT, IPv4Address.BITS_PER_SEGMENT), 
							isBlockIterator ? index -> getSegment(index).prefixBlockIterator() : index -> getSegment(index).prefixIterator()),
				prefLength);
	}
	
	Iterator<IPv4Address> blockIterator(IPv4Address original, AddressCreator<IPv4Address, ?, ?, IPv4AddressSegment> creator, int segmentCount) {
		if(segmentCount < 0) {
			throw new IllegalArgumentException();
		}
		if(segmentCount > getSegmentCount()) {
			return iterator(original, creator, false);
		}
		boolean isAllSubnets = getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets();
		boolean useOriginal = true;
		for(int i = 0; i < segmentCount; i++) {
			if(getSegment(i).isMultiple()) {
				useOriginal = false;
				break;
			}
		}
		return iterator(
				useOriginal ? original : null, 
				creator,// using a lambda for this one results in a big performance hit
				useOriginal ? null :
					iterator(
							getSegmentCount(),
							creator,
							null, // when no prefix we defer to other iterator, when there is one we use the whole original address in the encompassing iterator and not just the original segments
							index -> getSegment(index).iterator(!isAllSubnets),
							null,
							segmentCount - 1,
							segmentCount,
							index -> getSegment(index).identityIterator()),
				isAllSubnets ? null : getPrefixLength());
	}

	private static long getMaxValue(int segmentCount) {
		return MAX_VALUES[segmentCount];
	}
	
	@Override
	public IPv4AddressSection incrementBoundary(long increment) {
		if(increment <= 0) {
			if(increment == 0) {
				return this;
			}
			return getLower().increment(increment);
		}
		return getUpper().increment(increment);
	}

	@Override
	public IPv4AddressSection increment(long increment) {
		if(increment == 0 && !isMultiple()) {
			return this;
		}
		long lowerValue = 0xffffffffL & intValue();
		long upperValue = 0xffffffffL & upperIntValue();
		long count = getCount().longValue();
		checkOverflow(increment, lowerValue, upperValue, count, () -> getMaxValue(getSegmentCount()));
		return increment(
				this,
				increment,
				getAddressCreator(),
				count,
				lowerValue,
				upperValue,
				this::getLower,
				this::getUpper,
				getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets() ? null : getPrefixLength());
	}

	private static long getCount(IntUnaryOperator countProvider, int segCount) {
		if(segCount == 0) {
			return 1;
		}
		long result = countProvider.applyAsInt(0);
		for(int i = 1; i < segCount; i++) {
			result *= countProvider.applyAsInt(i);
		}
		return result;
	}
	
	public long getIPv4Count(boolean excludeZeroHosts) {
		return getIPv4Count(excludeZeroHosts, getSegmentCount());
	}

	//This was added so count available as a long and not as BigInteger
	private long getIPv4Count(boolean excludeZeroHosts, int segCount) {
		if(!isMultiple()) {
			if(excludeZeroHosts && isZero()) {
				return 0L;
			}
			return 1L;
		}
		long result = getCount(i -> getSegment(i).getValueCount(), segCount);
		if(excludeZeroHosts && includesZeroHost()) {
			int prefixedSegment = getNetworkSegmentIndex(getNetworkPrefixLength(), IPv4Address.BYTES_PER_SEGMENT, IPv4Address.BITS_PER_SEGMENT);
			long zeroHostCount = getCount(i -> {
				if(i == prefixedSegment) {
					IPAddressSegment seg = getSegment(i);
					int shift = seg.getBitCount() - seg.getSegmentPrefixLength();
					int count = ((seg.getUpperSegmentValue() >>> shift) - (seg.getSegmentValue() >>> shift)) + 1;
					return count;
				}
				return getSegment(i).getValueCount();
			}, prefixedSegment + 1);
			result -= zeroHostCount;
		}
		return result;
	}
	
	@Override
	protected BigInteger getCountImpl(boolean excludeZeroHosts, int segCount) {
		if(!isMultiple()) {
			if(excludeZeroHosts && includesZeroHost()) {
				return BigInteger.ZERO;
			}
			return BigInteger.ONE;
		}
		return BigInteger.valueOf(getIPv4Count(excludeZeroHosts, segCount));
	}

	//This was added so count available as a long and not as BigInteger
	public long getIPv4PrefixCount(int prefixLength) {
		checkSubnet(this, prefixLength);
		if(isMultiple()) {
			int networkSegmentIndex = getNetworkSegmentIndex(prefixLength, IPv4Address.BYTES_PER_SEGMENT, IPv4Address.BITS_PER_SEGMENT);
			int hostSegmentIndex = getHostSegmentIndex(prefixLength, IPv4Address.BYTES_PER_SEGMENT, IPv4Address.BITS_PER_SEGMENT);
			boolean hasPrefixedSegment = (networkSegmentIndex == hostSegmentIndex);
			return getCount(i -> {
				if(hasPrefixedSegment && i == networkSegmentIndex) {
					return getSegment(i).getPrefixValueCount();
				}
				return getSegment(i).getValueCount();
			}, networkSegmentIndex + 1);
		}
		return 1;
	}
		
	@Override
	public BigInteger getPrefixCount(int prefixLength) {
		return BigInteger.valueOf(getIPv4PrefixCount(prefixLength));
	}
		
	public long getIPv4PrefixCount() {
		Integer prefixLength = getPrefixLength();
		if(prefixLength == null || prefixLength >= getBitCount()) {
			return getIPv4Count(false);
		}
		return getIPv4PrefixCount(prefixLength);
	}

	@Override
	protected BigInteger getPrefixCountImpl() {
		return BigInteger.valueOf(getIPv4PrefixCount());
	}
	
	private IPv4AddressCreator getSegmentCreator() {
		return getIPv4SegmentCreator();
	}

	private IPv4AddressCreator getAddressCreator() {
		return getIPv4SegmentCreator();
	}
	
	private IPv4AddressCreator getIPv4SegmentCreator() {
		return getNetwork().getAddressCreator();
	}
	
	@Override
	public IPv4AddressSegment getDivision(int index) {
		return (IPv4AddressSegment) super.getDivision(index);
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
	public int getBitCount() {
		return getSegmentCount() << 3;
	}
	
	@Override
	public int getByteCount() {
		return getSegmentCount();
	}
	
	@Override
	protected byte[] getBytesImpl(boolean low) {
		int segmentCount = getSegmentCount();
		byte bytes[] = new byte[segmentCount];
		for(int i = 0; i < segmentCount; i++) {
			IPv4AddressSegment seg = getSegment(i);
			int val = low ? seg.getSegmentValue() : seg.getUpperSegmentValue();
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
	public boolean matchesWithMask(IPAddressSection other, IPAddressSection mask) {
		return other instanceof IPv4AddressSection && mask instanceof IPv4AddressSection && super.matchesWithMask(other, mask);
	}
	
	@Override
	protected boolean isSameGrouping(AddressDivisionGroupingBase other) {
		return other instanceof IPv4AddressSection && super.isSameGrouping(other);
	}
	
	@Override
	public boolean equals(Object o) {
		return o == this || (o instanceof IPv4AddressSection && ((IPv4AddressSection) o).isSameGrouping(this));
	}
	
	@Override
	public boolean contains(AddressSection other) {
		return other instanceof IPv4AddressSection && super.contains(other);
	}
	
	@Override
	public boolean prefixEquals(AddressSection other) {
		return other == this || (other instanceof IPv4AddressSection && prefixEquals(this, other, 0));
	}

	public IPv4AddressSection append(IPv4AddressSection other) {
		int count = getSegmentCount();
		return replace(count, count, other, 0, other.getSegmentCount());
	}

	public IPv4AddressSection insert(int index, IPv4AddressSection other) {
		return replace(index, index, other, 0, other.getSegmentCount());
	}

	/**
	 * Replace the segments of this section starting at the given index with the given replacement segments
	 * 
	 * @param index
	 * @param other
	 * @return
	 */
	public IPv4AddressSection replace(int index, IPv4AddressSection other) {
		return replace(index, index + other.getSegmentCount(), other, 0, other.getSegmentCount());
	}

	public IPv4AddressSection appendToNetwork(IPv4AddressSection other) {
		Integer prefixLength = getNetworkPrefixLength();
		if(prefixLength == null) {
			return append(other);
		}
		IPv4AddressSection thizz = this;
		int bitsPerSegment = getBitsPerSegment();
		int adjustment = prefixLength % bitsPerSegment;
		if(adjustment != 0) {
			prefixLength += bitsPerSegment - adjustment;
			thizz = setPrefixLength(prefixLength, false);
		}
		int index = prefixLength >>> 3;
		if(other.isPrefixed() && other.getPrefixLength() == 0) {
			//replacement is all host, cannot make it part of network
			return insert(index, other);
		}
		return thizz.replace(index, index, other, 0, other.getSegmentCount(), true);
	}
	
	/**
	 * Replaces segments starting from startIndex and ending before endIndex with the segments starting at replacementStartIndex and 
	 * ending before replacementEndIndex from the replacement section
	 * @param startIndex
	 * @param endIndex
	 * @param replacement
	 * @param replacementStartIndex
	 * @param replacementEndIndex
	 * @throws IndexOutOfBoundsException
	 * @throws IncompatibleAddressException if the resulting section would exceed the maximum segment count for this address type and version
	 * @return
	 */
	public IPv4AddressSection replace(int startIndex, int endIndex, IPv4AddressSection replacement, int replacementStartIndex, int replacementEndIndex) {
		return replace(startIndex, endIndex, replacement, replacementStartIndex, replacementEndIndex, false);
	}
	
	private IPv4AddressSection replace(int startIndex, int endIndex, IPv4AddressSection replacement, int replacementStartIndex, int replacementEndIndex, boolean appendNetwork) {
		int segmentCount = getSegmentCount();
		int replacedCount = endIndex - startIndex;
		int replacementCount = replacementEndIndex - replacementStartIndex;
		if(replacedCount < 0 || replacementCount < 0 || startIndex < 0 || replacementStartIndex < 0 || replacementEndIndex > replacement.getSegmentCount() || endIndex > segmentCount) {
			throw new IndexOutOfBoundsException();
		}
		IPv4AddressSection thizz = this;
		if(segmentCount + replacementCount - replacedCount > IPv4Address.SEGMENT_COUNT) {
			throw new AddressValueException(this, replacement, segmentCount + replacementCount - replacedCount);
		} else if(replacementCount == 0 && replacedCount == 0) {//keep in mind for ipvx, empty sections cannot have prefix lengths
			return this;
		} else if(segmentCount == replacedCount) {//keep in mind for ipvx, empty sections cannot have prefix lengths
			return replacement;
		} else if(getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
			if(appendNetwork) {
				thizz = withoutPrefixLength();
				int replacementEndBits = replacementEndIndex << 3;
				if(!replacement.isPrefixed() || replacement.getNetworkPrefixLength() > replacementEndBits) {
					replacement = replacement.setPrefixLength(replacementEndBits, false);
				}
			}
		} else {
			Integer prefixLength = getPrefixLength();
			if(appendNetwork) {
				int additionalSegs = segmentCount - endIndex;
				if(additionalSegs > 0) {
					//we move the non-replaced host segments from the end of this to the end of the replacement segments
					//and we also remove the prefix length from this
					thizz = getSection(0, startIndex).withoutPrefixLength();
					replacement = replacement.insert(replacementEndIndex, getSection(endIndex));
					replacementEndIndex += additionalSegs;
					endIndex = startIndex;
				} else {
					thizz = withoutPrefixLength();
					int replacementEndBits = replacementEndIndex << 3;
					if(!replacement.isPrefixed() || replacement.getNetworkPrefixLength() > replacementEndBits) {
						replacement = replacement.setPrefixLength(replacementEndBits, false);
					}
				}
			} else if(prefixLength != null && !appendNetwork && prefixLength <= startIndex << 3) {
				replacement = replacement.setPrefixLength(0, false);
			} else if(endIndex < segmentCount) {
				int replacementEndBits = replacementEndIndex << 3;
				if(replacement.isPrefixed() && replacement.getNetworkPrefixLength() <= replacementEndBits) {
					int thisNextIndexBits = endIndex << 3;
					if(prefixLength == null || prefixLength > thisNextIndexBits) {
						if(replacedCount > 0 || replacement.getPrefixLength() == 0) {
							thizz = setPrefixLength(thisNextIndexBits, false);
						} else {
							//we move the non-replaced host segments from the end of this to the end of the replacement segments
							//and we also remove the prefix length from this
							int additionalSegs = segmentCount - endIndex;
							thizz = getSection(0, startIndex);
							replacement = replacement.insert(replacementEndIndex, getSection(endIndex));
							replacementEndIndex += additionalSegs;
						}
					}
				}
			}
		}
		return replace(thizz, startIndex, endIndex, replacement, replacementStartIndex, replacementEndIndex, getAddressCreator(), appendNetwork, false);
	}
	
	/**
	 * Produces the subnet sections whose addresses are found in both this and the given argument.
	 * <p>
	 * This is also known as the conjunction of the two sets of address sections.
	 * <p>
	 * @param other
	 * @return the section containing the sections found in both this and the given subnet sections
	 */
	public IPv4AddressSection intersect(IPv4AddressSection other) throws SizeMismatchException {
		return intersect(this, other, getAddressCreator(), this::getSegment, other::getSegment);
	}
	
	/**
	 * Subtract the given subnet from this subnet, returning an array of sections for the result (the subnets will not be contiguous so an array is required).
	 * <p>
	 * Computes the subnet difference, the set of addresses in this address section but not in the provided section.  This is also known as the relative complement of the given argument in this subnet.
	 * <p>
	 * Keep in mind this is set subtraction, not subtraction of segment values.  We have a subnet of addresses and we are removing some of those addresses.
	 * 
	 * @param other
	 * @throws SizeMismatchException if the two sections are different sizes
	 * @return the difference
	 */
	public IPv4AddressSection[] subtract(IPv4AddressSection other) throws SizeMismatchException {
		return subtract(this, other, getAddressCreator(), this::getSegment, (section, prefix) -> section.setPrefixLength(prefix, false, true));
	}

	@Override
	public IPv4AddressNetwork getNetwork() {
		return Address.defaultIpv4Network();
	}

	@Override
	public IPv4AddressSection adjustPrefixBySegment(boolean nextSegment) {
		return adjustPrefixBySegment(nextSegment, true);
	}
	
	@Override
	public IPv4AddressSection adjustPrefixBySegment(boolean nextSegment, boolean zeroed) {
		return (IPv4AddressSection) super.adjustPrefixBySegment(nextSegment, zeroed);
	}
	
	@Override
	public IPv4AddressSection adjustPrefixLength(int adjustment) {
		return adjustPrefixLength(adjustment, true);
	}

	@Override
	public IPv4AddressSection adjustPrefixLength(int adjustment, boolean zeroed) {
		return (IPv4AddressSection) adjustPrefixLength(this, adjustment, zeroed, getAddressCreator(), (section, i) -> section.getSegment(i));
	}
	
	@Override
	public IPv4AddressSection applyPrefixLength(int networkPrefixLength) {
		return setPrefixLength(networkPrefixLength, true, true);
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
				(section, i) -> section.getSegment(i));
	}

	@Override
	public IPv4AddressSection removePrefixLength() {
		return removePrefixLength(true);
	}
	
	@Override
	public IPv4AddressSection withoutPrefixLength() {
		return removePrefixLength(false);
	}
	
	@Override @Deprecated
	public IPv4AddressSection removePrefixLength(boolean zeroed) {
		return removePrefixLength(this, zeroed, getAddressCreator(), IPv4AddressSection::getSegment);
	}

	@Override
	public IPv4AddressSection toZeroHost() throws IncompatibleAddressException {
		if(!isPrefixed()) {
			IPv4Address networkMask = getNetwork().getNetworkMask(0, !getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets());
			return networkMask.getSection(0, getSegmentCount());
		}
		if(includesZeroHost() && isSingleNetwork()) {
			return getLower();//cached
		}
		return createZeroHost();
	}

	IPv4AddressSection createZeroHost() {
		int prefixLength = getNetworkPrefixLength();//we know it is prefixed here so no NullPointerException
		IPv4Address mask = getNetwork().getNetworkMask(prefixLength);
		return getSubnetSegments(
				this,
				getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets() ? null : getNetworkPrefixLength(),
				getAddressCreator(),
				false,
				this::getSegment,
				i -> mask.getSegment(i).getSegmentValue(),
				true);
	}
	
	@Override
	public IPv4AddressSection toZeroHost(int prefixLength) {
		if(isPrefixed() && prefixLength == getNetworkPrefixLength()) {
			return toZeroHost();
		}
		IPv4Address mask = getNetwork().getNetworkMask(prefixLength);
		return getSubnetSegments(
				this,
				null,
				getAddressCreator(),
				false,
				this::getSegment,
				i -> mask.getSegment(i).getSegmentValue(),
				true);
	}

	@Override
	public IPv4AddressSection toMaxHost() throws IncompatibleAddressException {
		if(!isPrefixed()) {
			IPv4Address resultNoPrefix = getNetwork().getHostMask(0);
			if(getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
				return resultNoPrefix.getSection(0, getSegmentCount());
			}
			return resultNoPrefix.setPrefixLength(0).getSection(0, getSegmentCount());
		}
		if(includesZeroHost() && isSingleNetwork()) {
			return getLower(); // cached
		}
		return createMaxHost();
	}

	public IPv4AddressSection createMaxHost() {
		int prefixLength = getNetworkPrefixLength();//we know it is prefixed here so no NullPointerException
		IPv4Address mask = getNetwork().getHostMask(prefixLength);
		return getOredSegments(
				this,
				getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets() ? null : prefixLength,
				getAddressCreator(),
				false,
				this::getSegment,
				i -> mask.getSegment(i).getSegmentValue());
	}

	@Override
	public IPv4AddressSection toMaxHost(int prefixLength) {
		if(isPrefixed() && prefixLength == getNetworkPrefixLength()) {
			return toMaxHost();
		}
		IPv4Address mask = getNetwork().getHostMask(prefixLength);
		return getOredSegments(
				this,
				null,
				getAddressCreator(),
				false,
				this::getSegment,
				i -> mask.getSegment(i).getSegmentValue());
	}

	/**
	 * Does the bitwise conjunction with this address.  Useful when subnetting.
	 * 
	 * @param mask
	 * @param retainPrefix whether to drop the prefix
	 * @return
	 * @throws IncompatibleAddressException
	 */
	public IPv4AddressSection mask(IPv4AddressSection mask, boolean retainPrefix) throws IncompatibleAddressException, PrefixLenException, SizeMismatchException {
		checkMaskSectionCount(mask);
		return getSubnetSegments(
				this,
				retainPrefix ? getPrefixLength() : null,
				getAddressCreator(),
				true,
				this::getSegment,
				i -> mask.getSegment(i).getSegmentValue(),
				false);
	}

	/**
	 * Equivalent to {@link #mask(IPv4AddressSection, boolean)} with the second argument as false.
	 */
	public IPv4AddressSection mask(IPv4AddressSection mask) throws IncompatibleAddressException {
		return mask(mask, false);
	}
	
	/**
	 * Produces the bitwise conjunction of the given mask with the network section of the address as indicated by the given prefix length.
	 * Useful for subnetting.  Once you have zeroed a section of the network you can insert bits 
	 * using {@link #bitwiseOr(IPv4AddressSection)} or {@link #replace(int, IPv4AddressSection)}
	 * 
	 * @param mask
	 * @param networkPrefixLength
	 * @return
	 * @throws IncompatibleAddressException
	 */
	public IPv4AddressSection maskNetwork(IPv4AddressSection mask, int networkPrefixLength) throws IncompatibleAddressException, PrefixLenException, SizeMismatchException {
		checkMaskSectionCount(mask);
		if(getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
			return getSubnetSegments(
					this,
					cacheBits(networkPrefixLength),
					getAddressCreator(),
					true,
					this::getSegment,
					i -> mask.getSegment(i).getSegmentValue(),
					false);
		}
		IPv4AddressSection hostMask = getNetwork().getHostMaskSection(networkPrefixLength);
		return getSubnetSegments(
				this,
				cacheBits(networkPrefixLength),
				getAddressCreator(),
				true, 
				this::getSegment, 
				i -> {
					int val1 = mask.getSegment(i).getSegmentValue();
					int val2 = hostMask.getSegment(i).getSegmentValue();
					return val1 | val2;
				},
				false
		);
	}

	protected static Integer cacheBits(int i) {
		return IPAddressSection.cacheBits(i);
	}
	
	/**
	 * Equivalent to {@link #bitwiseOr(IPv4AddressSection, boolean)} with the second argument as false.
	 */
	public IPv4AddressSection bitwiseOr(IPv4AddressSection mask) throws IncompatibleAddressException {
		return bitwiseOr(mask, false);
	}
	
	/**
	 * Does the bitwise disjunction with this address section.  Useful when subnetting.  Similar to {@link #mask(IPv4AddressSection)} which does the bitwise conjunction.
	 * 
	 * @param retainPrefix whether the result will retain the same prefix length as this.
	 * @return
	 * @throws IncompatibleAddressException
	 */
	public IPv4AddressSection bitwiseOr(IPv4AddressSection mask, boolean retainPrefix) throws IncompatibleAddressException, SizeMismatchException {
		checkMaskSectionCount(mask);
		return getOredSegments(
				this,
				retainPrefix ? getPrefixLength() : null,
				getAddressCreator(),
				true,
				this::getSegment,
				i -> mask.getSegment(i).getSegmentValue());
	}

	/**
	 * Does the bitwise disjunction with this address section.  Useful when subnetting.  Similar to {@link #maskNetwork(IPv4AddressSection, int)} which does the bitwise conjunction.
	 * <p>
	 * Any existing prefix length is dropped for the new prefix length and the disjunction is applied up to the end the new prefix length.
	 * 
	 * @param mask
	 * @return
	 * @throws IncompatibleAddressException
	 */
	public IPv4AddressSection bitwiseOrNetwork(IPv4AddressSection mask, int networkPrefixLength) throws IncompatibleAddressException, SizeMismatchException {
		checkMaskSectionCount(mask);
		if(getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
			return getOredSegments(
					this,
					networkPrefixLength,
					getAddressCreator(),
					true,
					this::getSegment,
					i -> mask.getSegment(i).getSegmentValue());
		}
		IPv4AddressSection networkMask = getNetwork().getNetworkMaskSection(networkPrefixLength);
		return getOredSegments(
				this,
				networkPrefixLength,
				getAddressCreator(),
				true,
				this::getSegment, 
				i -> {
					int val1 = mask.getSegment(i).getSegmentValue();
					int val2 = networkMask.getSegment(i).getSegmentValue();
					return val1 & val2;
				}
		);
	}

	@Override
	public IPv4AddressSection getNetworkSection() {
		if(isPrefixed()) {
			return getNetworkSection(getNetworkPrefixLength());
		}
		return getNetworkSection(getBitCount());
	}
	
	@Override
	public IPv4AddressSection getNetworkSection(int networkPrefixLength) throws PrefixLenException {
		return getNetworkSection(networkPrefixLength, true);
	}
	
	@Override
	public IPv4AddressSection getNetworkSection(int networkPrefixLength, boolean withPrefixLength) throws PrefixLenException {
		return getNetworkSection(this, networkPrefixLength, withPrefixLength, getAddressCreator(), (i, prefix) -> getSegment(i).toNetworkSegment(prefix, withPrefixLength));
	}
	
	@Override
	public IPv4AddressSection getHostSection() {
		if(isPrefixed()) {
			return getHostSection(getNetworkPrefixLength());
		}
		return getHostSection(0);
	}
	
	@Override
	public IPv4AddressSection getHostSection(int networkPrefixLength) throws PrefixLenException {
		int hostSegmentCount = getHostSegmentCount(networkPrefixLength);
		return getHostSection(this, networkPrefixLength, hostSegmentCount, getAddressCreator(), (i, prefix) -> getSegment(i).toHostSegment(prefix));
	}
	
	@Override
	public IPv4AddressSection toPrefixBlock() {
		Integer prefixLength = getNetworkPrefixLength();
		if(prefixLength == null || getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
			return this;
		}
		return toPrefixBlock(prefixLength);
	}
	
	@Override
	public IPv4AddressSection toPrefixBlock(int networkPrefixLength) throws PrefixLenException {
		return toPrefixBlock(this, networkPrefixLength, getAddressCreator(), (i, prefix) -> getSegment(i).toNetworkSegment(prefix, true));
	}
	
	@Override
	public IPv4AddressSection assignPrefixForSingleBlock() {
		return (IPv4AddressSection) super.assignPrefixForSingleBlock();
	}
	
	@Override
	public IPv4AddressSection assignMinPrefixForBlock() {
		return (IPv4AddressSection) super.assignMinPrefixForBlock();
	}
	
	/**
	 * Produces the list of prefix block subnets that span from this series to the given series.
	 * 
	 * @param other
	 * @return
	 */
	public IPv4AddressSection[] spanWithPrefixBlocks(IPv4AddressSection other) {
		return getSpanningPrefixBlocks(
				this,
				other,
				IPv4AddressSection::getLower,
				IPv4AddressSection::getUpper,
				Address.ADDRESS_LOW_VALUE_COMPARATOR::compare,
				IPv4AddressSection::assignPrefixForSingleBlock,
				IPv4AddressSection::withoutPrefixLength,
				getAddressCreator()::createSectionArray);
	}
	
	/**
	 * 
	 * @param other
	 * @deprecated use {@link #spanWithSequentialBlocks(IPv4AddressSection)}
	 * @return
	 */
	@Deprecated
	public IPv4AddressSection[] spanWithRangedSegments(IPv4AddressSection other) {
		return spanWithSequentialBlocks(other);
	}
	
	/**
	 * Produces a list of range subnets that span from this series to the given series.
	 * 
	 * @param other
	 * @return
	 */
	public IPv4AddressSection[] spanWithSequentialBlocks(IPv4AddressSection other) {
		return getSpanningSequentialBlocks(
				this,
				other,
				IPv4AddressSection::getLower,
				IPv4AddressSection::getUpper,
				Address.ADDRESS_LOW_VALUE_COMPARATOR::compare,
				IPv4AddressSection::withoutPrefixLength,
				getAddressCreator());
	}
	
	/**
	 * 
	 * @param sections
	 * @deprecated use {@link #mergeToPrefixBlocks(IPv4AddressSection...)}
	 * @return
	 * @throws SizeMismatchException
	 */
	@Deprecated
	public IPv4AddressSection[] mergePrefixBlocks(IPv4AddressSection ...sections) throws SizeMismatchException {
		return mergeToPrefixBlocks(sections);
	}

	/**
	 * Merges this with the list of sections to produce the smallest array of prefix blocks, going from smallest to largest
	 * 
	 * @param sections the sections to merge with this
	 * @return
	 */
	public IPv4AddressSection[] mergeToPrefixBlocks(IPv4AddressSection ...sections) throws SizeMismatchException {
		List<IPAddressSegmentSeries> blocks = getMergedPrefixBlocks(this, sections, true);
		return blocks.toArray(new IPv4AddressSection[blocks.size()]);
	}
	
	/**
	 * Merges this with the list of sections to produce the smallest array of sequential block subnets, going from smallest to largest
	 * 
	 * @param sections the sections to merge with this
	 * @return
	 */
	public IPv4AddressSection[] mergeToSequentialBlocks(IPv4AddressSection ...sections) throws SizeMismatchException {
		List<IPAddressSegmentSeries> blocks = getMergedSequentialBlocks(this, sections, true, createSeriesCreator(getAddressCreator(), getMaxSegmentValue()));
		return blocks.toArray(new IPv4AddressSection[blocks.size()]);
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
	 * 
	 * If this has a prefix length, that will be included in the string.
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
	 * and is the same as {@link #toCanonicalString()}.
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
		IPAddressDivisionGrouping equivalentPart = new IPAddressDivisionGrouping(segs, getNetwork());
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
					throw new IncompatibleAddressException(firstRange, firstSegIndex, thisSeg, firstJoinedIndex + j, "ipaddress.error.segmentMismatch");
				}
			} else if(thisSeg.isMultiple()) {
				firstSegIndex = firstJoinedIndex + j;
				firstRange = thisSeg;
			}
			lower = lower << IPv4Address.BITS_PER_SEGMENT | thisSeg.getSegmentValue();
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
	
	static class EmbeddedIPv4AddressSection extends IPv4AddressSection {

		private static final long serialVersionUID = 4L;
		
		private final IPAddressSection encompassingSection;

		EmbeddedIPv4AddressSection(IPAddressSection encompassingSection, IPv4AddressSegment subSegments[]) {
			super(subSegments, false);
			this.encompassingSection = encompassingSection;
		}

		@Override
		public boolean isPrefixBlock() {
			return encompassingSection.isPrefixBlock();
		}
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
					ipv6AddressConverter = IPAddress.DEFAULT_ADDRESS_CONVERTER;
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
			public IPv4StringOptions toOptions() {
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
						int count = addressSection.getDivisionCount();
						for(int i = 0; i < count; i++) {
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
										for(int k = 0; k < count; k++) {
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
