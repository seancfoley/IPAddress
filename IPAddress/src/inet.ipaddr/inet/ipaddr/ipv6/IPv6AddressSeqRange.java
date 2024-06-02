/*
 * Copyright 2018-2022 Sean C Foley
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
import java.util.Iterator;
import java.util.function.Function;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressSeqRange;
import inet.ipaddr.NetworkMismatchException;
import inet.ipaddr.PrefixLenException;
import inet.ipaddr.format.standard.AddressCreator;
import inet.ipaddr.format.util.AddressComponentRangeSpliterator;
import inet.ipaddr.format.util.AddressComponentSpliterator;
import inet.ipaddr.format.validate.ParsedAddressGrouping;
import inet.ipaddr.ipv6.IPv6AddressNetwork.IPv6AddressCreator;

/**
 * Represents an arbitrary range of IPv6 addresses.
 * 
 * See {@link IPAddressSeqRange} for more details.
 * <p>
 * @custom.core
 * @author sfoley
 *
 */
public class IPv6AddressSeqRange extends IPAddressSeqRange implements Iterable<IPv6Address> {
	
	private static final long serialVersionUID = 1L;

	private static final BigInteger LONG_MAX = BigInteger.valueOf(Long.MAX_VALUE);
	private static final IPv6AddressSeqRange EMPTY[] = {};

	IPv6AddressSeqRange(IPv6Address first, IPv6Address second, boolean preSet) {
		super(first, second, preSet);
	}

	public IPv6AddressSeqRange(IPv6Address first, IPv6Address second) {
		super(
			first,
			second,
			IPv6Address::getLower,
			IPv6Address::getUpper,
			a -> a.withoutPrefixLength().removeZone());
		if(!first.getNetwork().isCompatible(second.getNetwork())) {
			throw new NetworkMismatchException(first, second);
		}
	}
	
	private IPv6AddressSeqRange(IPAddress first, IPAddress second) {
		super(first, second);
	}
	
	@Override
	public IPv6Address getLower() {
		return (IPv6Address) super.getLower();
	}
	
	@Override
	public IPv6Address getUpper() {
		return (IPv6Address) super.getUpper();
	}
	
	private IPv6AddressCreator getAddressCreator() {
		return getLower().getDefaultCreator();
	}

	@Override
	public Iterable<IPv6Address> getIterable() {
		return this;
	}

	@Override
	public Iterator<IPv6Address> iterator() {
		IPv6Address lower = getLower();
		IPv6Address upper = getUpper();
		AddressCreator<IPv6Address, ?, ?, IPv6AddressSegment> creator = getAddressCreator();
		if(!isMultiple()) {
			return iterator(lower, creator);
		}
		int divCount = lower.getSegmentCount();
		return iterator(
				lower,
				upper,
				creator,
				IPv6Address::getSegment,
				(seg, segIndex) -> seg.iterator(),
				(addr1, addr2, index) -> addr1.getSegment(index).getSegmentValue() == addr2.getSegment(index).getSegmentValue(),
				divCount - 1,
				divCount,
				null);
	}
	
	@Override
	public AddressComponentRangeSpliterator<IPv6AddressSeqRange, IPv6Address> spliterator() {
		int segmentCount = getLower().getSegmentCount();
		IPv6AddressCreator creator = getAddressCreator();
		int networkSegIndex = segmentCount - 1;
		int hostSegIndex = segmentCount;
		return createSpliterator(
				this,
				spliterator -> {
					IPv6AddressSeqRange range = spliterator.getAddressItem();
					return split(
						spliterator,
						(segsLower, segsUpper) -> new IPv6AddressSeqRange(
								creator.createAddressInternal(segsLower),
								creator.createAddressInternal(segsUpper)),
						creator,
						range.getLower().getSection().getSegmentsInternal(),
						range.getUpper().getSection().getSegmentsInternal(),
						networkSegIndex,
						hostSegIndex,
						null);
				},
				(lowest, highest, range) -> range.iterator(),
				IPv6AddressSeqRange::getCount,
				range -> range.getCount().compareTo(LONG_MAX) <= 0,
				range -> range.getCount().longValue());
	}

	@Override
	public Stream<IPv6Address> stream() {
		return StreamSupport.stream(spliterator(), false);
	}

	@Override
	public IPv6Address coverWithPrefixBlock() {
		return getLower().coverWithPrefixBlock(getUpper());
	}

	@Override
	public IPv6Address[] spanWithPrefixBlocks() {
		return getLower().spanWithPrefixBlocks(getUpper());
	}

	@Override
	public IPv6Address[] spanWithSequentialBlocks() {
		return getLower().spanWithSequentialBlocks(getUpper());
	}

	@Override
	protected IPv6AddressSeqRange create(IPAddress lower, IPAddress upper) {
		return new IPv6AddressSeqRange(lower, upper);
	}

	/* (non-Javadoc)
	 * @see inet.ipaddr.IPAddressRange#createPair(inet.ipaddr.IPAddress, inet.ipaddr.IPAddress, inet.ipaddr.IPAddress, inet.ipaddr.IPAddress)
	 */
	@Override
	protected IPv6AddressSeqRange[] createPair(IPAddress lower1, IPAddress upper1,
			IPAddress lower2, IPAddress upper2) {
		return new IPv6AddressSeqRange[] { create(lower1, upper1), create(lower2, upper2) };
	}

	/* (non-Javadoc)
	 * @see inet.ipaddr.IPAddressRange#createSingle(inet.ipaddr.IPAddress, inet.ipaddr.IPAddress)
	 */
	@Override
	protected IPv6AddressSeqRange[] createSingle(IPAddress lower, IPAddress upper) {
		return new IPv6AddressSeqRange[] { create(lower, upper) };
	}
	
	@Override
	protected IPv6AddressSeqRange[] createSingle() {
		return new IPv6AddressSeqRange[] { this };
	}
	
	@Override
	protected IPv6AddressSeqRange[] createEmpty() {
		return EMPTY;
	}

	/* (non-Javadoc)
	 * @see inet.ipaddr.IPAddressRange#prefixBlockIterator(int)
	 */
	@Override
	public Iterator<IPv6Address> prefixBlockIterator(int prefLength) {
		if(prefLength < 0) {
			throw new PrefixLenException(prefLength);
		}
		IPv6Address lower = getLower();
		IPv6Address upper = getUpper();
		AddressCreator<IPv6Address, ?, ?, IPv6AddressSegment> creator = getAddressCreator();
		int bitsPerSegment = lower.getBitsPerSegment();
		int bytesPerSegment = lower.getBytesPerSegment();
		int segCount = lower.getSegmentCount();
		Integer prefLengths[] = new Integer[segCount];
		int shifts[] = new int[segCount];
		int networkSegIndex = 0;
		if(prefLength > 0) {
			networkSegIndex = getNetworkSegmentIndex(prefLength, bytesPerSegment, bitsPerSegment);
		}
		for(int i = networkSegIndex; i < segCount; i++) {
			Integer segPrefLength = ParsedAddressGrouping.getPrefixedSegmentPrefixLength(bitsPerSegment, prefLength, i);
			prefLengths[i] = segPrefLength;
			shifts[i] = bitsPerSegment - segPrefLength;
		}
		int hostSegIndex = getHostSegmentIndex(prefLength, bytesPerSegment, bitsPerSegment);
		return iterator(
				lower,
				upper,
				creator,
				IPv6Address::getSegment,
				(seg, segIndex) -> seg.iterator(),
				(addr1, addr2, index) -> {
					Integer segPrefLength = prefLengths[index];
					if(segPrefLength == null) {
						return addr1.getSegment(index).getSegmentValue() == addr2.getSegment(index).getSegmentValue();
					}
					int shift = shifts[index];
					return addr1.getSegment(index).getSegmentValue() >>> shift == addr2.getSegment(index).getSegmentValue() >>> shift;
				},
				networkSegIndex,
				hostSegIndex,
				(seg, index) -> {
					Integer segPrefLength = prefLengths[index];
					if(segPrefLength == null) {
						return seg.iterator();
					}
					return seg.prefixBlockIterator(segPrefLength);
				});
	}

	@Override
	public AddressComponentRangeSpliterator<IPv6AddressSeqRange, IPv6Address> prefixBlockSpliterator(int prefLength) {
		if(prefLength < 0) {
			throw new PrefixLenException(prefLength);
		}
		IPv6Address lower = getLower();
		int bitsPerSegment = lower.getBitsPerSegment();
		int bytesPerSegment = lower.getBytesPerSegment();
		IPv6AddressCreator creator = getAddressCreator();
		Integer prefixLength = IPv6AddressSection.cacheBits(prefLength);
		int networkSegIndex = getNetworkSegmentIndex(prefLength, bytesPerSegment, bitsPerSegment);
		int hostSegIndex = getHostSegmentIndex(prefLength, bytesPerSegment, bitsPerSegment);
		return createSpliterator(
				this,
				spliterator -> {
					IPv6AddressSeqRange range = spliterator.getAddressItem();
					return split(
						spliterator,
						(segsLower, segsUpper) -> new IPv6AddressSeqRange(
								creator.createAddressInternal(segsLower),
								creator.createAddressInternal(segsUpper)),
						creator,
						range.getLower().getSection().getSegmentsInternal(),
						range.getUpper().getSection().getSegmentsInternal(),
						networkSegIndex,
						hostSegIndex,
						prefixLength);
				},
				(isLowest, isHighest, range) -> range.prefixBlockIterator(prefLength),
				range -> range.getPrefixCount(prefLength),
				range -> range.getPrefixCount(prefLength).compareTo(LONG_MAX) <= 0,
				range -> range.getPrefixCount(prefLength).longValue());	
	}

	@Override
	public Stream<IPv6Address> prefixBlockStream(int prefLength) {
		return StreamSupport.stream(prefixBlockSpliterator(prefLength), false);
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv6AddressSeqRange> prefixIterator(int prefixLength) {
		return (Iterator<IPv6AddressSeqRange>) super.prefixIterator(prefixLength);
	}

	@Override
	public AddressComponentSpliterator<IPv6AddressSeqRange> prefixSpliterator(int prefLength) {
		if(prefLength < 0) {
			throw new PrefixLenException(prefLength);
		}
		IPv6Address lower = getLower();
		int bitsPerSegment = lower.getBitsPerSegment();
		int bytesPerSegment = lower.getBytesPerSegment();
		IPv6AddressCreator creator = getAddressCreator();
		Integer prefixLength = IPv6AddressSection.cacheBits(prefLength);
		int networkSegIndex = getNetworkSegmentIndex(prefLength, bytesPerSegment, bitsPerSegment);
		int hostSegIndex = getHostSegmentIndex(prefLength, bytesPerSegment, bitsPerSegment);
		return createPrefixSpliterator(
				this,
				spliterator -> {
					IPv6AddressSeqRange range = spliterator.getAddressItem();
					return split(
						spliterator,
						(segsLower, segsUpper) -> new IPv6AddressSeqRange(
								creator.createAddressInternal(segsLower),
								creator.createAddressInternal(segsUpper)),
						creator,
						range.getLower().getSection().getSegmentsInternal(),
						range.getUpper().getSection().getSegmentsInternal(),
						networkSegIndex,
						hostSegIndex,
						prefixLength);
				},
				(isLowest, isHighest, range) -> (isLowest || isHighest) ? range.prefixIterator(prefLength) : rangedIterator(range.prefixBlockIterator(prefLength)),
				range -> range.getPrefixCount(prefLength),
				range -> range.getPrefixCount(prefLength).compareTo(LONG_MAX) <= 0,
				range -> range.getPrefixCount(prefLength).longValue());	
	}

	@Override
	public Stream<IPv6AddressSeqRange> prefixStream(int prefLength) {
		return StreamSupport.stream(prefixSpliterator(prefLength), false);
	}
	
	public String toIPv6String(Function<IPv6Address, String> lowerStringer, String separator, Function<IPv6Address, String> upperStringer) {
		return lowerStringer.apply(getLower()) + separator + upperStringer.apply(getUpper());
	}
	
	@Override
	public IPv6AddressSeqRange intersect(IPAddressSeqRange other) {
		return (IPv6AddressSeqRange) super.intersect(other);
	}
	
	@Override
	public IPv6AddressSeqRange join(IPAddressSeqRange other) {
		return (IPv6AddressSeqRange) super.join(other);
	}
	
	@Override
	public IPv6AddressSeqRange[] subtract(IPAddressSeqRange other) {
		return (IPv6AddressSeqRange[]) super.subtract(other);
	}

	@Override
	public IPv6AddressSeqRange toSequentialRange() {
		return this;
	}
}
