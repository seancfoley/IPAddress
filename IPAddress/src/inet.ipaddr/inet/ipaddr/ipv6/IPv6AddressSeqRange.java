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
package inet.ipaddr.ipv6;

import java.util.Iterator;
import java.util.function.Function;

import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressSeqRange;
import inet.ipaddr.NetworkMismatchException;
import inet.ipaddr.PrefixLenException;
import inet.ipaddr.format.standard.AddressCreator;
import inet.ipaddr.format.validate.ParsedAddressGrouping;
import inet.ipaddr.ipv6.IPv6AddressNetwork.IPv6AddressCreator;

/**
 * @custom.core
 * @author sfoley
 *
 */
public class IPv6AddressSeqRange extends IPAddressSeqRange implements Iterable<IPv6Address> {
	
	private static final long serialVersionUID = 1L;

	private static final IPv6AddressSeqRange EMPTY[] = {};
	
	public IPv6AddressSeqRange(IPv6Address first, IPv6Address second) {
		super(
			first,
			second,
			IPv6Address::getLower,
			IPv6Address::getUpper,
			a -> a.withoutPrefixLength().removeZone());
		if(!first.getNetwork().equals(second.getNetwork())) {
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
	public Iterator<? extends IPAddress> prefixBlockIterator(int prefLength) {
		if(prefLength < 0) {
			throw new PrefixLenException(prefLength);
		}
		IPv6Address lower = getLower();
		IPv6Address upper = getUpper();
		AddressCreator<IPv6Address, ?, ?, IPv6AddressSegment> creator = getAddressCreator();
		return iterator(
				lower,
				upper,
				creator,
				IPv6Address::getSegment,
				(seg, segIndex) -> seg.iterator(),
				(addr1, addr2, index) -> {
					Integer segPrefLength = ParsedAddressGrouping.getPrefixedSegmentPrefixLength(IPv6Address.BITS_PER_SEGMENT, prefLength, index);
					if(segPrefLength == null) {
						return addr1.getSegment(index).getSegmentValue() == addr2.getSegment(index).getSegmentValue();
					}
					int shift = IPv6Address.BITS_PER_SEGMENT - segPrefLength;
					return addr1.getSegment(index).getSegmentValue() >>> shift == addr2.getSegment(index).getSegmentValue() >>> shift;
				},
				getNetworkSegmentIndex(prefLength, IPv6Address.BYTES_PER_SEGMENT, IPv6Address.BITS_PER_SEGMENT),
				getHostSegmentIndex(prefLength, IPv6Address.BYTES_PER_SEGMENT, IPv6Address.BITS_PER_SEGMENT),
				(seg, index) -> {
					Integer segPrefLength = ParsedAddressGrouping.getPrefixedSegmentPrefixLength(IPv6Address.BITS_PER_SEGMENT, prefLength, index);
					if(segPrefLength == null) {
						return seg.iterator();
					}
					return seg.prefixBlockIterator(segPrefLength);
				});
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv6AddressSeqRange> prefixIterator(int prefixLength) {
		return (Iterator<IPv6AddressSeqRange>) super.prefixIterator(prefixLength);
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
}
