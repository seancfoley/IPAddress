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
import inet.ipaddr.IPAddressRange;
import inet.ipaddr.NetworkMismatchException;
import inet.ipaddr.format.standard.AddressCreator;
import inet.ipaddr.format.validate.ParsedAddressGrouping;
import inet.ipaddr.ipv6.IPv6AddressNetwork.IPv6AddressCreator;

/**
 * @author sfoley
 *
 */
public class IPv6AddressRange extends IPAddressRange implements Iterable<IPv6Address> {
	
	private static final long serialVersionUID = 1L;

	private static final IPv6AddressRange EMPTY[] = {};
	
	protected IPv6AddressRange(IPv6Address first, IPv6Address second) {
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
	
	@Override
	public IPv6Address getLower() {
		return (IPv6Address) lower;
	}
	
	@Override
	public IPv6Address getUpper() {
		return (IPv6Address) upper;
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
		return getLower().spanWithPrefixBlocks(upper);
	}

	@Override
	public IPv6Address[] spanWithRanges() {
		return getLower().spanWithRangedSegments(upper);
	}

	@Override
	protected IPv6AddressRange create(IPAddress lower, IPAddress upper) {
		return new IPv6AddressRange((IPv6Address) lower, (IPv6Address) upper);
	}

	/* (non-Javadoc)
	 * @see inet.ipaddr.IPAddressRange#createPair(inet.ipaddr.IPAddress, inet.ipaddr.IPAddress, inet.ipaddr.IPAddress, inet.ipaddr.IPAddress)
	 */
	@Override
	protected IPv6AddressRange[] createPair(IPAddress lower1, IPAddress upper1,
			IPAddress lower2, IPAddress upper2) {
		return new IPv6AddressRange[] { create(lower1, upper1), create(lower2, upper2) };
	}

	/* (non-Javadoc)
	 * @see inet.ipaddr.IPAddressRange#createSingle(inet.ipaddr.IPAddress, inet.ipaddr.IPAddress)
	 */
	@Override
	protected IPv6AddressRange[] createSingle(IPAddress lower, IPAddress upper) {
		return new IPv6AddressRange[] { create(lower, upper) };
	}
	
	@Override
	protected IPv6AddressRange[] createSingle() {
		return new IPv6AddressRange[] { this };
	}
	
	@Override
	protected IPv6AddressRange[] createEmpty() {
		return EMPTY;
	}

	/* (non-Javadoc)
	 * @see inet.ipaddr.IPAddressRange#prefixBlockIterator(int)
	 */
	@Override
	public Iterator<? extends IPAddress> prefixBlockIterator(int prefLength) {
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
	
	public String toIPv6String(Function<IPv6Address, String> lowerStringer, String separator, Function<IPv6Address, String> upperStringer) {
		return lowerStringer.apply(getLower()) + separator + upperStringer.apply(getUpper());
	}
	
	@Override
	public IPv6AddressRange intersect(IPAddressRange other) {
		return (IPv6AddressRange) super.intersect(other);
	}
	
	@Override
	public IPv6AddressRange join(IPAddressRange other) {
		return (IPv6AddressRange) super.join(other);
	}
	
	@Override
	public IPv6AddressRange[] subtract(IPAddressRange other) {
		return (IPv6AddressRange[]) super.subtract(other);
	}
}
