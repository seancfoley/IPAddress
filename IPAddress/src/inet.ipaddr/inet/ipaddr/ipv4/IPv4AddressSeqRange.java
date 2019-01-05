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
package inet.ipaddr.ipv4;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.function.Function;

import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressSeqRange;
import inet.ipaddr.NetworkMismatchException;
import inet.ipaddr.PrefixLenException;
import inet.ipaddr.format.standard.AddressCreator;
import inet.ipaddr.format.validate.ParsedAddressGrouping;
import inet.ipaddr.ipv4.IPv4AddressNetwork.IPv4AddressCreator;

/**
 * @custom.core
 * @author sfoley
 *
 */
public class IPv4AddressSeqRange extends IPAddressSeqRange implements Iterable<IPv4Address> {
	
	private static final long serialVersionUID = 1L;

	private static final IPv4AddressSeqRange EMPTY[] = {};
				
	public IPv4AddressSeqRange(IPv4Address first, IPv4Address second) {
		super(
			first,
			second,
			IPv4Address::getLower,
			IPv4Address::getUpper,
			IPv4Address::withoutPrefixLength);
		if(!first.getNetwork().equals(second.getNetwork())) {
			throw new NetworkMismatchException(first, second);
		}
	}
	
	private IPv4AddressSeqRange(IPAddress first, IPAddress second) {
		super(first, second);
	}
	
	@Override
	public IPv4Address getLower() {
		return (IPv4Address) super.getLower();
	}
	
	@Override
	public IPv4Address getUpper() {
		return (IPv4Address) super.getUpper();
	}
	
	private IPv4AddressCreator getAddressCreator() {
		return getLower().getNetwork().getAddressCreator();
	}
	
	/**
	 * Equivalent to {@link #getCount()} but returns a long
	 * 
	 * @return
	 */
	public long getIPv4Count() {
		return getUpper().longValue() - getLower().longValue() + 1;
	}
	
	/**
	 * Equivalent to {@link #getPrefixCount(int)} but returns a long
	 * 
	 * @return
	 */
	public long getIPv4PrefixCount(int prefixLength) {
		if(prefixLength < 0) {
			throw new PrefixLenException(this, prefixLength);
		}
		int bitCount = getBitCount();
		if(bitCount <= prefixLength) {
			return getIPv4Count();
		}
		int shiftAdjustment = bitCount - prefixLength;
		long upperAdjusted = getUpper().longValue() >>> shiftAdjustment;
		long lowerAdjusted = getLower().longValue() >>> shiftAdjustment;
		return upperAdjusted - lowerAdjusted + 1;
	}
	
	@Override
	protected BigInteger getCountImpl() {
		return BigInteger.valueOf(getIPv4Count());
	}
	
	@Override
	public BigInteger getPrefixCount(int prefixLength) {
		return BigInteger.valueOf(getIPv4PrefixCount(prefixLength));
	}
	
	@Override
	public Iterable<IPv4Address> getIterable() {
		return this;
	}

	@Override
	public Iterator<IPv4Address> iterator() {
		IPv4Address lower = getLower();
		IPv4Address upper = getUpper();
		AddressCreator<IPv4Address, ?, ?, IPv4AddressSegment> creator = getAddressCreator();
		if(!isMultiple()) {
			return iterator(lower, creator);
		}
		int divCount = lower.getSegmentCount();
		return iterator(
				lower,
				upper,
				creator,
				IPv4Address::getSegment,
				(seg, segIndex) -> seg.iterator(),
				(addr1, addr2, index) -> addr1.getSegment(index).getSegmentValue() == addr2.getSegment(index).getSegmentValue(),
				divCount - 1,
				divCount,
				null);
	}
	
	@Override
	public Iterator<IPv4Address> prefixBlockIterator(int prefLength) {
		if(prefLength < 0) {
			throw new PrefixLenException(prefLength);
		}
		IPv4Address lower = getLower();
		IPv4Address upper = getUpper();
		AddressCreator<IPv4Address, ?, ?, IPv4AddressSegment> creator = getAddressCreator();
		return iterator(
				lower,
				upper,
				creator,
				IPv4Address::getSegment,
				(seg, segIndex) -> seg.iterator(),
				(addr1, addr2, index) -> {
					Integer segPrefLength = ParsedAddressGrouping.getPrefixedSegmentPrefixLength(IPv4Address.BITS_PER_SEGMENT, prefLength, index);
					if(segPrefLength == null) {
						return addr1.getSegment(index).getSegmentValue() == addr2.getSegment(index).getSegmentValue();
					}
					int shift = IPv4Address.BITS_PER_SEGMENT - segPrefLength;
					return addr1.getSegment(index).getSegmentValue() >>> shift == addr2.getSegment(index).getSegmentValue() >>> shift;
				},
				getNetworkSegmentIndex(prefLength, IPv4Address.BYTES_PER_SEGMENT, IPv4Address.BITS_PER_SEGMENT),
				getHostSegmentIndex(prefLength, IPv4Address.BYTES_PER_SEGMENT, IPv4Address.BITS_PER_SEGMENT),
				(seg, index) -> {
					Integer segPrefLength = ParsedAddressGrouping.getPrefixedSegmentPrefixLength(IPv4Address.BITS_PER_SEGMENT, prefLength, index);
					if(segPrefLength == null) {
						return seg.iterator();
					}
					return seg.prefixBlockIterator(segPrefLength);
				});
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv4AddressSeqRange> prefixIterator(int prefixLength) {
		return (Iterator<IPv4AddressSeqRange>) super.prefixIterator(prefixLength);
	}

	@Override
	public IPv4Address[] spanWithPrefixBlocks() {
		return getLower().spanWithPrefixBlocks(getUpper());
	}

	@Override
	public IPv4Address[] spanWithSequentialBlocks() {
		return getLower().spanWithSequentialBlocks(getUpper());
	}
	
	@Override
	public int getMinPrefixLengthForBlock() {
		int result = getBitCount();
		int lowerZeros = Integer.numberOfTrailingZeros(getLower().intValue());
		if(lowerZeros != 0) {
			int upperOnes = Integer.numberOfTrailingZeros(~getUpper().intValue());
			if(upperOnes != 0) {
				int prefixedBitCount = Math.min(lowerZeros, upperOnes);
				result -= prefixedBitCount;
			}
		}
		return result;
	}
	
	@Override
	public Integer getPrefixLengthForSingleBlock() {
		int divPrefix = getMinPrefixLengthForBlock();
		int lowerValue = getLower().intValue();
		int upperValue = getUpper().intValue();
		int bitCount = getBitCount();
		if(divPrefix == bitCount) {
			if(lowerValue == upperValue) {
				return IPv4AddressSection.cacheBits(divPrefix);
			}
		} else {
			int shift = bitCount - divPrefix;
			if(lowerValue >>> shift == upperValue >>> shift) {
				return IPv4AddressSection.cacheBits(divPrefix);
			}
		}
		return null;
	}

	@Override
	protected IPv4AddressSeqRange create(IPAddress lower, IPAddress upper) {
		return new IPv4AddressSeqRange(lower, upper);
	}

	/* (non-Javadoc)
	 * @see inet.ipaddr.IPAddressRange#createPair(inet.ipaddr.IPAddress, inet.ipaddr.IPAddress, inet.ipaddr.IPAddress, inet.ipaddr.IPAddress)
	 */
	@Override
	protected IPv4AddressSeqRange[] createPair(IPAddress lower1, IPAddress upper1,
			IPAddress lower2, IPAddress upper2) {
		return new IPv4AddressSeqRange[] {create(lower1, upper1), create(lower2, upper2)};
	}

	/* (non-Javadoc)
	 * @see inet.ipaddr.IPAddressRange#createSingle(inet.ipaddr.IPAddress, inet.ipaddr.IPAddress)
	 */
	@Override
	protected IPv4AddressSeqRange[] createSingle(IPAddress lower, IPAddress upper) {
		return new IPv4AddressSeqRange[] {
			create(lower, upper)
		};
	}
	
	@Override
	protected IPv4AddressSeqRange[] createSingle() {
		return new IPv4AddressSeqRange[] { this };
	}
	
	@Override
	protected IPv4AddressSeqRange[] createEmpty() {
		return EMPTY;
	}
	
	public String toIPv4String(Function<IPv4Address, String> lowerStringer, String separator, Function<IPv4Address, String> upperStringer) {
		return lowerStringer.apply(getLower()) + separator + upperStringer.apply(getUpper());
	}
	
	@Override
	public IPv4AddressSeqRange intersect(IPAddressSeqRange other) {
		return (IPv4AddressSeqRange) super.intersect(other);
	}
	
	@Override
	public IPv4AddressSeqRange join(IPAddressSeqRange other) {
		return (IPv4AddressSeqRange) super.join(other);
	}
	
	@Override
	public IPv4AddressSeqRange[] subtract(IPAddressSeqRange other) {
		return (IPv4AddressSeqRange[]) super.subtract(other);
	}
}
