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
package inet.ipaddr;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.function.Function;
import java.util.function.IntFunction;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;

import inet.ipaddr.IPAddressSection.SegFunction;
import inet.ipaddr.format.AddressItem;
import inet.ipaddr.format.AddressItemRange;
import inet.ipaddr.format.large.IPAddressLargeDivisionGrouping;
import inet.ipaddr.format.standard.AddressCreator;
import inet.ipaddr.format.validate.ParsedAddressGrouping;

/**
 * This class can be used to represent an arbitrary range of IP addresses.  Note that the IPAddress and IPAddressString classes
 * can be used to represents address prefix subnets (eg 1.2.0.0/16 or 1:2:3:4::/64) or range subnets (1.2.0-255.* or 1:2:3:4:*), see
 * {@link IPAddressString} for details.  Range subnets allow you to specify a range of values within each segment.
 * <p>
 * IPAddress and IPAddressString cover all potential subnets and addresses that can be represented by a string or set of value ranges consisting of
 * 4 or less segments for IPv4, and 8 or less segments for IPv6.
 * <p>
 * This the allows the representation of any address range that is entirely sequential.
 * <p>
 * In many cases an arbitrary range cannot be represented by IPAddress or IPAddressString, due to their segmented nature.
 * In all cases you can represent any address with a single segment included with a single instance of {@link IPAddressLargeDivisionGrouping}.
 * However, {@link IPAddressLargeDivisionGrouping}, because it allows arbitrary division bit-lengths, cannot does not offer all the same operations offered with segments of equal bit-length.
 * Additionally, once represented as a single division, many of the multi-segment-based operations are not available.
 * <p>
 * String representations include the full address for both the lower and upper bounds of the range.
 *  
 * 
 * @author sfoley
 *
 */
public abstract class IPAddressRange implements AddressItem, AddressItemRange, Serializable {
	
	private static final long serialVersionUID = 1L;
	
	protected final IPAddress lower, upper;
	
	private transient BigInteger count;
	private transient int hashCode;

	protected <T extends IPAddress> IPAddressRange(
			T first, 
			T other,
			UnaryOperator<T> getLower,
			UnaryOperator<T> getUpper,
			UnaryOperator<T> prefixLenRemover) {
		boolean f;
		if((f = first.contains(other)) || other.contains(first)) {
			T addr = f ? prefixLenRemover.apply(first):  prefixLenRemover.apply(other);
			lower = getLower.apply(addr);
			upper = getUpper.apply(addr);
		} else {
			T firstLower = getLower.apply(first);
			T otherLower = getLower.apply(other);
			T firstUpper = getUpper.apply(first);
			T otherUpper = getUpper.apply(other);
			T lower = compare(firstLower, otherLower) > 0 ? otherLower : firstLower;
			T upper = compare(firstUpper, otherUpper) < 0 ? otherUpper : firstUpper;
			this.lower = prefixLenRemover.apply(lower);
			this.upper = prefixLenRemover.apply(upper);
		}
	}
	
	/**
	 * compares values
	 * @return
	 */
	private static int compare(IPAddress one, IPAddress two) {
		return Address.ADDRESS_LOW_VALUE_COMPARATOR.compare(one, two);
	}
	
	@Override
	public BigInteger getCount() {
		BigInteger result = count;
		if(result == null) {
			result = getCountImpl();
		}
		return result;
	}
	
	/**
	 * 
	 * @param other the range to compare, which does not need to range across the same address space
	 * @return whether this range spans more addresses than the provided range.
	 */
	public boolean isMore(IPAddressRange other) {
		return getCount().compareTo(other.getCount()) > 0;
	}
	
	protected BigInteger getCountImpl() {
		return AddressItem.super.getCount();
	}
	
	@Override
	public abstract Iterable<? extends IPAddress> getIterable();
	
	protected static int getNetworkSegmentIndex(int networkPrefixLength, int bytesPerSegment, int bitsPerSegment) {
		return ParsedAddressGrouping.getNetworkSegmentIndex(networkPrefixLength, bytesPerSegment, bitsPerSegment);
	}
	
	protected static int getHostSegmentIndex(int networkPrefixLength, int bytesPerSegment, int bitsPerSegment) {
		return ParsedAddressGrouping.getHostSegmentIndex(networkPrefixLength, bytesPerSegment, bitsPerSegment);
	}
	
	public abstract Iterator<? extends IPAddress> prefixBlockIterator(int prefLength);
	
	@FunctionalInterface
	protected interface SegValueComparator<T> {
	    boolean apply(T segmentSeries1, T segmentSeries2, int index);
	}
	
	@Override
	public abstract Iterator<? extends IPAddress> iterator();
	
	protected static <T extends Address, S extends AddressSegment> Iterator<T> iterator(T original, AddressCreator<T, ?, ?, S> creator) {
		return IPAddressSection.iterator(original, creator, null);
	}
	
	/*
	 This iterator is (not surprisingly) 2 to 3 times faster (based on measurements I've done) than an iterator that uses the increment method like:
	 
	 return iterator(a -> a.increment(1));
	 
	 protected Iterator<T> iterator(UnaryOperator<T> incrementor) {
	 	return new Iterator<T>() {
			BigInteger count = getCount();
			T current = lower;
					
			@Override
			public boolean hasNext() {
				return !count.equals(BigInteger.ZERO);
			}

			@Override
			public T next() {
				if(hasNext()) {
					T result = current;
					current = incrementor.apply(current);
					count = count.subtract(BigInteger.ONE);
					return result;
				}
				throw new NoSuchElementException();
			}
		};
	 }
	 */
	protected static <T extends IPAddress, S extends IPAddressSegment> Iterator<T> iterator(
			T lower,
			T upper,
			AddressCreator<T, ?, ?, S> creator,
			SegFunction<T, S> segProducer,
			SegFunction<S, Iterator<S>> segmentIteratorProducer,
			SegValueComparator<T> segValueComparator,
			int networkSegmentIndex,
			int hostSegmentIndex,
			SegFunction<S, Iterator<S>> prefixedSegIteratorProducer) {
		int divCount = lower.getDivisionCount();
		
		// at any given point in time, this list provides an iterator for the segment at each index
		ArrayList<Supplier<Iterator<S>>> segIteratorProducerList = new ArrayList<Supplier<Iterator<S>>>(divCount);
		
		// at any given point in time, finalValue[i] is true if and only if we have reached the very last value for segment i - 1
		// when that happens, the next iterator for the segment at index i will be the last
		boolean finalValue[] = new boolean[divCount + 1];
		
		// here is how the segment iterators will work:
		// the low and high values at each segment are low, high
		// the maximum possible valoues for any segment are min, max
		// we first find the first k >= 0 such that low != high for the segment at index k
		
		//	the initial set of iterators at each index are as follows:
		//    for i < k finalValue[i] is set to true right away.
		//		we create an iterator from seg = new Seg(low)
		//    for i == k we create a wrapped iterator from Seg(low, high), wrapper will set finalValue[i] once we reach the final value of the iterator
		//    for i > k we create an iterator from Seg(low, max)
		// 
		// after the initial iterator has been supplied, any further iterator supplied for the same segment is as follows:
		//    for i <= k, there was only one iterator, there will be no further iterator
		//    for i > k,
		//	  	if i == 0 or of if flagged[i - 1] is true, we create a wrapped iterator from Seg(low, high), wrapper will set finalValue[i] once we reach the final value of the iterator
		//      otherwise we create an iterator from Seg(min, max)
		//
		// By following these rules, we iterator through all possible addresses	
		boolean notDiffering = true;
		finalValue[0] = true;
		S allSegShared = null;
		for(int i = 0; i < divCount; i++) {
			SegFunction<S, Iterator<S>> segIteratorProducer;
			if(prefixedSegIteratorProducer != null && i >= networkSegmentIndex) {
				segIteratorProducer = prefixedSegIteratorProducer;
			} else {
				segIteratorProducer = segmentIteratorProducer;
			}
			S lowerSeg = segProducer.apply(lower, i);
			int indexi = i;
			if(notDiffering) {
				notDiffering = segValueComparator.apply(lower, upper, i);
				if(notDiffering) {
					// there is only one iterator and it produces only one value
					finalValue[i + 1] = true;
					Iterator<S> iterator = segIteratorProducer.apply(lowerSeg, i);
					segIteratorProducerList.add(() -> iterator);
				} else {
					// in the first differing segment the only iterator will go from segment value of lower address to segment value of upper address
					Iterator<S> iterator = segIteratorProducer.apply(
							creator.createSegment(lowerSeg.getSegmentValue(), upper.getSegment(i).getSegmentValue(), null), i);
					
					// the wrapper iterator detects when the iterator has reached its final value
					Iterator<S> wrappedFinalIterator = new Iterator<S>() {
						@Override
						public boolean hasNext() {
							return iterator.hasNext();
						}

						@Override
						public S next() {
							S next = iterator.next();
							if(!iterator.hasNext()) {
								finalValue[indexi + 1] = true;
							}
							return next;
						}
					};
					segIteratorProducerList.add(() -> wrappedFinalIterator);
				}
			} else {
				// in the second and all following differing segments, rather than go from segment value of lower address to segment value of upper address
				// we go from segment value of lower address to the max seg value the first time through
				// then we go from the min value of the seg to the max seg value each time until the final time,
				// the final time we go from the min value to the segment value of upper address
				// we know it is the final time through when the previous iterator has reached its final value, which we track
				
				// the first iterator goes from the segment value of lower address to the max value of the segment
				Iterator<S> firstIterator = segIteratorProducer.apply(creator.createSegment(lowerSeg.getSegmentValue(), lower.getMaxSegmentValue(), null), i);
				
				// the final iterator goes from 0 to the segment value of our upper address
				Iterator<S> finalIterator = segIteratorProducer.apply(creator.createSegment(0, upper.getSegment(i).getSegmentValue(), null), i);
				
				// the wrapper iterator detects when the final iterator has reached its final value
				Iterator<S> wrappedFinalIterator = new Iterator<S>() {
					@Override
					public boolean hasNext() {
						return finalIterator.hasNext();
					}

					@Override
					public S next() {
						S next = finalIterator.next();
						if(!finalIterator.hasNext()) {
							finalValue[indexi + 1] = true;
						}
						return next;
					}
				};
				if(allSegShared == null) {
					allSegShared = creator.createSegment(0, lower.getMaxSegmentValue(), null);
				}
				// all iterators after the first iterator and before the final iterator go from 0 the max segment value,
				// and there will be many such iterators
				S allSeg = allSegShared;
				Supplier<Iterator<S>> finalIteratorProducer = () -> finalValue[indexi] ?  wrappedFinalIterator : segIteratorProducer.apply(allSeg, indexi);
				segIteratorProducerList.add(() -> {
					//the first time through, we replace the iterator producer so the first iterator used only once
					segIteratorProducerList.set(indexi, finalIteratorProducer);
					return firstIterator;
				});
			}
		}
		IntFunction<Iterator<S>> iteratorProducer = iteratorIndex -> segIteratorProducerList.get(iteratorIndex).get();
		return IPAddressSection.iterator(null, creator,
				IPAddressSection.iterator(
						lower.getSegmentCount(),
						creator,
						iteratorProducer, 
						networkSegmentIndex,
						hostSegmentIndex,
						iteratorProducer)
			);
	}
	
	@Override
	public IPAddress getLower() {
		return lower;
	}
	
	@Override
	public IPAddress getUpper() {
		return upper;
	}
	
	public String toCanonicalString(String separator) {
		return toString(IPAddress::toCanonicalString, separator, IPAddress::toCanonicalString);
	}
	
	public String toNormalizedString(String separator) {
		return toString(IPAddress::toNormalizedString, separator, IPAddress::toNormalizedString);
	}
	
	public String toString(Function<IPAddress, String> lowerStringer, String separator, Function<IPAddress, String> upperStringer) {
		return lowerStringer.apply(lower) + separator + upperStringer.apply(upper);
	}
	
	@Override
	public String toString() {
		return toCanonicalString(" to ");
	}
	
	public abstract IPAddress[] spanWithPrefixBlocks();

	public abstract IPAddress[] spanWithRanges();
	
	/**
	 * Joins the given ranges into the fewest number of ranges.
	 * If no joining can take place, the original array is returned.
	 * 
	 * @param ranges
	 * @return
	 */
	public static IPAddressRange[] join(IPAddressRange... ranges) {
		int joinedCount = 0;
		Arrays.sort(ranges, Address.ADDRESS_LOW_VALUE_COMPARATOR);
		for(int i = 0; i < ranges.length; i++) {
			IPAddressRange range = ranges[i];
			if(range == null) {
				continue;
			}
			for(int j = i + 1; j < ranges.length; j++) {
				IPAddressRange range2 = ranges[j];
				if(range2 == null) {
					continue;
				}
				IPAddress upper = range.upper;
				IPAddress lower = range2.lower;
				if(compare(upper, lower) >= 0
						|| upper.increment(1).equals(lower)) {
					//join them
					ranges[i] = range = range.create(range.lower, range2.upper);
					ranges[j] = null;
					joinedCount++;
				} else break;
			}
		}
		if(joinedCount == 0) {
			return ranges;
		}
		IPAddressRange joined[] = new IPAddressRange[ranges.length - joinedCount];
		for(int i = 0, j = 0; i < ranges.length; i++) {
			IPAddressRange range = ranges[i];
			if(range == null) {
				continue;
			}
			joined[j++] = range;
			if(j >= joined.length) {
				break;
			}
		}
		return joined;
	}
	
	public boolean overlaps(IPAddressRange other) {
		return compare(other.lower, upper) <= 0 && compare(other.upper, lower) >= 0;
	}
	
	public boolean contains(IPAddressRange other) {
		return compare(other.lower, lower) >= 0 && compare(other.upper, upper) <= 0;
	}
	
	@Override
	public int hashCode() {
		int res = hashCode;
		if(res == 0) {
			res = 31 * lower.hashCode() + upper.hashCode();
			hashCode = res;
		}
		return res;
	}
	
	@Override
	public boolean equals(Object o) {
		if(o instanceof IPAddressRange) {
			IPAddressRange otherRange = (IPAddressRange) o;
				return lower.equals(otherRange.lower) && upper.equals(otherRange.upper);
			}
			return false;
	}
	
	/**
	 * Returns the intersection of this range with the given range, a range which includes those addresses in both this and the given rqnge.
	 * @param other
	 * @return
	 */
	public IPAddressRange intersect(IPAddressRange other) {
		IPAddress otherLower = other.lower;
		IPAddress otherUpper = other.upper;
		IPAddress lower = this.lower;
		IPAddress upper = this.upper;
		if(compare(lower, otherLower) <= 0) {
			if(compare(upper, otherUpper) >= 0) {
				return other;
			} else if(compare(upper, otherLower) < 0) {
				return null;
			}
			return create(otherLower, upper);
		} else if(compare(otherUpper, upper) >= 0) {
			return this;
		} else if(compare(otherUpper, lower) < 0) {
			return null;
		}
		return create(lower, otherUpper);
	}
	
	/**
	 * If this range overlaps with the given range,
	 * or if the highest value of the lower range is one below the lowest value of the higher range,
	 * then the two are joined into a new larger range that is returned.
	 * <p>
	 * Otherwise null is returned.
	 * 
	 * @param other
	 * @return
	 */
	public IPAddressRange join(IPAddressRange other) {
		IPAddress otherLower = other.lower;
		IPAddress otherUpper = other.upper;
		IPAddress lower = this.lower;
		IPAddress upper = this.upper;
		int lowerComp = compare(lower, otherLower);
		if(!overlaps(other)) {
			if(lowerComp >= 0) {
				if(otherUpper.increment(1).equals(lower)) {
					return create(otherLower, upper);
				}
			} else {
				if(upper.increment(1).equals(otherLower)) {
					return create(lower, otherUpper);
				}
			}
			return null;
		}
		int upperComp = compare(upper, otherUpper);
		IPAddress lowestLower, highestUpper;
		if(lowerComp >= 0) {
			if(lowerComp == 0 && upperComp == 0) {
				return this;
			}
			lowestLower = otherLower;
		} else {
			lowestLower = lower;
		}
		highestUpper = upperComp >= 0 ? upper : otherUpper;
		return create(lowestLower, highestUpper);
	}
	
	/**
	 * Subtracts the given range from this range, to produce either zero, one, or two address ranges that contain the addresses in this range and not in the given range.
	 * If the result has length 2, the two ranges are in increasing order.
	 * 
	 * @param other
	 * @return
	 */
	public IPAddressRange[] subtract(IPAddressRange other) {
		IPAddress otherLower = other.lower;
		IPAddress otherUpper = other.upper;
		IPAddress lower = this.lower;
		IPAddress upper = this.upper;
		if(compare(lower, otherLower) < 0) {
			if(compare(upper, otherUpper) > 0) { // l ol ou u
				return createPair(lower, otherLower.increment(-1), otherUpper.increment(1), upper);
			} else {
				int comp = compare(upper, otherLower);
				if(comp < 0) { // l u ol ou
					return createSingle();
				} else if(comp == 0) { // l u == ol ou
					return createSingle(lower, upper.increment(-1));
				}
				return createSingle(lower, otherLower.increment(-1)); // l ol u ou 
			}
		} else if(compare(otherUpper, upper) >= 0) { // ol l u ou
			return createEmpty();
		} else {
			int comp = compare(otherUpper, lower);
			if(comp < 0) {
				return createSingle(); // ol ou l u
			} else if(comp == 0) {
				return createSingle(lower.increment(1), upper); //ol ou == l u
			}
			return createSingle(otherUpper.increment(1), upper); // ol l ou u    
		}
	}
	
	protected abstract IPAddressRange create(IPAddress lower, IPAddress upper);
	
	protected abstract IPAddressRange[] createPair(IPAddress lower1, IPAddress upper1, IPAddress lower2, IPAddress upper2);
	
	protected abstract IPAddressRange[] createSingle(IPAddress lower, IPAddress upper);
	
	protected abstract IPAddressRange[] createSingle();
	
	protected abstract IPAddressRange[] createEmpty();

	@Override
	public boolean containsPrefixBlock(int prefixLen) {
		return IPAddressSection.containsPrefixBlock(prefixLen, lower, upper);
	}
	
	@Override
	public boolean containsSinglePrefixBlock(int prefixLen) {
		return IPAddressSection.containsSinglePrefixBlock(prefixLen, lower, upper);
	}
	
	@Override
	public int getBitCount() {
		return lower.getBitCount();
	}

	@Override
	public byte[] getBytes() {
		return lower.getBytes();
	}

	@Override
	public byte[] getBytes(byte[] bytes) {
		return lower.getBytes(bytes);
	}

	@Override
	public byte[] getBytes(byte[] bytes, int index) {
		return lower.getBytes(bytes, index);
	}

	@Override
	public byte[] getUpperBytes() {
		return upper.getUpperBytes();
	}

	@Override
	public byte[] getUpperBytes(byte[] bytes) {
		return upper.getUpperBytes(bytes);
	}

	@Override
	public byte[] getUpperBytes(byte[] bytes, int index) {
		return upper.getUpperBytes(bytes, index);
	}

	@Override
	public BigInteger getValue() {
		return lower.getValue();
	}

	@Override
	public BigInteger getUpperValue() {
		return upper.getValue();
	}

	@Override
	public boolean isZero() {
		return lower.isZero() && !isMultiple();
	}

	@Override
	public boolean includesZero() {
		return lower.isZero();
	}

	@Override
	public boolean isMax() {
		return upper.isMax() && !isMultiple();
	}

	@Override
	public boolean includesMax() {
		return upper.isMax();
	}
}
