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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.function.Function;
import java.util.function.IntFunction;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;

import inet.ipaddr.IPAddressSection.SegFunction;
import inet.ipaddr.format.IPAddressRange;
import inet.ipaddr.format.standard.AddressCreator;
import inet.ipaddr.format.validate.ParsedAddressGrouping;

/**
 * This class can be used to represent an arbitrary range of IP addresses.  
 * <p>
 * Note that the IPAddress and IPAddressString classes allow you to specify a range of values for each segment.
 * That allows you to represent single addresses, any address prefix subnet (eg 1.2.0.0/16 or 1:2:3:4::/64) or any subnet that can be represented with segment ranges (1.2.0-255.* or 1:2:3:4:*), see
 * {@link IPAddressString} for details.
 * <p>
 * IPAddressString and IPAddress cover all potential subnets and addresses that can be represented by a single address string of 4 or less segments for IPv4, and 8 or less segments for IPv6.
 * <p>
 * This class allows the representation of any sequential address range, including those that cannot be represented by IPAddress.
 * <p>
 * String representations include the full address for both the lower and upper bounds of the range.
 *  
 * @custom.core
 * @author sfoley
 *
 */
public abstract class IPAddressSeqRange implements IPAddressRange {
	
	private static final long serialVersionUID = 1L;
	
	protected final IPAddress lower, upper;
	
	private transient BigInteger count;
	private transient int hashCode;

	protected <T extends IPAddress> IPAddressSeqRange(
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
			T lower = compareLowValues(firstLower, otherLower) > 0 ? otherLower : firstLower;
			T upper = compareLowValues(firstUpper, otherUpper) < 0 ? otherUpper : firstUpper;
			this.lower = prefixLenRemover.apply(lower);
			this.upper = prefixLenRemover.apply(upper);
		}
	}
	
	protected <T extends IPAddress> IPAddressSeqRange(
			T first, 
			T second) {
		lower = first;
		upper = second;
	}

	private static int compareLowValues(IPAddress one, IPAddress two) {
		return IPAddress.compareLowValues(one, two);
	}
	
	@Override
	public BigInteger getCount() {
		BigInteger result = count;
		if(result == null) {
			count = result = getCountImpl();
		}
		return result;
	}
	
	@Override
	public boolean isMultiple() {
		BigInteger count = this.count;
		if(count == null) {
			return !getLower().equals(getUpper());
		}
		return IPAddressRange.super.isMultiple();
	}
	
	/**
	 * 
	 * @param other the range to compare, which does not need to range across the same address space
	 * @return whether this range spans more addresses than the provided range.
	 */
	public boolean isMore(IPAddressSeqRange other) {
		return getCount().compareTo(other.getCount()) > 0;
	}
	
	protected BigInteger getCountImpl() {
		return IPAddressRange.super.getCount();
	}
	
	@Override
	public abstract Iterable<? extends IPAddress> getIterable();
	
	protected static int getNetworkSegmentIndex(int networkPrefixLength, int bytesPerSegment, int bitsPerSegment) {
		return ParsedAddressGrouping.getNetworkSegmentIndex(networkPrefixLength, bytesPerSegment, bitsPerSegment);
	}
	
	protected static int getHostSegmentIndex(int networkPrefixLength, int bytesPerSegment, int bitsPerSegment) {
		return ParsedAddressGrouping.getHostSegmentIndex(networkPrefixLength, bytesPerSegment, bitsPerSegment);
	}
	
	/**
	 * Iterates through the range of prefix blocks in this range instance using the given prefix length.
	 * 
	 * @param prefLength
	 * @return
	 */
	@Override
	public abstract Iterator<? extends IPAddress> prefixBlockIterator(int prefLength);
	
	/**
	 * Iterates through the range of prefixes in this range instance using the given prefix length.
	 * 
	 * @param prefixLength
	 * @return
	 */
	@Override
	public Iterator<? extends IPAddressSeqRange> prefixIterator(int prefixLength) {
		if(!isMultiple()) {
			return new Iterator<IPAddressSeqRange>() {
				IPAddressSeqRange orig = IPAddressSeqRange.this;

				@Override
				public boolean hasNext() {
					return orig != null;
				}

			    @Override
				public IPAddressSeqRange next() {
			    	if(orig == null) {
			    		throw new NoSuchElementException();
			    	}
			    	IPAddressSeqRange result = orig;
			    	orig = null;
			    	return result;
			    }
			
			    @Override
				public void remove() {
			    	throw new UnsupportedOperationException();
			    }
			};
		}
		return new Iterator<IPAddressSeqRange>() {
			Iterator<? extends IPAddress> prefixBlockIterator = prefixBlockIterator(prefixLength);
			private boolean first = true;

			@Override
			public boolean hasNext() {
				return prefixBlockIterator.hasNext();
			}

		    @Override
			public IPAddressSeqRange next() {
		    	IPAddress next = prefixBlockIterator.next();
		    	if(first) {
		    		first = false;
		    		// next is a prefix block
		    		IPAddress lower = getLower();
		    		if(hasNext()) {
			    		if(!lower.includesZeroHost(prefixLength)) {
			    			return create(lower, next.getUpper());
			    		}
		    		} else {
		    			IPAddress upper = getUpper();
		    			if(!lower.includesZeroHost(prefixLength) || !upper.includesMaxHost(prefixLength)) {
		    				return create(lower, upper);
		    			}
		    		}
		    	} else if(!hasNext()) {
		    		IPAddress upper = getUpper();
		    		if(!upper.includesMaxHost(prefixLength)) {
		    			return create(next.getLower(), upper);
		    		}
		    	}
		    	return next.toSequentialRange();
		    }
		
		    @Override
			public void remove() {
		    	throw new UnsupportedOperationException();
		    }
		};
	}
	
	@FunctionalInterface
	protected interface SegValueComparator<T> {
	    boolean apply(T segmentSeries1, T segmentSeries2, int index);
	}
	
	@Override
	public abstract Iterator<? extends IPAddress> iterator();
	
	/*
	 * This iterator is used for the case where the range is non-multiple
	 */
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
	
	public String toNormalizedString(String separator) {
		Function<IPAddress, String> stringer = IPAddress::toNormalizedString;
		return toString(stringer, separator, stringer);
	}
	
	@Override
	public String toNormalizedString() {
		return toNormalizedString(" -> ");
	}
	
	public String toCanonicalString(String separator) {
		Function<IPAddress, String> stringer = IPAddress::toCanonicalString;
		return toString(stringer, separator, stringer);
	}
	
	@Override
	public String toCanonicalString() {
		return toCanonicalString(" -> ");
	}
	
	public String toString(Function<IPAddress, String> lowerStringer, String separator, Function<IPAddress, String> upperStringer) {
		return lowerStringer.apply(getLower()) + separator + upperStringer.apply(getUpper());
	}
	
	@Override
	public String toString() {
		return toCanonicalString();
	}

	@Override
	public abstract IPAddress[] spanWithPrefixBlocks();

	@Override
	public abstract IPAddress[] spanWithSequentialBlocks();
	
	/**
	 * Joins the given ranges into the fewest number of ranges.
	 * If no joining can take place, the original array is returned.
	 * 
	 * @param ranges
	 * @return
	 */
	public static IPAddressSeqRange[] join(IPAddressSeqRange... ranges) {
		int joinedCount = 0;
		Arrays.sort(ranges, Address.ADDRESS_LOW_VALUE_COMPARATOR);
		for(int i = 0; i < ranges.length; i++) {
			IPAddressSeqRange range = ranges[i];
			if(range == null) {
				continue;
			}
			for(int j = i + 1; j < ranges.length; j++) {
				IPAddressSeqRange range2 = ranges[j];
				if(range2 == null) {
					continue;
				}
				IPAddress upper = range.getUpper();
				IPAddress lower = range2.getLower();
				if(compareLowValues(upper, lower) >= 0
						|| upper.increment(1).equals(lower)) {
					//join them
					ranges[i] = range = range.create(range.getLower(), range2.getUpper());
					ranges[j] = null;
					joinedCount++;
				} else break;
			}
		}
		if(joinedCount == 0) {
			return ranges;
		}
		IPAddressSeqRange joined[] = new IPAddressSeqRange[ranges.length - joinedCount];
		for(int i = 0, j = 0; i < ranges.length; i++) {
			IPAddressSeqRange range = ranges[i];
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
	
	public boolean overlaps(IPAddressSeqRange other) {
		return compareLowValues(other.getLower(), getUpper()) <= 0 && compareLowValues(other.getUpper(), getLower()) >= 0;
	}
	
	private boolean containsRange(IPAddressRange other) {
		return compareLowValues(other.getLower(), getLower()) >= 0 && compareLowValues(other.getUpper(), getUpper()) <= 0;
	}
	
	@Override
	public boolean contains(IPAddress other) {
		return containsRange(other);
	}
	
	@Override
	public boolean contains(IPAddressSeqRange other) {
		return containsRange(other);
	}
	
	@Override
	public int hashCode() {
		int res = hashCode;
		if(res == 0) {
			res = 31 * getLower().hashCode() + getUpper().hashCode();
			hashCode = res;
		}
		return res;
	}
	
	@Override
	public boolean equals(Object o) {
		if(o instanceof IPAddressSeqRange) {
			IPAddressSeqRange otherRange = (IPAddressSeqRange) o;
				return getLower().equals(otherRange.getLower()) && getUpper().equals(otherRange.getUpper());
			}
			return false;
	}
	
	/**
	 * Returns the intersection of this range with the given range, a range which includes those addresses in both this and the given rqnge.
	 * @param other
	 * @return
	 */
	public IPAddressSeqRange intersect(IPAddressSeqRange other) {
		IPAddress otherLower = other.getLower();
		IPAddress otherUpper = other.getUpper();
		IPAddress lower = this.getLower();
		IPAddress upper = this.getUpper();
		if(compareLowValues(lower, otherLower) <= 0) {
			if(compareLowValues(upper, otherUpper) >= 0) {
				return other;
			} else if(compareLowValues(upper, otherLower) < 0) {
				return null;
			}
			return create(otherLower, upper);
		} else if(compareLowValues(otherUpper, upper) >= 0) {
			return this;
		} else if(compareLowValues(otherUpper, lower) < 0) {
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
	public IPAddressSeqRange join(IPAddressSeqRange other) {
		IPAddress otherLower = other.getLower();
		IPAddress otherUpper = other.getUpper();
		IPAddress lower = this.getLower();
		IPAddress upper = this.getUpper();
		int lowerComp = compareLowValues(lower, otherLower);
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
		int upperComp = compareLowValues(upper, otherUpper);
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
	public IPAddressSeqRange[] subtract(IPAddressSeqRange other) {
		IPAddress otherLower = other.getLower();
		IPAddress otherUpper = other.getUpper();
		IPAddress lower = this.getLower();
		IPAddress upper = this.getUpper();
		if(compareLowValues(lower, otherLower) < 0) {
			if(compareLowValues(upper, otherUpper) > 0) { // l ol ou u
				return createPair(lower, otherLower.increment(-1), otherUpper.increment(1), upper);
			} else {
				int comp = compareLowValues(upper, otherLower);
				if(comp < 0) { // l u ol ou
					return createSingle();
				} else if(comp == 0) { // l u == ol ou
					return createSingle(lower, upper.increment(-1));
				}
				return createSingle(lower, otherLower.increment(-1)); // l ol u ou 
			}
		} else if(compareLowValues(otherUpper, upper) >= 0) { // ol l u ou
			return createEmpty();
		} else {
			int comp = compareLowValues(otherUpper, lower);
			if(comp < 0) {
				return createSingle(); // ol ou l u
			} else if(comp == 0) {
				return createSingle(lower.increment(1), upper); //ol ou == l u
			}
			return createSingle(otherUpper.increment(1), upper); // ol l ou u    
		}
	}
	
	protected abstract IPAddressSeqRange create(IPAddress lower, IPAddress upper);
	
	protected abstract IPAddressSeqRange[] createPair(IPAddress lower1, IPAddress upper1, IPAddress lower2, IPAddress upper2);
	
	protected abstract IPAddressSeqRange[] createSingle(IPAddress lower, IPAddress upper);
	
	protected abstract IPAddressSeqRange[] createSingle();
	
	protected abstract IPAddressSeqRange[] createEmpty();

	@Override
	public boolean containsPrefixBlock(int prefixLen) {
		return IPAddressSection.containsPrefixBlock(prefixLen, getLower(), getUpper());
	}
	
	@Override
	public boolean containsSinglePrefixBlock(int prefixLen) {
		return IPAddressSection.containsSinglePrefixBlock(prefixLen, getLower(), getUpper());
	}
	
	@Override
	public int getBitCount() {
		return getLower().getBitCount();
	}

	@Override
	public byte[] getBytes() {
		return getLower().getBytes();
	}

	@Override
	public byte[] getBytes(byte[] bytes) {
		return getLower().getBytes(bytes);
	}

	@Override
	public byte[] getBytes(byte[] bytes, int index) {
		return getLower().getBytes(bytes, index);
	}

	@Override
	public byte[] getUpperBytes() {
		return getUpper().getUpperBytes();
	}

	@Override
	public byte[] getUpperBytes(byte[] bytes) {
		return getUpper().getUpperBytes(bytes);
	}

	@Override
	public byte[] getUpperBytes(byte[] bytes, int index) {
		return getUpper().getUpperBytes(bytes, index);
	}

	@Override
	public BigInteger getValue() {
		return getLower().getValue();
	}

	@Override
	public BigInteger getUpperValue() {
		return getUpper().getValue();
	}

	@Override
	public boolean isZero() {
		return includesZero() && !isMultiple();
	}

	@Override
	public boolean includesZero() {
		return getLower().isZero();
	}

	@Override
	public boolean isMax() {
		return includesMax() && !isMultiple();
	}

	@Override
	public boolean includesMax() {
		return getUpper().isMax();
	}
}
