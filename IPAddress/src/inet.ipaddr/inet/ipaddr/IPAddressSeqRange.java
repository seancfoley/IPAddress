/*
 * Copyright 2018-2024 Sean C Foley
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
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.IntFunction;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.function.ToLongFunction;
import java.util.function.UnaryOperator;
import java.util.stream.Stream;

import inet.ipaddr.AddressNetwork.AddressSegmentCreator;
import inet.ipaddr.IPAddressSection.IPAddressSeqRangePrefixSpliterator;
import inet.ipaddr.IPAddressSection.IPAddressSeqRangeSpliterator;
import inet.ipaddr.IPAddressSection.SegFunction;
import inet.ipaddr.IPAddressSection.SeqRangeIteratorProvider;
import inet.ipaddr.format.AddressComponentRange;
import inet.ipaddr.format.IPAddressRange;
import inet.ipaddr.format.standard.AddressCreator;
import inet.ipaddr.format.util.AddressComponentRangeSpliterator;
import inet.ipaddr.format.util.AddressComponentSpliterator;
import inet.ipaddr.format.validate.ParsedAddressGrouping;
import inet.ipaddr.ipv4.IPv4AddressSeqRange;
import inet.ipaddr.ipv6.IPv6AddressSeqRange;

/**
 * This class can be used to represent an arbitrary range of consecutive IP addresses.  
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

	private static final IPAddressSeqRange EMPTY_RANGES[] = new IPAddressSeqRange[0];
	private static final IPAddressSeqRangeList EMPTY_RANGE_LISTS[] = new IPAddressSeqRangeList[0];

	public static final String DEFAULT_RANGE_SEPARATOR = " -> ";
	
	protected static final IPAddressConverter DEFAULT_ADDRESS_CONVERTER = IPAddress.DEFAULT_ADDRESS_CONVERTER;

	protected final IPAddress lower, upper;
	
	private transient BigInteger count;
	private transient Boolean isMultiple;
	private transient int hashCode;

	protected <T extends IPAddress> IPAddressSeqRange(T first, T second, boolean preSet) {
		lower = first;
		upper = second;
	}

	protected <T extends IPAddress> IPAddressSeqRange(
			T first, 
			T other,
			UnaryOperator<T> getLower,
			UnaryOperator<T> getUpper,
			UnaryOperator<T> prefixLenRemover) {
		boolean f;
		if((f = first.contains(other)) || other.contains(first)) {
			T addr = f ? prefixLenRemover.apply(first) : prefixLenRemover.apply(other);
			lower = getLower.apply(addr);
			upper = getUpper.apply(addr);
		} else {
			T firstLower = getLower.apply(first);
			T otherLower = getLower.apply(other);
			T firstUpper = getUpper.apply(first);
			T otherUpper = getUpper.apply(other);
			T lower = compareLowerValues(firstLower, otherLower) > 0 ? otherLower : firstLower;
			T upper = compareLowerValues(firstUpper, otherUpper) < 0 ? otherUpper : firstUpper;
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

	static boolean versionsMatch(IPAddress one, IPAddress two) {
		return one.matchesVersion(two);
	}

	private static int compareLowerValues(IPAddress one, IPAddress two) {
		return AddressComparator.compareSegmentValues(false, one.getSection(), two.getSection());
	}

	private static int compareUpperValues(IPAddress one, IPAddress two) {
		return AddressComparator.compareSegmentValues(true, one.getSection(), two.getSection());
	}

	static String getMessage(String key) {
		return HostIdentifierException.getMessage(key);
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
		Boolean isMult = this.isMultiple;
		if(isMult == null) {
			BigInteger count = this.count;
			if(count == null) {
				IPAddress lower = getLower();
				IPAddress upper = getUpper();
				isMult = lower != upper && compareLowerValues(lower, upper) != 0;
			} else {
				isMult = !count.equals(BigInteger.ONE);
				this.isMultiple = isMult;
			}
		}
		return isMult;
	}

	public boolean isIPv4() {
		return false;
	}

	public boolean isIPv6() {
		return false;
	}

	/**
	 * If this sequential range is IPv4, or can be converted to IPv4 by applying the same conversion to all address in the range, returns that {@link IPv4AddressSeqRane}.  Otherwise, returns null.
	 * 
	 * @return the range
	 */
	public IPv4AddressSeqRange toIPv4() {
		return null;
	}
	
	/**
	 * If this sequential range is IPv6, or can be converted to IPv6 by applying the same conversion to all address in the range, returns that {@link IPv6AddressSeqRane}.  Otherwise, returns null.
	 * 
	 * @return the range
	 */
	public IPv6AddressSeqRange toIPv6() {
		return null;
	}
	
	/**
	 * 
	 * @deprecated use {@link #compareCounts(IPAddressSeqRange)} instead
	 * @param other the range to compare, which does not need to range across the same address space
	 * @return whether this range spans more addresses than the provided range.
	 */
	@Deprecated
	public boolean isMore(IPAddressSeqRange other) {
		return compareCounts(other) > 0;
	}
	
	/**
	 * Compares the counts of this range with the give range.
	 * 
	 * Rather than calculating counts with getCount(), there can be more efficient ways of comparing whether one range has more addresses than another than another.
	 * 
	 * @param other the range to compare, which does not need to range across the same address space
	 * @return a positive integer if this range has a larger count than the provided, 0 if they are the same, a negative integer if the other has a larger count.
	 */
	public int compareCounts(IPAddressSeqRange other) {
		if(count == null || other.count == null) {
			// don't calculate counts if not necessary
			IPAddress lower = getLower();
			IPAddress otherLower = other.getLower();
			if(versionsMatch(lower, otherLower)) {
				int lowerComp = compareLowerValues(lower, otherLower);
				int upperComp = compareLowerValues(getUpper(), other.getUpper());
				if(lowerComp > 0) {
					if(upperComp <= 0) {
						return -1;
					}
				} else if(lowerComp < 0) {
					if(upperComp >= 0) {
						return 1;
					}
				} else {
					if(upperComp < 0) {
						return -1;
					}
					if(upperComp > 0) {
						return 1;
					}
					return 0;
				}
			}
		}
		return getCount().compareTo(other.getCount());
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

	@Override
	public abstract AddressComponentRangeSpliterator<? extends IPAddressSeqRange, ? extends IPAddress> prefixBlockSpliterator(int prefLength);

	@Override
	public abstract Stream<? extends IPAddress> prefixBlockStream(int prefLength);

	protected static interface IPAddressSeqRangeSplitterSink<S, T>{
		void setSplitValues(S left, S right);
		
		S getAddressItem();
	};
	
	@FunctionalInterface
	protected static interface IPAddressSeqRangeIteratorProvider<S, T> extends SeqRangeIteratorProvider<S,T>{}
	
	protected static <S extends AddressComponentRange, T> AddressComponentRangeSpliterator<S, T> createSpliterator(
			S forIteration,
			Predicate<IPAddressSeqRangeSplitterSink<S, T>> splitter,
			IPAddressSeqRangeIteratorProvider<S, T> iteratorProvider,
			ToLongFunction<S> longSizer) {
		return new IPAddressSeqRangeSpliterator<S, T>(forIteration, splitter, iteratorProvider, longSizer);
	}
	
	protected static <S extends AddressComponentRange, T> AddressComponentRangeSpliterator<S, T> createSpliterator(
			S forIteration,
			Predicate<IPAddressSeqRangeSplitterSink<S, T>> splitter,
			IPAddressSeqRangeIteratorProvider<S, T> iteratorProvider,
			Function<S, BigInteger> sizer,
			Predicate<S> downSizer,
			ToLongFunction<S> longSizer) {
		return new IPAddressSeqRangeSpliterator<S, T>(forIteration, splitter, iteratorProvider, sizer, downSizer, longSizer);
	}

	protected static <S extends AddressComponentRange> AddressComponentSpliterator<S> createPrefixSpliterator(
			S forIteration,
			Predicate<IPAddressSeqRangeSplitterSink<S, S>> splitter,
			IPAddressSeqRangeIteratorProvider<S, S> iteratorProvider,
			ToLongFunction<S> longSizer) {
		return new IPAddressSeqRangePrefixSpliterator<S>(forIteration, splitter, iteratorProvider, longSizer);
	}
	
	protected static <S extends AddressComponentRange> AddressComponentSpliterator<S> createPrefixSpliterator(
			S forIteration,
			Predicate<IPAddressSeqRangeSplitterSink<S, S>> splitter,
			IPAddressSeqRangeIteratorProvider<S, S> iteratorProvider,
			Function<S, BigInteger> sizer,
			Predicate<S> downSizer,
			ToLongFunction<S> longSizer) {
		return new IPAddressSeqRangePrefixSpliterator<S>(forIteration, splitter, iteratorProvider, sizer, downSizer, longSizer);
	}
	
	protected static <R,A extends IPAddress> Iterator<R> rangedIterator(Iterator<A> iter) {
		return new Iterator<R>() {
			@Override
			public boolean hasNext() {
				return iter.hasNext();
			}

			@SuppressWarnings("unchecked")
			@Override
			public R next() {
				return (R) iter.next().coverWithSequentialRange();
			}
		};
	}

	/**
	 * Iterates through the range of prefixes in this range instance using the given prefix length.
	 * <p>
	 * Since a range between two arbitrary addresses cannot always be represented with a single IPAddress instance,
	 * the returned iterator iterates through {@link IPAddressSeqRange} instances.
	 * <p>
	 * For instance, if iterating from 1.2.3.4 to 1.2.4.5 with prefix 8, the range shares the same prefix 1,
	 * but the range cannot be represented by the address 1.2.3-4.4-5 which does not include 1.2.3.255 or 1.2.4.0 both of which are in the original range.
	 * Nor can the range be represented by 1.2.3-4.0-255 which includes 1.2.4.6 and 1.2.3.3, both of which were not in the original range.
	 * An IPAddressSeqRange is thus required to represent that prefixed range.
	 * 
	 * @param prefixLength
	 * @return
	 */
	@Override
	public Iterator<? extends IPAddressSeqRange> prefixIterator(int prefixLength) {
		if(prefixLength < 0) {
			throw new PrefixLenException(prefixLength);
		}
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
		    	return next.coverWithSequentialRange();
		    }
		};
	}

	@Override
	public abstract AddressComponentSpliterator<? extends IPAddressSeqRange> prefixSpliterator(int prefLength);
	
	@Override
	public abstract Stream<? extends IPAddressSeqRange> prefixStream(int prefLength);

	@FunctionalInterface
	protected interface SegValueComparator<T> {
	    boolean apply(T segmentSeries1, T segmentSeries2, int index);
	}

	/**
	 * Splits a sequential range into two.
	 * <p>
	 * Returns false if it cannot be done.
	 * 
	 * @param beingSplit
	 * @param transformer
	 * @param segmentCreator
	 * @param originalSegments
	 * @param networkSegmentIndex if this index matches hostSegmentIndex, splitting will attempt to split the network part of this segment
	 * @param hostSegmentIndex splitting will work with the segments prior to this one
	 * @param prefixLength
	 * @return
	 */
	protected static <I extends IPAddressSeqRange, T extends IPAddressRange, S extends AddressSegment> boolean split(
			IPAddressSeqRangeSplitterSink<I, T> sink,
			BiFunction<S[], S[], I> transformer,
			AddressSegmentCreator<S> segmentCreator,
			S originalSegmentsLower[],
			S originalSegmentsUpper[],
			int networkSegmentIndex, //for regular iterators (not prefix block), networkSegmentIndex is last segment (count - 1) - it is only instrumental with prefix iterators
			int hostSegmentIndex, // for regular iterators hostSegmentIndex is past last segment (count) - it is only instrumental with prefix iterators
			Integer prefixLength) {
		int i = 0;
		S lowerSeg, upperSeg;
		lowerSeg = upperSeg = null;
		boolean isSplit = false;
		for(; i < hostSegmentIndex; i++) {
			S segLower = originalSegmentsLower[i];
			S segUpper = originalSegmentsUpper[i];
			int lower = segLower.getSegmentValue();
			int upper = segUpper.getSegmentValue();
			// if multiple, split into two
			if(lower != upper) {
				isSplit = true;
				int size = upper - lower;
				int mid = lower + (size >>> 1);
				lowerSeg = segmentCreator.createSegment(mid);
				upperSeg = segmentCreator.createSegment(mid + 1);
				break;
			}
		}
		if(i == networkSegmentIndex && !isSplit) {
			// prefix or prefix block iterators: no need to differentiate, handle both as prefix, iteration will handle the rest
			S segLower = originalSegmentsLower[i];
			S segUpper = originalSegmentsUpper[i];
			int segBitCount = segLower.getBitCount();
			Integer pref = IPAddressSection.getSegmentPrefixLength(segBitCount, prefixLength, i);
			int shiftAdjustment = segBitCount - pref;
			int lower = segLower.getSegmentValue();
			int upper = segUpper.getSegmentValue();
			lower >>>= shiftAdjustment;
			upper >>>= shiftAdjustment;
			if(lower != upper) {
				isSplit = true;
				int size = upper - lower;
				int mid = lower + (size >>> 1);
				int next = mid + 1;
				mid = (mid << shiftAdjustment) | ~(~0 << shiftAdjustment);
				next <<= shiftAdjustment;
				lowerSeg = segmentCreator.createSegment(mid);
				upperSeg = segmentCreator.createSegment(next);
			}
		}
		if(isSplit) {
			int len = originalSegmentsLower.length;
			S lowerUpperSegs[] = segmentCreator.createSegmentArray(len);
			S upperLowerSegs[] = segmentCreator.createSegmentArray(len);
			System.arraycopy(originalSegmentsLower, 0, lowerUpperSegs, 0, i);
			System.arraycopy(originalSegmentsLower, 0, upperLowerSegs, 0, i);
			int j = i + 1;
			lowerUpperSegs[i] = lowerSeg;
			upperLowerSegs[i] = upperSeg;
			Arrays.fill(lowerUpperSegs, j, lowerUpperSegs.length, segmentCreator.createSegment(lowerSeg.getMaxSegmentValue()));
			Arrays.fill(upperLowerSegs, j, upperLowerSegs.length, segmentCreator.createSegment(0));
			sink.setSplitValues(transformer.apply(originalSegmentsLower, lowerUpperSegs), transformer.apply(upperLowerSegs, originalSegmentsUpper));
		}
		return isSplit;
	}

	@Override
	public abstract Iterator<? extends IPAddress> iterator();

	@Override
	public abstract AddressComponentRangeSpliterator<? extends IPAddressSeqRange, ? extends IPAddress> spliterator();
	
	@Override
	public abstract Stream<? extends IPAddress> stream();

	/*
	 * This iterator is used for the case where the range is non-multiple
	 */
	protected static <T extends Address, S extends AddressSegment> Iterator<T> iterator(T original, AddressCreator<T, ?, ?, S> creator) {
		return IPAddressSection.iterator(original, creator, null);
	}
	
	/*
	 This iterator is (not surprisingly) 2 to 3 times faster (based on measurements I've done) than an iterator that uses the increment method like:
	 
	 return iterator(a -> a.increment());
	 
	 protected Iterator<T> iterator(UnaryOperator<T> incrementor) {
	 	return new Iterator<T>() {
			BigInteger count = getCount();
			T current = lower;
					
			@Override
			public boolean hasNext() {
				return count.signum() != 0;
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
		int divCount = lower.getSegmentCount();
		
		// at any given point in time, this list provides an iterator for the segment at each index
		ArrayList<Supplier<Iterator<S>>> segIteratorProducerList = new ArrayList<Supplier<Iterator<S>>>(divCount);
		
		// at any given point in time, finalValue[i] is true if and only if we have reached the very last value for segment i - 1
		// when that happens, the next iterator for the segment at index i will be the last
		boolean finalValue[] = new boolean[divCount + 1];
		
		// here is how the segment iterators will work:
		// the low and high values at each segment are low, high
		// the maximum possible values for any segment are min, max
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
		// By following these rules, we iterate through all possible addresses	
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
	
	/**
	 * Returns the lowest address in the sequential range, the one with the lowest numeric value
	 */
	@Override
	public IPAddress getLower() {
		return lower;
	}

	/**
	 * Returns the highest address in the sequential range, the one with the highest numeric value
	 */
	@Override
	public IPAddress getUpper() {
		return upper;
	}

	/**
	 * Returns the individual address at the given index into this sequential range.
	 * <p>
	 * If the increment is negative, or the increment exceeds {@link #getCount()} - 1, this method throws IndexOutOfBoundsException.
	 * <p>
	 * Otherwise, this returns the address that is the given index upwards into the list of sequential ranges, with the increment of zero
	 * returning the first address.
	 * 
	 * @param index
	 * @return
	 */
	public abstract IPAddress get(BigInteger index);

	/**
	 * Returns the individual address at the given index into this sequential range.
	 * <p>
	 * If the increment is negative, or the increment exceeds {@link #getCount()} - 1, this method throws IndexOutOfBoundsException.
	 * <p>
	 * Otherwise, this returns the address that is the given index upwards into the list of sequential ranges, with the increment of zero
	 * returning the first address.
	 * 
	 * @param index
	 * @return
	 */
	public abstract IPAddress get(long index);

	public String toNormalizedString(String separator) {
		Function<IPAddress, String> stringer = IPAddress::toNormalizedString;
		return toString(stringer, separator, stringer);
	}

	/**
	 * Produces a normalized string for the address range.
	 * It has the format "lower -&gt; upper" where lower and upper are the normalized strings for the lowest and highest addresses in the range, given by {@link #getLower()} and {@link #getUpper()}.
	 */
	@Override
	public String toNormalizedString() {
		return toNormalizedString(DEFAULT_RANGE_SEPARATOR);
	}

	/**
	 * Produces a canonical string for the address range with the given separator string.
	 */
	public String toCanonicalString(String separator) {
		Function<IPAddress, String> stringer = IPAddress::toCanonicalString;
		return toString(stringer, separator, stringer);
	}

	/**
	 * Produces a canonical string for the address range.
	 * It has the format "lower -&gt; upper" where lower and upper are the canonical strings for the lowest and highest addresses in the range, given by {@link #getLower()} and {@link #getUpper()}.
	 */
	@Override
	public String toCanonicalString() {
		return toCanonicalString(DEFAULT_RANGE_SEPARATOR);
	}

	public String toString(Function<? super IPAddress, String> lowerStringer, String separator, Function<? super IPAddress, String> upperStringer) {
		return toString(getLower(), lowerStringer, separator, getUpper(), upperStringer);
	}
	
	static String toString(IPAddress lower, Function<? super IPAddress, String> lowerStringer, String separator, IPAddress upper, Function<? super IPAddress, String> upperStringer) {
		return lowerStringer.apply(lower) + separator + upperStringer.apply(upper);
	}

	/**
	 * Produces the canonical string for the address, also available from {@link #toCanonicalString()}.
	 */
	@Override
	public String toString() {
		return toCanonicalString();
	}

	/**
	 * Returns the minimal-size prefix block that covers all the addresses in this range.
	 * The resulting block will have a larger count than this, unless this range already directly corresponds to a prefix block.
	 */
	@Override
	public abstract IPAddress coverWithPrefixBlock();
	
	@Override
	public abstract IPAddress[] spanWithPrefixBlocks();

	@Override
	public abstract IPAddress[] spanWithSequentialBlocks();
	
	/**
	 * Joins the given ranges into the fewest number of ranges.
	 * This method can handle null ranges, which are ignored.
	 * The returned array will never be null and will be sorted by ascending lowest range value. 
	 * <p>
	 * If the input ranges are both IPv4 and IPv6, then the joined IPv4 ranges will be followed by the joined IPv6 ranges.
	 * 
	 * @param ranges
	 * @return
	 */
	public static IPAddressSeqRange[] join(IPAddressSeqRange... ranges) {
		return joinImpl(ranges, true);
	}
	
	private static IPAddressSeqRange[] joinImpl(IPAddressSeqRange ranges[], boolean isFinal) {
		if(ranges.length == 0) {
			return EMPTY_RANGES;
		}
		ranges = ranges.clone();
		// null entries are automatic joins
		int joinedCount = 0;
		for(int i = 0, j = ranges.length - 1; i <= j; i++) {
			if(ranges[i] == null) {
				joinedCount++;
				while(ranges[j] == null && j > i) {
					j--;
					joinedCount++;
				}
				if(j > i) {
					ranges[i] = ranges[j];
					ranges[j] = null;
					j--;
				}
			}
		}
		int len = ranges.length - joinedCount;
		Arrays.sort(ranges, 0, len, Address.ADDRESS_LOW_VALUE_COMPARATOR);
		for(int i = 0; i < len; ) {
			IPAddressSeqRange range = ranges[i];
			IPAddress currentLower = range.getLower();
			IPAddress currentUpper = range.getUpper();
			boolean didJoin = false;
			int j = i + 1;
			for(; j < len; j++) {
				IPAddressSeqRange range2 = ranges[j];
				IPAddress nextLower = range2.getLower();
				if(!versionsMatch(nextLower, currentUpper)) {
					break;
				}
				if(compareLowerValues(currentUpper, nextLower) >= 0
						|| currentUpper.increment().equals(nextLower)) {
					// join them
					joinedCount++;
					IPAddress nextUpper = range2.getUpper();
					if(compareLowerValues(currentUpper, nextUpper) < 0) {
						currentUpper = nextUpper;
					}
					ranges[j] = null;
					didJoin = true;
				} else break;
			}
			if(didJoin) {
				ranges[i] = range.create(currentLower, currentUpper);
			}
			i = j;
		}
		if(joinedCount == 0) {
			return ranges;
		}
		if(ranges.length == joinedCount) {
			return EMPTY_RANGES;
		}
		if(isFinal) {
			IPAddressSeqRange joined[] = new IPAddressSeqRange[ranges.length - joinedCount];
			if(joined.length > 0) {
				for(int i = 0, j = 0; ; i++) {
					IPAddressSeqRange range = ranges[i];
					if(range == null) {
						continue;
					}
					joined[j++] = range;
					if(j >= joined.length) {
						break;
					}
				}
			}
			ranges = joined;
		}
		return ranges;
	}

	/**
	 * Creates ranges lists from the given ranges.
	 * If the input ranges comprise multiple versions of IP addresses, then multiple lists will be returned, the IPv4 followed by the IPv6 list.
	 * If there are no non-null input ranges, then a zero-length array is returned.
	 * @param ranges
	 * @return
	 */
	public static IPAddressSeqRangeList[] joinIntoList(IPAddressSeqRange... ranges) {
		IPAddressSeqRange res[] = joinImpl(ranges, false);
		if(res.length == 0) {
			return EMPTY_RANGE_LISTS;
		}
		int capacity = 10;
		int twiceSize = res.length << 1;
		if(twiceSize > capacity) {
			capacity = twiceSize;
		}
		IPAddress previousAddress = null;
		ArrayList<IPAddressSeqRangeList> multipleLists = null;
		IPAddressSeqRangeList previousList = null;
		IPAddressSeqRangeList list = new IPAddressSeqRangeList(capacity);
		for(int i = 0; i < res.length; i++) {
			IPAddressSeqRange rng = res[i];
			if(rng == null) {
				continue;
			}
			IPAddress next = rng.getLower();
			if(previousAddress != null && !versionsMatch(previousAddress, next)) {
				if(previousList != null) {
					// second time we switch versions, which is not possible if just IPv4/v6
					multipleLists = new ArrayList<>();
					multipleLists.add(previousList);
					multipleLists.add(list);
					previousList = null;
				} else if(multipleLists != null) {
					// third time we switch versions, which is not possible if just IPv4/v6
					multipleLists.add(list);
				} else {
					// first time we switch versions
					previousList = list;
				}
				list = new IPAddressSeqRangeList(capacity);
			}
			previousAddress = next;
			list.ranges.add(rng);
		}
		if(multipleLists != null) {
			multipleLists.add(list);
			return multipleLists.toArray(new IPAddressSeqRangeList[multipleLists.size()]);
		}
		if(previousList != null) {
			return new IPAddressSeqRangeList[]{previousList, list};
		}
		return new IPAddressSeqRangeList[]{list};
	}

	boolean isContainedBy(IPAddress other) {
		IPAddress lower = getLower(), upper = getUpper();
		if(!versionsMatch(lower, other)) {
			return false;
		}
		int segCount = lower.getSegmentCount();
		for(int i = 0; i < segCount; i++) {
			IPAddressSegment lowerSeg = lower.getSegment(i);
			IPAddressSegment upperSeg = upper.getSegment(i);
			int lowerSegValue = lowerSeg.getSegmentValue();
			int upperSegValue = upperSeg.getSegmentValue();
			IPAddressSegment otherSeg = other.getSegment(i);
			int otherSegLowerValue = otherSeg.getSegmentValue();
			int otherSegUpperValue = otherSeg.getUpperSegmentValue();
			if(lowerSegValue < otherSegLowerValue || upperSegValue > otherSegUpperValue) {
				return false;
			}
			if(lowerSegValue != upperSegValue) {
				for(int j = i + 1; j < segCount; j++) {
					otherSeg = other.getSegment(j);
					if(!otherSeg.isFullRange()) {
						return false;
					}
				}
				break;
			}
		}
		return true;
	}
	
	/**
	 * Returns true if this sequential range overlaps the given address or subnet.
	 * 
	 * @param other
	 * @return
	 */
	@Override
	public boolean overlaps(IPAddress other) {
		IPAddress lower = getLower(), upper = getUpper();
		if(!versionsMatch(lower, other)) {
			return false;
		}
		int segCount = lower.getSegmentCount();
		for(int i = 0; i < segCount; i++) {
			IPAddressSegment lowerSeg = lower.getSegment(i);
			IPAddressSegment upperSeg = upper.getSegment(i);
			int lowerSegValue = lowerSeg.getSegmentValue();
			int upperSegValue = upperSeg.getSegmentValue();
			IPAddressSegment otherSeg = other.getSegment(i);
			int otherSegLowerValue = otherSeg.getSegmentValue();
			int otherSegUpperValue = otherSeg.getUpperSegmentValue();
			if(lowerSegValue == upperSegValue) {
				if(lowerSegValue < otherSegLowerValue || lowerSegValue > otherSegUpperValue) {
					return false;
				}
			} else {
				if(otherSegLowerValue < upperSegValue && otherSegUpperValue > lowerSegValue) {
					return true;
				} else if(otherSegLowerValue == upperSegValue) {
					for(int j = i + 1; j < segCount; j++) {
						otherSeg = other.getSegment(j);
						upperSeg = upper.getSegment(j);
						upperSegValue = upperSeg.getSegmentValue();
						otherSegLowerValue = otherSeg.getSegmentValue();
						if(otherSegLowerValue < upperSegValue) {
							return true;
						} else if(otherSegLowerValue > upperSegValue) {
							return false;
						}
					}
					break;
				} else if(otherSegUpperValue == lowerSegValue) {
					for(int j = i + 1; j < segCount; j++) {
						otherSeg = other.getSegment(j);
						lowerSeg = lower.getSegment(j);
						lowerSegValue = lowerSeg.getSegmentValue();
						otherSegUpperValue = otherSeg.getUpperSegmentValue();
						if(otherSegUpperValue > lowerSegValue) {
							return true;
						} else if(otherSegUpperValue < lowerSegValue) {
							return false;
						}
					}
					break;
				} else {
					return false;
				}
			}
		}
		return true;
	}
	
	/**
	 * Returns true if this sequential range overlaps the given sequential range.
	 * 
	 * @param other
	 * @return
	 */
	@Override
	public boolean overlaps(IPAddressSeqRange other) {
		IPAddress otherLower = other.getLower();
		IPAddress upper = getUpper();
		if(!versionsMatch(upper, otherLower)) {
			return false;
		}
		return overlapsCheck(getLower(), upper, otherLower, other.getUpper());
	}
	
	private static boolean overlapsCheck(IPAddress lower, IPAddress upper, IPAddress otherLower, IPAddress otherUpper) {
		return compareLowerValues(otherLower, upper) <= 0 && compareLowerValues(otherUpper, lower) >= 0;
	}

	// we choose to not make this public
	// it is simply wrong to do an instanceof in the IPAddressRange interface, it assumes you know all implementors, 
	// it will not work if/when someone adds a new implementation.
	// If you do not know how an IPAddressRange is implemented, can you do the contains?  
	// Yes, but only by iterating, which is ugly for large ranges.
	// Now that we have coverWithSequentialRange() in IPAddressRange, it is easy to do this for sequential subnets.
	// And for non-sequential, there is no simple way of doing it, 
	// in IPAddress you need to either go through the segments, or you need to go through the sequential blocks,
	// and there is no general way to do it for any implementation of IPAddressRange.
	private boolean containsRange(IPAddressRange other, Supplier<IPAddress> lowerComp, Supplier<IPAddress> upperComp) {
		IPAddress otherLower = lowerComp.get();
		IPAddress lower = getLower();
		if(!versionsMatch(lower, otherLower)) {
			return false;
		}
		return compareLowerValues(otherLower, lower) >= 0 && compareUpperValues(upperComp.get(), getUpper()) <= 0;
	}
	
	@Override
	public boolean contains(IPAddress other) {
		Supplier<IPAddress> identity = () -> other;
		return containsRange(other, identity, identity);
	}
	
	@Override
	public boolean contains(IPAddressSeqRange other) {
		return containsRange(other, other::getLower, other::getUpper);
	}

	/**
	 * Returns the distance of the given address from the initial value of this range.  Indicates where an address sits relative to the range ordering.
	 * <p>
	 * If within or above the range, it is the distance to the lower boundary of the sequential range.  If below the range, returns the number of addresses following the address to the lower range boundary.
	 * <p>
	 * The method does not return null if this range does not contain the address.  You can call {@link #contains(IPAddress)} or you can compare with {@link #getCount()} to check for containment.
	 * An address is in the range if 0 &lt;= {@link #enumerate(IPAddress)} &lt; {@link #getCount()}.
	 * <p>
	 * Returns null when the argument is a multi-valued subnet. The argument must be an individual address.
	 * <p>
	 * If the given address does not have the same version or type as the addresses in this range, then null is returned.
	 */
	@Override
	public BigInteger enumerate(IPAddress other) {
		IPAddress lower = getLower();
		if(other == lower) {
			return BigInteger.ZERO;
		} else if(other == getUpper()) { 
			return getCount().subtract(BigInteger.ONE);
		}
		return lower.enumerate(other);
	}

	/**
	 * Returns whether the address or subnet represents a range of values that are sequential.
	 * <p>
	 * IP address sequential ranges are sequential by definition, so this returns true.
	 * 
	 * @return true
	 */
	@Override
	public boolean isSequential() {
		return true;
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

	/**
	 * Returns whether the given sequential address range is equal to this sequential address range.
 	 * Two sequential address ranges are equal if their lower and upper range boundaries are equal.
	 */
	@Override
	public boolean equals(Object o) {
		if(o instanceof IPAddressSeqRange) {
			IPAddressSeqRange otherRange = (IPAddressSeqRange) o;
				return getLower().equals(otherRange.getLower()) && getUpper().equals(otherRange.getUpper());
			}
			return false;
	}

	/**
	 * Returns the intersection of this range with the given range, a range which includes those addresses in both this and the given range.
	 * @param other
	 * @return
	 */
	public IPAddressSeqRange intersect(IPAddressSeqRange other) {
		IPAddress lower = getLower();
		IPAddress otherLower = other.getLower();
		if(!versionsMatch(lower, otherLower)) {
			return null;
		}
		IPAddress upper = getUpper();
		IPAddress otherUpper = other.getUpper();
		if(compareLowerValues(lower, otherLower) <= 0) {
			if(compareLowerValues(upper, otherUpper) >= 0) {
				return other;
			} else if(compareLowerValues(upper, otherLower) < 0) {
				return null;
			}
			return create(otherLower, upper);
		} else if(compareLowerValues(otherUpper, upper) >= 0) {
			return this;
		} else if(compareLowerValues(otherUpper, lower) < 0) {
			return null;
		}
		return create(lower, otherUpper);
	}

	/**
	 * Joins two ranges if they are contiguous ranges.
	 * 
	 * If this range overlaps the given range,
	 * or if the highest value of the lower range is one below the lowest value of the higher range,
	 * then the two are joined into a new larger range that is returned.
	 * <p>
	 * Otherwise, null is returned.
	 * <p>
	 * Use {@link #joinIntoList(IPAddressSeqRange)} if you wish the result to match the original inputs. 
	 * That method returns a list which contains both this and the given range, regardless of whether they can be joined into a single range. 
	 * 
	 * @param other
	 * @return
	 */
	public IPAddressSeqRange join(IPAddressSeqRange other) {
		IPAddress lower = getLower();
		IPAddress otherLower = other.getLower();
		if(!versionsMatch(lower, otherLower)) {
			return null;
		}
		int lowerComp = compareLowerValues(lower, otherLower);
		IPAddress upper = getUpper();
		IPAddress otherUpper = other.getUpper();
		IPAddressSeqRange singleJoin = joinOverlapping(lowerComp, lower, upper, otherLower, otherUpper);
		if(singleJoin != null) {
			return singleJoin;
		}
		if(lowerComp > 0) {
			if(compareLowerValues(otherUpper.increment(), lower) == 0) {
				return create(otherLower, upper);
			}
		} else {
			if(compareLowerValues(upper.increment(), otherLower) == 0) {
				return create(lower, otherUpper);
			}
		}
		return null;
	}

	private IPAddressSeqRange joinOverlapping(int lowerComp, IPAddress lower, IPAddress upper, IPAddress otherLower, IPAddress otherUpper) {
		if(overlapsCheck(lower, upper, otherLower, otherUpper)) {
			int upperComp = compareLowerValues(upper, otherUpper);
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
		return null;
	}

	/**
	 * Joins two ranges.
	 * 
	 * Similar to {@link #join(IPAddressSeqRange)}, but instead the result includes all the addresses in both ranges, regardless of whether they are contiguous.
	 * 
	 * @param other
	 * @return
	 */
	public IPAddressSeqRangeList joinIntoList(IPAddressSeqRange other) {
		IPAddress lower = getLower();
		IPAddress otherLower = other.getLower();
		if(!versionsMatch(lower, otherLower)) {
			throw new IllegalArgumentException(getMessage("ipaddress.error.mismatched.bit.size"));
		}
		int lowerComp = compareLowerValues(lower, otherLower);
		IPAddress upper = getUpper();
		IPAddress otherUpper = other.getUpper();
		IPAddressSeqRange singleJoin = joinOverlapping(lowerComp, lower, upper, otherLower, otherUpper);
		if(singleJoin == null) {
			if(lowerComp > 0) {
				if(compareLowerValues(otherUpper.increment(), lower) == 0) {
					return create(otherLower, upper).intoSequentialRangeList();
				}
				return createDoubleList(other, this);
			}
			if(compareLowerValues(upper.increment(), otherLower) == 0) {
				return create(lower, otherUpper).intoSequentialRangeList();
			}
			return createDoubleList(this, other);
		}
		return singleJoin.intoSequentialRangeList();
	}

	/**
	 * Extend this sequential range to include all addresses in the given individual address or subnet.
	 * If the argument has a different IP version than this, null is returned.
	 * Otherwise, this method returns the range that includes this range, the given address or subnet, and all addresses in-between.
	 * 
	 * @param other
	 * @return
	 */
	public IPAddressSeqRange extend(IPAddress other) {
		return extend(other, other, other);
	}
	
	/**
	 * Extend this sequential range to include all addresses in the given sequential range.
	 * If the argument has a different IP version than this, null is returned.
	 * Otherwise, this method returns the range that includes this range, the given sequential range, and all addresses in-between.
	 * 
	 * @param other
	 * @return
	 */
	public IPAddressSeqRange extend(IPAddressSeqRange other) {
		return extend(other, other.getLower(), other.getUpper());
	}
	
	private IPAddressSeqRange extend(IPAddressRange other, IPAddress lowerComp, IPAddress upperComp) {
		IPAddress lower = getLower();
		IPAddress otherLowerComp = lowerComp;
		if(!versionsMatch(lower, otherLowerComp)) {
			return null;
		}
		IPAddress upper = getUpper();
		int lowerComparison = compareLowerValues(lower, otherLowerComp);
		int upperComparison = compareUpperValues(upper, upperComp);
		if(lowerComparison > 0) { // 
			if(upperComparison <= 0) { // ol l u ou
				return other.coverWithSequentialRange();
			}
			// ol l ou u or ol ou l u
			return create(other.getLower(), upper);
		}
		// lowerComp <= 0
		if(upperComparison >= 0) { // l ol ou u
			return this;
		}
		return create(lower, other.getUpper());// l ol u ou or l u ol ou
	}
	
	/**
	 * Extend this sequential range to include all address in the given range, which can be an IPAddress or IPAddressSeqRange.
	 * If the argument has a different IP version than this, null is returned.
	 * Otherwise, this method returns the range that includes this range, the given range, and all addresses in-between.
	 * 
	 * @param other
	 * @return
	 */
	public IPAddressSeqRange extend(IPAddressRange other) {
		return extend(other, other.getLower(), other.getUpper());
	}

	/**
	 * Subtracts the given range from this range, to produce either zero, one, or two address ranges that contain the addresses in this range and not in the given range.
	 * If the result has length 2, the two ranges are ordered by ascending lowest range value. 
	 * 
	 * @param other
	 * @return
	 */
	public IPAddressSeqRange[] subtract(IPAddressSeqRange other) {
		return subtract(
				other,
				this::createEmptyArray,
				this::createSingleThis,
				this::createSingleArray,
				this::createDoubleArray);
	}

	/**
	 * Subtracts the given range from this range, to produce either zero, one, or two address ranges, stored in a IPAddressSeqRangeList, which is sorted, that contain the addresses in this range and not in the given range.
	 * 
	 * @param other
	 * @return
	 */
	public IPAddressSeqRangeList subtractIntoList(IPAddressSeqRange other) {
		return subtract(
				other,
				this::createList,
				this::intoSequentialRangeList,
				this::createSingleList,
				this::createDoubleList);
	}

	private <T> T subtract(
			IPAddressSeqRange other,
			Supplier<T> createEmpty,
			Supplier<T> createThis,
			Function<IPAddressSeqRange, T> createSingle,
			BiFunction<IPAddressSeqRange, IPAddressSeqRange, T> createDouble //createPair
			) {
		IPAddress lower = getLower();
		IPAddress upper = getUpper();
		IPAddress otherLower = other.getLower();
		IPAddress otherUpper = other.getUpper();
		if(!versionsMatch(lower, otherLower)) {
			return createThis.get();
		}
		if(compareLowerValues(lower, otherLower) < 0) {
			if(compareLowerValues(upper, otherUpper) > 0) { // l ol ou u
				IPAddressSeqRange first = create(lower, otherLower.decrement());
				IPAddressSeqRange second = create(otherUpper.increment(), upper);
				return createDouble.apply(first, second);
			}
			int comp = compareLowerValues(upper, otherLower);
			if(comp < 0) { // l u ol ou
				return createThis.get();
			}
			// l ol u ou (includes l u == ol ou)
			IPAddressSeqRange rng = create(lower, otherLower.decrement());
			return createSingle.apply(rng);
		} else if(compareLowerValues(otherUpper, upper) >= 0) { // ol l u ou
			return createEmpty.get();
		}
		int comp = compareLowerValues(otherUpper, lower);
		if(comp < 0) {
			return createThis.get(); // ol ou l u
		}
		// ol l ou u  (includes  ol ou == l u)
		IPAddressSeqRange rng = create(otherUpper.increment(), upper);
		return createSingle.apply(rng);
	}

	@Override
	public IPAddressSeqRange[] complement() {
		return complement(
				this::createEmptyArray,
				this::createSingleArray,
				this::createDoubleArray);
	}

	public IPAddressSeqRangeList complementIntoList() {
		return complement(
				this::createList,
				this::createSingleList,
				this::createDoubleList);
	}

	private <T> T complement(
			Supplier<T> createEmpty,
			Function<IPAddressSeqRange, T> createSingle,
			BiFunction<IPAddressSeqRange, IPAddressSeqRange, T> createDouble) {
		IPAddress lower = getLower();
		IPAddress upper = getUpper();
		if(lower.includesZero()) {
			if(upper.includesMax()) {
				return createEmpty.get();
			}
			IPAddress max = lower.getNetwork().getNetworkMask(getBitCount(), false);
			IPAddressSeqRange rng = create(upper.increment(), max);
			return createSingle.apply(rng);
		}
		IPAddress zero = lower.getNetwork().getNetworkMask(0, false);
		if(getUpper().includesMax()) {
			IPAddressSeqRange rng = create(zero, lower.decrement());
			return createSingle.apply(rng);
		}
		IPAddress max = lower.getNetwork().getNetworkMask(getBitCount(), false);
		IPAddressSeqRange first = create(zero, lower.decrement());
		IPAddressSeqRange second = create(upper.increment(), max);
		return createDouble.apply(first, second);
	}

	/**
	 * Splits this range at the given address into two ranges, one lower and one upper.  
	 * The second range starts with the lower address of the given address or subnet.
	 * The first range consists of all preceding addresses.
	 * <p>
	 * This is similar to subtract, but without removing the given address or subnet from the result.
	 * <p>
	 * Unlike subtract, this always returns an array of length two.  In some cases, one or both of the two returned ranges is null.
	 * <p>
	 * If the given address or subnet includes the first address in this range, 
	 * or all addresses of the given address or subnet are below the lower value of this range, 
	 * then the first range is null, and the second range is the same range as this range.
	 * <p>
	 * If all addresses of the given address or subnet are above the upper value of this range, 
	 * then the first range is is the same range as this range, and the second range is null.
	 * <p>
	 * If the given address has a different version than this, then both returned ranges is null.
	 * 
	 * @param other
	 * @return
	 */
	public IPAddressSeqRange[] split(IPAddress other) {
		IPAddress lower = getLower();
		if(!versionsMatch(lower, other)) {
			return createArray(2);
		}
		if(compareLowerValues(lower, other) < 0) {
			IPAddress upper = getUpper();
			if(compareLowerValues(upper, other) >= 0) { // l ol u
				IPAddress otherLower = other.withoutPrefixLength().getLower();
				IPAddressSeqRange first = create(lower, otherLower.decrement());
				IPAddressSeqRange second = create(otherLower, upper);
				return createDoubleArray(first, second);
			}
			// l u ol
			return createDouble(false);
		}
		// ol l u
		return createDouble(true);
	}
	
	/**
	 * Same as split, but returns only the lower range.
	 * @param other
	 * @return
	 */
	public IPAddressSeqRange lowerFromSplit(IPAddress other) {
		IPAddress lower = getLower();
		if(!versionsMatch(lower, other)) {
			return null;
		}
		if(compareLowerValues(lower, other) < 0) {
			if(compareLowerValues(getUpper(), other) >= 0) { // l ol u
				return lowerSplit(other);
			}
			// l u ol
			return this;
		}
		// ol l u
		return null;
	}

	IPAddressSeqRange lowerSplit(IPAddress other) {
		return create(getLower(), other.withoutPrefixLength().decrement());
	}
	
	/**
	 * Same as split, but returns only the upper range.
	 * @param other
	 * @return
	 */
	public IPAddressSeqRange upperFromSplit(IPAddress other) {
		IPAddress lower = getLower();
		if(!versionsMatch(lower, other)) {
			return null;
		}
		if(compareLowerValues(lower, other) < 0) {
			if(compareLowerValues(getUpper(), other) >= 0) { // l ol u
				return upperSplit(other);
			}
			// l u ol
			return null;
		}
		// ol l u
		return this;
	}
	
	IPAddressSeqRange upperSplit(IPAddress other) {
		return create(other.withoutPrefixLength().getLower(), getUpper());
	}

	@Override
	public IPAddressSeqRangeList intoSequentialRangeList() {
		return createSingleList(this);
	}

	private IPAddressSeqRange[] createSingleThis() {
		IPAddressSeqRange arr[] = createArray(1);
		arr[0] = this;
		return arr;
	}

	private IPAddressSeqRange[] createEmptyArray() {
		return createArray(0);
	}

	private IPAddressSeqRange[] createSingleArray(IPAddressSeqRange rng) {
		IPAddressSeqRange arr[] = createArray(1);
		arr[0] = rng;
		return arr;
	}

	private IPAddressSeqRange[] createDoubleArray(IPAddressSeqRange rng1, IPAddressSeqRange rng2) {
		IPAddressSeqRange arr[] = createArray(2);
		arr[0] = rng1;
		arr[1] = rng2;
		return arr;
	}

	private IPAddressSeqRange[] createDouble(boolean asUpper) {
		IPAddressSeqRange arr[] = createArray(2);
		arr[asUpper ? 1 : 0] = this;
		return arr;
	}

	protected abstract IPAddressSeqRange create(IPAddress lower, IPAddress upper);

	protected abstract IPAddressSeqRange[] createArray(int capacity);

	protected abstract IPAddressSeqRangeList createList();
	
	private IPAddressSeqRangeList createSingleList(IPAddressSeqRange rng) {
		IPAddressSeqRangeList list = createList();
		list.ranges.add(rng);
		return list;
	}
	
	private IPAddressSeqRangeList createDoubleList(IPAddressSeqRange rng1, IPAddressSeqRange rng2) {
		IPAddressSeqRangeList list = createList();
		list.ranges.add(rng1);
		list.ranges.add(rng2);
		return list;
	}

	@Override
	public boolean containsPrefixBlock(int prefixLen) {
		IPAddressSection.checkSubnet(lower, prefixLen);
		int divCount = lower.getDivisionCount();
		int bitsPerSegment = lower.getBitsPerSegment();
		int i = getHostSegmentIndex(prefixLen, lower.getBytesPerSegment(), bitsPerSegment);
		if(i < divCount) {
			IPAddressSegment div = lower.getSegment(i);
			IPAddressSegment upperDiv = upper.getSegment(i);
			int segmentPrefixLength = IPAddressSection.getPrefixedSegmentPrefixLength(bitsPerSegment, prefixLen, i);
			if(!div.containsPrefixBlock(div.getSegmentValue(), upperDiv.getSegmentValue(), segmentPrefixLength)) {
				return false;
			}
			for(++i; i < divCount; i++) {
				div = lower.getSegment(i);
				upperDiv = upper.getSegment(i);
				//is full range?
				if(!div.includesZero() || !upperDiv.includesMax()) {
					return false;
				}
			}
		}
		return true;
	}
	
	@Override
	public boolean containsSinglePrefixBlock(int prefixLen) {
		IPAddressSection.checkSubnet(lower, prefixLen);
		int prevBitCount = 0;
		int divCount = lower.getDivisionCount();
		for(int i = 0; i < divCount; i++) {
			IPAddressSegment div = lower.getSegment(i);
			IPAddressSegment upperDiv = upper.getSegment(i);
			int bitCount = div.getBitCount();
			int totalBitCount = bitCount + prevBitCount;
			if(prefixLen >= totalBitCount) {
				if(!div.isSameValues(upperDiv)) {
					return false;
				}
			} else  {
				int divPrefixLen = Math.max(0, prefixLen - prevBitCount);
				if(!div.containsSinglePrefixBlock(div.getSegmentValue(), upperDiv.getSegmentValue(), divPrefixLen)) {
					return false;
				}
				for(++i; i < divCount; i++) {
					div = lower.getSegment(i);
					upperDiv = upper.getSegment(i);
					//is full range?
					if(!div.includesZero() || !upperDiv.includesMax()) {
						return false;
					}
				}
				return true;
			}
			prevBitCount = totalBitCount;
		}
		return true;
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

	/**
	 * Returns whether this sequential range spans from the zero address to itself.
	 */
	@Override
	public boolean isZero() {
		return includesZero() && !isMultiple();
	}

	/**
	 * Returns whether this sequential range's lower value is the zero address.
	 */
	@Override
	public boolean includesZero() {
		return getLower().isZero();
	}

	/**
	 * Returns whether this sequential range spans from the highest address, the address whose bits are all ones, to itself.
	 */
	@Override
	public boolean isMax() {
		return includesMax() && !isMultiple();
	}

	/**
	 * Returns whether this sequential range's upper value is the highest address, the address whose bits are all ones.
	 */
	@Override
	public boolean includesMax() {
		return getUpper().isMax();
	}
}
