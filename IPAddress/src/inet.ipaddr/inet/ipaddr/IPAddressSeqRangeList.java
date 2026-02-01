/*
 * Copyright 2026 Sean C Foley
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
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Spliterator;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.IntFunction;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import inet.ipaddr.format.IPAddressRange;
import inet.ipaddr.format.util.AddressComponentRangeSpliterator;
import inet.ipaddr.format.util.AddressTrie;
import inet.ipaddr.format.util.BigSpliterator;
import inet.ipaddr.format.validate.ChangeTracker;
import inet.ipaddr.format.validate.ChangeTracker.Change;
import inet.ipaddr.ipv4.IPv4AddressSeqRange;

/**
 * IPAddressSeqRangeList maintains a sorted list of sequential address ranges.  
 * It consists of a series of IPAddressSeqRange instances to describe a range of addresses that is non-sequential if more than one IPAddressSeqRange is in the list.  
 * As addresses are added and removed, the lost of IPAddressSeqRange instances are adjusted, 
 * so that it is always the minimal list of sequential ranges that includes all the specified addresses.
 * <p>
 * It is one of the efficient options provided by this library implementing {@link IPAddressCollection} to maintain sets of individual IP addresses, 
 * the other being {@link IPAddressContainmentTrie}.
 * <p>
 * Lookups of addresses, subnets, or sequential ranges the list are performed by binary search on the list of sequential address ranges.
 * <p>
 * Finding the address at a specific index in the list is performed by binary search on the sizes of the individual sequential ranges in the list.
 * <p>
 * The maximum number of addresses in the sequential range list is unlimited.  
 * However, the maximum number of disconnected sequential ranges is limited to the maximum size of an array, which is limited by the max value of an integer.
 * <p>
 * With some data-sets, this collection type will have better search performance than an {@link inet.ipaddr.format.util.IPAddressTrie} or {@link IPAddressContainmentTrie} due to improved cache coherency with many CPU processors.
 * <p>
 * {@link IPAddressCollection} equality with another instance of IPAddressCollection is determined by the contents of the collections.
 * An IPAddressSeqRangeList (or an instance of IPv4AddressSeqRangeList or IPv6AddressSeqRangeList) is equal to an {@link IPAddressContainmentTrie}  (or an instance of IPv4AddressContainmentTrie or IPv6AddressContainmentTrie) if the collections contain the same set of individual addresses.
 * <p>
 * An IPAddressSeqRangeList may contain either IPv6 addresses, or IPv4 addresses, but not both at the same time.
 * An attempt to add an address when the collection already contains an address of a different version will throw IllegalArgumentException.
 * However, once such a collection becomes empty again, it can accept either an IPv6 address or IPv4 address once more.
 * 
 * @author scfoley
 *
 * @param <E>
 */
public class IPAddressSeqRangeList implements IPAddressCollection<IPAddress, IPAddressSeqRange> {

	private static final long serialVersionUID = 1L;

	static final BigInteger LONG_MAX = BigInteger.valueOf(Long.MAX_VALUE);

	protected static String getMessage(String key) {
		return HostIdentifierException.getMessage(key);
	}

	@SuppressWarnings("serial")
	protected static class RangeList<E> extends ArrayList<E> {
		RangeList(int initialCapacity) {
			super(initialCapacity);
		}

		RangeList() {}

		 @Override
		protected void removeRange(int fromIndex, int toIndex) {
			super.removeRange(fromIndex, toIndex);
		}
	}

	protected RangeList<IPAddressSeqRange> ranges;

	// Caches sum of ranges sizes from range 0 upwards.  
	// Instrumental for better performance in the methods that search by index, and the getCount method.
	// If entry at index i exists, then it represents the total count of addresses in range 0, range 1, ..., range i.
	// It is cleared with calls to remove or add addresses.
	// It is regenerated with calls to getCount(int).
	protected transient RangeList<BigInteger> rangeSizes;

	protected ChangeTracker changeTracker;

	public IPAddressSeqRangeList() {
		this.changeTracker = new ChangeTracker();
		ranges = new RangeList<>(); 
		rangeSizes = new RangeList<>();
	}

	/**
	 * Constructs a new list with the given initial capacity for the number of disjointed ranges.
	 * 
	 * @param initialCapacity
	 */
	public IPAddressSeqRangeList(int initialCapacity) {
		this(new ChangeTracker(), initialCapacity);
	}

	IPAddressSeqRangeList(ChangeTracker changeTracker, int initialCapacity) {
		this.changeTracker = changeTracker;
		ranges = new RangeList<>(initialCapacity); 
		rangeSizes = new RangeList<>(initialCapacity);
	}

	@Override
	public boolean contains(IPAddress address) {
		return indexOfContainingSeqRange(address) >= 0;
	}

	/**
	 * If this list contains all the addresses in the given list, returns the index of the lowest sequential range in this list containing some elements of the given address or subnet.  
	 * <p>
	 * If this list does not contain all the addresses in the given subnet, a negative number is returned.
	 * If the given address or subnet contains addresses of a different version, then -1 is returned.
	 * Otherwise, the returned negative number is (-(insertion index) - 1), where the insertion index is the lowest index in this list where addresses would have to be inserted in order to contain the given address or subnet.
	 * <p>
	 * This means that the returned value will be >= 0 if and only if the ranges in the list contain the given address or subnet.
	 *
	 * @param address
	 * @return
	 */
	public int indexOfContainingSeqRange(IPAddress address) {
		if(ranges.size() == 0 || !versionsMatch(ranges.get(0).getLower(), address)) {
			return -1;
		}
		if(address.isSequential()) {
			return containsSequential(address, 0);
		}
		// an unusual case is non-sequential addresses fitting into separate ranges
		// eg 1.2.3-5.0 and the disjunct range being [1.2.3.0 -> 1.2.4.0], [1.2.5.0 -> 1.2.6.0]
		Iterator<? extends IPAddress> iterator = address.sequentialBlockIterator();
		IPAddress next = iterator.next();
		int result = containsSequential(next, 0);
		if(result >= 0) {
			for(int index = result; iterator.hasNext(); ) {
				next = iterator.next();
				index = containsSequential(next, index);
				if(index < 0) {
					return index;
				}
			}
		}
		return result;
	}

	/**
	 * Returns whether this list contains all addresses in the given containment trie.
	 * 
	 * @param trie
	 * @return
	 */
	public boolean contains(IPAddressContainmentTrieBase<? extends IPAddress, ?> trie) {
		return indexOfContainingSeqRange(trie) >= 0;
	}
	
	/**
	 * If this list contains all the addresses in the given containment trie, returns the index of the lowest sequential range in this list containing some elements of the containment trie.
	 * It returns 0 if both this list and the given containment trie are empty. 
	 * <p>
	 * If this list does not contain all the addresses in the given containment trie, a negative number is returned.
	 * If the given trie contains addresses of a different version, then -1 is returned.
	 * Otherwise, the returned negative number is (-(insertion index) - 1), where the insertion index is the lowest index in this list where addresses would have to be inserted in order to contain the given containment trie.
	 * <p>
	 * This means that the returned value will be >= 0 if and only if the ranges in the list contain the addresses in the given containment trie.
	 *
	 * @param address
	 * @return
	 */
	public int indexOfContainingSeqRange(IPAddressContainmentTrieBase<? extends IPAddress, ?> trie) {
		return indexOfContainingSeqRange(trie.trie);
	}

	/**
	 * Returns whether this list contains all added addresses and added prefix blocks in the given trie.
	 * 
	 * @param trie
	 * @return
	 */
	public boolean contains(AddressTrie<? extends IPAddress> trie) {
		return indexOfContainingSeqRange(trie) >= 0;
	}

	/**
	 * If this list contains all the added addresses and the added prefix blocks in the given trie, returns the index of the lowest sequential range in this list containing some elements of the trie.
	 * It returns 0 if both this list and the given trie are empty. 
	 * <p>
	 * If this list does not contain all the addresses in the given trie, a negative number is returned.
	 * If the given trie contains addresses of a different version, then -1 is returned.
	 * Otherwise, the returned negative number is (-(insertion index) - 1), where the insertion index is the lowest index in this list where addresses would have to be inserted in order to contain the given trie.
	 * <p>
	 * This means that the returned value will be >= 0 if and only if the ranges in the list contain the addresses in the given trie.
	 *
	 * @param address
	 * @return
	 */
	public int indexOfContainingSeqRange(AddressTrie<? extends IPAddress> trie) {
		if(ranges.size() == 0) {
			return trie.isEmpty() ? 0 : -1;
		}
		// this iterator cannot be the collection iterator which goes by individual address, it must be the enclosed trie's iterator
		Iterator<? extends IPAddress> iterator = trie.iterator();
		IPAddress next = iterator.next();
		if(!versionsMatch(ranges.get(0).getLower(), next)) {
			return -1;
		}
		int result = containsSequential(next, 0);
		if(result >= 0) {
			for(int index = result; iterator.hasNext(); ) {
				next = iterator.next();
				index = containsSequential(next, index);
				if(index < 0) {
					return index;
				}
			}
		}
		return result;
	}

	public boolean contains(IPAddressSeqRangeList list) {
		return indexOfContainingSeqRange(list) >= 0;
	}

	/**
	 * If this list contains all the addresses in the given list, this returns the index of the lowest sequential range in this list containing some elements of the given sequential range list,  
	 * If the given list is empty, then 0 is returned.
	 * <p>
	 * If this list does not contain all the addresses in the given list, a negative number is returned.
	 * If the given list contains addresses of a different version, then -1 is returned.
	 * Otherwise, the returned negative number is (-(insertion index) - 1), where the insertion index is the lowest index in this list where addresses would have to be inserted in order to contain the given list.
	 * <p>
	 * This means that the returned value will be >= 0 if and only if the ranges in the list contain the given list.
	 *
	 * @param address
	 * @return
	 */
	public int indexOfContainingSeqRange(IPAddressSeqRangeList list) {
		int otherRangeSize = list.ranges.size();
		if(otherRangeSize == 0) {
			return 0;
		} else if(ranges.size() == 0 || !versionsMatch(ranges.get(0).getLower(), list.getSeqRange(0).getLower())) {
			return -1;
		}
		IPAddressSeqRange other = list.getSeqRange(0);
		int result = containsSequential(other, 0);
		if(result >= 0) {
			for(int i = 1, lowerIndex = result; i < otherRangeSize; i++) {
				other = list.getSeqRange(i);
				lowerIndex = containsSequential(other, lowerIndex);
				if(lowerIndex < 0) {
					return lowerIndex;
				}
			}
		}
		return result;
	}

	@Override
	public boolean contains(IPAddressSeqRange seqRange) {
		return indexOfContainingSeqRange(seqRange) >= 0;
	}

	/**
	 * If this list contains the given sequential range, returns the index of the sequential range in this list containing the given sequential range.
	 * <p>
	 * If this list does not contain the given sequential range, a negative number is returned.
	 * If the given list contains addresses of a different version, then -1 is returned.
	 * Otherwise, the returned negative number is (-(insertion index) - 1), where the insertion index is the lowest index in this list where addresses from the given sequential range would have to be inserted in order to contain the given sequential range.
	 * <p>
	 * This means that the returned value will be >= 0 if and only if a range in the list contain the given sequential range.
	 *
	 * @param address
	 * @return
	 */
	public int indexOfContainingSeqRange(IPAddressSeqRange seqRange) {
		if(ranges.size() == 0 || !versionsMatch(ranges.get(0), seqRange)) {
			return -1;
		}
		return containsSequential(seqRange, 0);
	}

	// negative value means not contains, positive value gives the index of the containing sequential range
	private int containsSequential(IPAddressSeqRange seqRange, int startIndex) { 
		IPAddress lower = seqRange.getLower();
		int lowerIndex = binarySearchLower(startIndex, lower); 
		if(lowerIndex < 0) {
			return lowerIndex;
		}
		if(compareUpperValues(seqRange.getUpper(), ranges.get(lowerIndex).getUpper()) <= 0) {
			return lowerIndex;
		}
		return -(lowerIndex + 1);
	}

	// negative value means not contains, positive value gives the index of the containing sequential range
	private int containsSequential(IPAddress addr, int startIndex) { 
		int lowerIndex = binarySearchLower(startIndex, addr); 
		if(lowerIndex < 0) {
			return lowerIndex;
		}
		if(!addr.isMultiple() || compareUpperValues(addr, ranges.get(lowerIndex).getUpper()) <= 0) {
			return lowerIndex;
		}
		return -(lowerIndex + 1);
	}	

	@Override
	public boolean overlaps(IPAddressSeqRange seqRange) {
		return indexOfOverlappingSeqRange(seqRange) >= 0;
	}

	/**
	 * If this list overlaps with the given sequential range, this returns the index of the lowest sequential range in this list overlapping the given sequential range.  
	 * <p>
	 * If this list does not overlap with the given sequential range, a negative number is returned.
	 * If the given sequential range contains addresses that are a different version from those in this list, then -1 is returned.
	 * Otherwise, the returned negative number is (-(insertion index) - 1), where the insertion index is the lowest index in this list where addresses could be inserted to result in overlap.
	 * <p>
	 * This means that the returned value will be >= 0 if and only if the ranges in this list overlap with the given sequential range.
	 *
	 * @param address
	 * @return
	 */
	public int indexOfOverlappingSeqRange(IPAddressSeqRange seqRange) {
		return overlapsSequential(seqRange, 0, seqRange.getLower(), seqRange.getUpper());
	}

	@Override
	public boolean overlaps(IPAddress address) {
		return indexOfOverlappingSeqRange(address) >= 0;
	}

	/**
	 * If this list overlaps with the given address or subnet, this returns the index of the lowest sequential range in this list overlapping addresses from the given address or subnet.  
	 * <p>
	 * If this list does not overlap with the given address or subnet, a negative number is returned.
	 * If the given address or subnet is a different version, then -1 is returned.
	 * Otherwise, the returned negative number is (-(insertion index) - 1), where the insertion index is the lowest index in this list where addresses could be inserted to result in overlap.
	 * <p>
	 * This means that the returned value will be >= 0 if and only if the ranges in this list overlap with the given address or subnet.
	 *
	 * @param address
	 * @return
	 */
	public int indexOfOverlappingSeqRange(IPAddress address) {
		if(ranges.size() == 0 || !versionsMatch(ranges.get(0).getLower(), address)) {
			return -1;
		} else if(address.isSequential()) {
			return overlapsSequential(address);
		}
		// an unusual case is non-sequential addresses fitting into separate ranges
		// eg 1.2.3-5.0 and the disjunct range being [1.2.3.0 -> 1.2.4.0], [1.2.5.0 -> 1.2.6.0]
		Iterator<? extends IPAddress> iterator = address.sequentialBlockIterator();
		IPAddress next = iterator.next();
		int result = overlapsSequential(next);
		if(result < 0) {
			for(int index = result; iterator.hasNext(); ) {
				index = -(index + 1);
				next = iterator.next();
				index = overlapsSequential(next, index, next, next);
				if(index >= 0) {
					return index;
				} else if(index >= ranges.size()) {
					break;
				}
			} 
		}
		return result;
	}

	private int overlapsSequential(IPAddress address) {
		return overlapsSequential(address, 0, address, address);
	}

	public boolean overlaps(IPAddressSeqRangeList list) {
		if(ranges.size() == 0 || list.ranges.size() == 0 || !versionsMatch(ranges.get(0).getLower(), list.getSeqRange(0).getLower())) {
			return false;
		}
		// reduce the number of binary searches by iterating over the smaller range list
		int thisCount = getSeqRangeCount();
		int otherCount = list.getSeqRangeCount();
		if(thisCount < otherCount) {
			return list.doOverlaps(this) >= 0;
		}
		return doOverlaps(list) >= 0;
	}

	/**
	 * If this list overlaps with addresses in the given list, this returns the index of the lowest sequential range in this list overlapping some elements of the given sequential range list.  
	 * <p>
	 * If this list does not overlap with the given list, a negative number is returned.
	 * If the given list is empty or contains addresses of a different version, then -1 is returned.
	 * Otherwise, the returned negative number is (-(insertion index) - 1), where the insertion index is the lowest index in this list where addresses could be inserted to result in overlap.
	 * <p>
	 * This means that the returned value will be >= 0 if and only if the ranges in this list overlap with the given list.
	 *
	 * @param address
	 * @return
	 */
	public int indexOfOverlappingSeqRange(IPAddressSeqRangeList list) {
		if(ranges.size() == 0 || list.ranges.size() == 0 || !versionsMatch(ranges.get(0).getLower(), list.getSeqRange(0).getLower())) {
			return -1;
		}
		return doOverlaps(list);
	}

	private int doOverlaps(IPAddressSeqRangeList smallerList) {
		// Check each IPAddressSeqRange in smallerList for overlap.
		// We take advantage of the ordering of the list of IPAddressSeqRanges,
		// for each new binary search, the lower end can be the index returned by the previous search
		IPAddressSeqRange other = smallerList.getSeqRange(0);
		int result = overlapsSequential(other, 0, other.getLower(), other.getUpper());
		if(result < 0) {
			for(int i = 0, lowerIndex = result; i < smallerList.getSeqRangeCount(); i++) {
				lowerIndex = -(lowerIndex + 1);
				other = smallerList.getSeqRange(i);
				lowerIndex = overlapsSequential(other, lowerIndex, other.getLower(), other.getUpper());
				if(lowerIndex >= 0) {
					return lowerIndex; 
				} else if(lowerIndex >= ranges.size()) {
					break;
				}
			}
		}
		return result;
	}

	// lowerComp returns an address whose lower values can be used to represent the lower values of the range
	// upperComp returns an address whose upper values can be used to represent the upper values of the range
	// In practice, this means that for a subnet, the subnet itself can be used,
	// but for a sequential range, the lower or upper range boundary must be used.
	//
	// If there is overlap, returns the non-negative index where the lowest overlap occurs
	// If no overlap, returns the index where the given range would be inserted
	private int overlapsSequential(IPAddressRange rng, int lowerBound, IPAddress lowerCompare, IPAddress upperCompare) {
		int lowerIndex = binarySearchLower(lowerBound, lowerCompare);
		if(lowerIndex < 0) {
			if(rng.isMultiple()) {
				int lowerIndexAdjusted = -(lowerIndex + 1);
				int upperIndex = binarySearchUpper(lowerIndexAdjusted, upperCompare);
				if(upperIndex >= 0 || upperIndex != lowerIndex) {
					lowerIndex = lowerIndexAdjusted;
				}
			}
		}
		return lowerIndex;
	}

	/**
	 * Returns the highest address in the collection strictly less than all addresses in the given address or subnet.
	 * 
	 * @param addr
	 * @return
	 */
	@Override
	public IPAddress lower(IPAddress addr) {
		if(isEmpty() || !versionsMatch(getLower(), addr)) {
			return null;
		}
		int index = binarySearchLower(addr);
		if(index < 0) {
			// not in the list
			int indexAdjusted = -(index + 1);
			if(indexAdjusted == 0) {
				return null;
			}
			return ranges.get(indexAdjusted - 1).getUpper();
		}
		// is in the range list
		IPAddressSeqRange existingRange = ranges.get(index);
		if(compareLowerValues(existingRange.getLower(), addr) == 0) {
			// lowest value in the range
			if(index == 0) {
				return null;
			}
			return ranges.get(index - 1).getUpper();
		}
		return addr.decrement();
	}

	/**
	 * Returns the highest address in the collection less than or equal to the lowest address in the given address or subnet.
	 * 
	 * @param addr
	 * @return
	 */
	@Override
	public IPAddress floor(IPAddress addr) {
		if(isEmpty() || !versionsMatch(getLower(), addr)) {
			return null;
		}
		int index = binarySearchLower(addr);
		if(index < 0) {
			// not in the list
			int indexAdjusted = -(index + 1);
			if(indexAdjusted == 0) {
				return null;
			}
			return ranges.get(indexAdjusted - 1).getUpper();
		}
		// is in the range list, just return it
		return addr.withoutPrefixLength().getLower(); 
	}

	/**
	 * Returns the lowest address in the collection greater than or equal to the highest address in the given address or subnet.
	 * 
	 * @param addr
	 * @return
	 */
	@Override
	public IPAddress ceiling(IPAddress addr) {
		if(isEmpty() || !versionsMatch(getLower(), addr)) {
			return null;
		}
		int index = binarySearchUpper(addr);
		if(index < 0) {
			// not in the list
			int indexAdjusted = -(index + 1);
			if(indexAdjusted == ranges.size()) {
				return null;
			}
			return ranges.get(indexAdjusted).getLower();
		}
		// is in the range list, just return it
		return addr.withoutPrefixLength().getUpper();
	}

	/**
	 * Returns the lowest address in the collection strictly greater than all addresses in the given address or subnet.
	 * 
	 * @param addr
	 * @return
	 */
	@Override
	public IPAddress higher(IPAddress addr) {
		if(isEmpty() || !versionsMatch(getLower(), addr)) {
			return null;
		}
		int index = binarySearchUpper(addr);
		if(index < 0) {
			// not in the list
			int indexAdjusted = -(index + 1);
			if(indexAdjusted == ranges.size()) {
				return null;
			}
			return ranges.get(indexAdjusted).getLower();
		}
		// is in the range list
		IPAddressSeqRange existingRange = ranges.get(index);
		if(compareUpperValues(existingRange.getUpper(), addr) == 0) {
			// highest value in the range
			int nextRangeIndex = index + 1;
			if(nextRangeIndex == ranges.size()) {
				return null;
			}
			return ranges.get(nextRangeIndex).getLower();
		}
		return addr.incrementBoundary();
	}

	/**
	 * Returns a new IPAddressSeqRangeList comprising all the addresses not contained in this list.
	 * <p>
	 * If this list is empty and is not restricted to a single version like its subclasses,
	 * then the IP version is ambiguous, so the complement cannot be determined in that case.  In that case, null is returned.
	 * 
	 * @return
	 */
	public IPAddressSeqRangeList complementIntoList() {
		if(isEmpty()) {
			return null;
		}
		IPAddress zero = null, max = null;
		IPAddressSeqRange firstRange = ranges.get(0);
		if(!firstRange.includesZero()) {
			zero = firstRange.getLower().getNetwork().getNetworkMask(0, false);
		}
		IPAddressSeqRange lastRange = ranges.get(ranges.size() - 1);
		if(!lastRange.includesMax()) {
			IPAddress addr = lastRange.getLower();
			max = addr.getNetwork().getNetworkMask(addr.getBitCount(), false);
		}
		IPAddressSeqRangeList result = new IPAddressSeqRangeList();
		complement(result, zero, max);
		return result;
	}

	protected void complement(IPAddressSeqRangeList newList, IPAddress zero, IPAddress max) { 
		if(isEmpty()) {
			newList.add(zero.spanWithRange(max)); 
		} else {
			RangeList<IPAddressSeqRange> newRanges = newList.ranges;
			IPAddressSeqRange previous = ranges.get(0);
			if(!previous.includesZero()) {
				IPAddress first = previous.getLower();
				newRanges.add(previous.create(zero, first.decrement()));
			}
			for(int i = 1; i < ranges.size(); i++) {
				IPAddressSeqRange rng = ranges.get(i);
				newRanges.add(rng.create(previous.getUpper().increment(), rng.getLower().decrement()));
				previous = rng;
			}
			if(!previous.includesMax()) {
				IPAddress last = previous.getUpper();
				newRanges.add(previous.create(last.increment(), max));
			}
		}
	}

	/**
	 * Produces a new IPAddressSeqRangeList that has all the addressed in the given list removed from this list.
	 * Neither this list nor the given list are altered, instead a new list is created and returned.
	 * @param list
	 * @return
	 */
	public IPAddressSeqRangeList removeIntoList(IPAddressSeqRangeList list) {
		IPAddressSeqRangeList result = new IPAddressSeqRangeList();
		remove(list, result);
		return result;
	}

	protected void remove(IPAddressSeqRangeList list, IPAddressSeqRangeList result) {
		if(ranges.size() > 0) { // something to remove
			if(list.ranges.size() == 0 || !versionsMatch(ranges.get(0), list.ranges.get(0))) { // not removing anything
				result.ranges.addAll(ranges);
				result.rangeSizes.addAll(rangeSizes);
			} else {
				removeRanges(list, result);
			}
		}
	}

	private void removeRanges(IPAddressSeqRangeList list, IPAddressSeqRangeList result) {
		RangeList<IPAddressSeqRange> resultList = result.ranges;
		int currentIndex = 0;
		PendingRange pending = new PendingRange();
		for(int i = 0; i < list.getSeqRangeCount(); i++) {
			IPAddressSeqRange otherRange = list.getSeqRange(i);
			currentIndex = remove(otherRange, resultList, pending, currentIndex);
			if(currentIndex >= ranges.size()) {
				break;
			}
		}
		// If there is a pending range, then the range at upper index is in the pending range,
		// so the ranges ar upperIndex + 1 must be added after the pending range.
		// Otherwise the ranges at upperIndex must be added.
		if(!pending.isEmpty()) {
			currentIndex++;
			resultList.add(pending.from.create(pending.lower, pending.upper));
			pending.clear();
		}
		if(currentIndex < ranges.size()) {
			resultList.addAll(ranges.subList(currentIndex, ranges.size()));
		}	
	}

	private int remove(IPAddressSeqRange seqRange, RangeList<IPAddressSeqRange> result, PendingRange pending, int index) {
		IPAddress lower = seqRange.getLower(), upper = seqRange.getUpper();
		int lowerIndex = binarySearchLower(index, lower);
		boolean splitLower = lowerIndex >= 0;
		if(!splitLower) {
			lowerIndex = -(lowerIndex + 1);
		}
		int upperIndex;
		boolean splitUpper;
		if(seqRange.isMultiple() && lowerIndex != ranges.size()) {
			upperIndex = binarySearchLower(lowerIndex, seqRange.getUpper());
			splitUpper = upperIndex >= 0;
			if(!splitUpper) {
				upperIndex =  -(upperIndex + 1);
			}
		} else {
			upperIndex = lowerIndex;
			splitUpper = splitLower;
		}

		IPAddressSeqRange existingRange = null;
		if(pending.isEmpty()) {
			// add ranges following the last range and preceding this one
			if(lowerIndex > index) {
				result.addAll(ranges.subList(index, lowerIndex));
			}
			if(splitLower) {
				existingRange = ranges.get(lowerIndex);
				splitLower = compareLowerValues(existingRange.getLower(), lower) != 0;
			}
		} else {
			// check if the pending range overlaps with this one, creating a large unified pending range
			if(lowerIndex > pending.existingRangeUpperIndex) {
				// there is no overlap, add the pending range, and then add the succeeding ranges that precede this one
				result.add(pending.from.create(pending.lower, pending.upper));
				pending.clear();
				// at this time, index is the pending range upper index
				if(++index < lowerIndex) {
					result.addAll(ranges.subList(index, lowerIndex));
				} 
				if(splitLower) {
					existingRange = ranges.get(lowerIndex);
					splitLower = compareLowerValues(existingRange.getLower(), lower) != 0;
				}
			}
		}

		IPAddress existingUpperUpper = null;
		IPAddressSeqRange existingUpperRange = null;
		if(splitUpper) {
			existingUpperRange = ranges.get(upperIndex);
			existingUpperUpper = existingUpperRange.getUpper();
			if(compareLowerValues(existingUpperUpper, upper) == 0) {// see if upper matches the end of the range at upperIndex
				splitUpper = false;
				upperIndex++;
			}
		}

		if(lowerIndex < upperIndex) { // spans at least one existing range
			if(!pending.isEmpty()) {
				// came in with: y1     x1  removed x2  pending  y2   
				// here we have: y1     x1  removed x2  pending lower  y2  upper
				// we want to add x2 to lower to result
				result.add(pending.from.create(pending.lower, lower.decrement()));
				pending.clear();
			} else if(splitLower) {
				result.add(existingRange.lowerSplit(lower));
			}
			if(splitUpper) {
				// new pending
				pending.from = seqRange;
				pending.lower = upper.increment();
				pending.existingRangeUpperIndex = pending.lowerIndex = upperIndex;
				pending.upper = existingUpperUpper;
			}
		} else { // spans 0 or 1 existing range
			//IPAddress existingUpper = existingRange.getUpper();
			if(!pending.isEmpty()) {
				// came in with: y1     x1  removed x2  pending  y2   
				// here we have: y1     x1  removed x2  pending lower upper y2  
				// we want to add x2 to lower to result
				result.add(pending.from.create(pending.lower, lower.decrement()));
				// still pending in the same range
				pending.lower = seqRange.getUpper().increment();
			} else {
				if(splitLower) {
					result.add(existingRange.lowerSplit(lower));
				}
				if(splitUpper) {
					// we want to set pending to upper to y2
					pending.from = seqRange;
					pending.lower = seqRange.getUpper().increment();
					pending.existingRangeUpperIndex = pending.lowerIndex = lowerIndex;
					pending.upper = existingUpperRange.getUpper();
				} // else range does not intersect with anything
			}
		}
		return upperIndex;
	}

	/**
	 * Produces a new IPAddressSeqRangeList that is the intersection of this list with the given list.
	 * Neither this list nor the given list are altered, instead a new intersection list is created and returned.
	 * @param list
	 * @return
	 */
	public IPAddressSeqRangeList intersectIntoList(IPAddressSeqRangeList list) {
		IPAddressSeqRangeList result = new IPAddressSeqRangeList();
		intersect(list, result);
		return result;
	}

	protected void intersect(IPAddressSeqRangeList list, IPAddressSeqRangeList result) {
		if(ranges.size() == 0 || list.ranges.size() == 0) {
			return;
		} else if(!versionsMatch(ranges.get(0), list.ranges.get(0))) {
			return;
		}
		int thisCount = getSeqRangeCount();
		int otherCount = list.getSeqRangeCount();
		if(thisCount < otherCount) {
			list.intersectSmaller(this, result);
		} else {
			intersectSmaller(list, result);
		}
	}

	private void intersectSmaller(IPAddressSeqRangeList list, IPAddressSeqRangeList result) {
		RangeList<IPAddressSeqRange> resultList = result.ranges;
		int currentIndex = 0;
		for(int i = 0; i < list.getSeqRangeCount(); i++) {
			IPAddressSeqRange otherRange = list.getSeqRange(i);
			currentIndex = intersect(otherRange, resultList, currentIndex);
			if(currentIndex >= ranges.size()) {
				break;
			}
		}
	}

	private int intersect(IPAddressSeqRange seqRange, RangeList<IPAddressSeqRange> result, int index) {
		int lowerIndex = binarySearchLower(index, seqRange.getLower());
		boolean lowerIntersects = lowerIndex >= 0;
		if(!lowerIntersects) {
			lowerIndex = -(lowerIndex + 1);
		}
		int upperIndex;
		boolean upperIntersects;
		if(seqRange.isMultiple() && lowerIndex != ranges.size()) {
			IPAddress upper = seqRange.getUpper();
			upperIndex = binarySearchLower(lowerIndex, upper);
			upperIntersects = upperIndex >= 0;
			if(!upperIntersects) {
				upperIndex =  -(upperIndex + 1);
			}
		} else {
			upperIndex = lowerIndex;
			upperIntersects = lowerIntersects;
		}

		if(lowerIndex < upperIndex) { // spans at least one existing range
			if(lowerIntersects) {
				// add part of the lower intersecting range
				result.add(ranges.get(lowerIndex).upperSplit(seqRange.getLower()));
				if(++lowerIndex < upperIndex) {
					result.addAll(ranges.subList(lowerIndex, upperIndex));
				}
			} else {
				result.addAll(ranges.subList(lowerIndex, upperIndex));
			}
			if(upperIntersects) {
				result.add(seqRange.upperSplit(ranges.get(upperIndex).getLower()));
			} 
		} else { // spans 0 or 1 existing range
			if(lowerIntersects) { // intersects with the one range
				// we know upperIntersects is true because upperIndex points to the same range,
				// so the both lower and upper is contained in the range at lowerIndex,
				// so the intersection is the exact same range
				result.add(seqRange);
			} else if(upperIntersects) { // intersects partially
				result.add(seqRange.upperSplit(ranges.get(upperIndex).getLower()));
			} // else no intersection
		}
		return upperIndex;
	}

	private static class PendingRange {
		IPAddressSeqRange from;
		IPAddress lower, upper;
		int lowerIndex, existingRangeUpperIndex;

		void clear() {
			lower = upper = null;
			from = null;
			lowerIndex = existingRangeUpperIndex = -1;
		}

		boolean isEmpty() {
			return lower == null;
		}

		@Override
		public String toString() {
			if(isEmpty()) {
				return "<empty>";
			}
			return IPAddressSeqRange.toString(
					lower, IPAddress::toCanonicalString, 
					IPAddressSeqRange.DEFAULT_RANGE_SEPARATOR, 
					upper, IPAddress::toCanonicalString);
		}
	}

	private static int compareLowerValues(IPAddress one, IPAddress two) {
		return AddressComparator.compareSegmentValues(false, one.getSection(), two.getSection());
	}

	private static int compareUpperValues(IPAddress one, IPAddress two) {
		return AddressComparator.compareSegmentValues(true, one.getSection(), two.getSection());
	}

	/**
	 * Creates a list that was all addresses in this list and the provided list.
	 * 
	 * @param list
	 * @return
	 */
	public IPAddressSeqRangeList joinIntoList(IPAddressSeqRangeList list) {
		if(list.getSeqRangeCount() == 0) {
			return clone();
		} else if(ranges.size() != 0 && !versionsMatch(ranges.get(0), list.ranges.get(0))) {
			throw new IllegalArgumentException(getMessage("ipaddress.error.mismatched.bit.size"));
		}
		IPAddressSeqRangeList result = new IPAddressSeqRangeList();
		join(list, result);
		return result;
	}

	protected void join(IPAddressSeqRangeList list, IPAddressSeqRangeList result) {
		if(ranges.size() == 0) {
			result.ranges.addAll(list.ranges);
			result.rangeSizes.addAll(list.rangeSizes);
		} else {
			int thisCount = getSeqRangeCount();
			int otherCount = list.getSeqRangeCount();
			if(thisCount < otherCount) {
				list.joinSmaller(this, result);
			} else {
				joinSmaller(list, result);
			}
		}
	}

	private void joinSmaller(IPAddressSeqRangeList list, IPAddressSeqRangeList result) {
		RangeList<IPAddressSeqRange> resultList = result.ranges;
		int currentIndex = 0;
		PendingRange pending = new PendingRange();
		for(int i = 0; i < list.getSeqRangeCount(); i++) {
			IPAddressSeqRange seqRange = list.getSeqRange(i);
			currentIndex = join(seqRange, resultList, pending, currentIndex);
		}
		// If there is a pending range, then the range at upper index is in the pending range,
		// so the ranges at upperIndex + 1 must be added after the pending range.
		// Otherwise the ranges at upperIndex must be added.
		if(!pending.isEmpty()) {
			currentIndex++;
			resultList.add(pending.from.create(pending.lower, pending.upper));
			pending.clear();
		}
		if(currentIndex < ranges.size()) {
			resultList.addAll(ranges.subList(currentIndex, ranges.size()));
		}
	}

	private int join(IPAddressSeqRange seqRange, RangeList<IPAddressSeqRange> result, PendingRange pending, int index) {
		int lowerIndex = binarySearchLower(index, seqRange.getLower());
		boolean extendLower = lowerIndex < 0;
		if(extendLower) {
			lowerIndex = -(lowerIndex + 1);
		}
		int upperIndex;
		boolean extendUpper;
		if(seqRange.isMultiple() && lowerIndex != ranges.size()) {
			upperIndex = binarySearchLower(lowerIndex, seqRange.getUpper());
			extendUpper = upperIndex < 0;
			if(extendUpper) {
				upperIndex = -(upperIndex + 1);
			}
		} else {
			upperIndex = lowerIndex;
			extendUpper = extendLower;
		}
		// check if the lower address is 1 above the upper address of the previous range
		if(extendLower && lowerIndex > 0 && compareLowerValues(ranges.get(lowerIndex - 1).getUpper().increment(), seqRange.getLower())== 0) {
			lowerIndex--;
			extendLower = false;
		}
		// check if the upper address is 1 below the lower address of the next range
		if(extendUpper && upperIndex < ranges.size()) {
			extendUpper = compareLowerValues(ranges.get(upperIndex).getLower(), seqRange.getUpper().increment()) != 0;
		}

		if(pending.isEmpty()) {
			// add ranges following the last range and preceding this one
			if(lowerIndex > index) {
				result.addAll(ranges.subList(index, lowerIndex));
			}
		} else {
			// check if the pending range overlaps with this one, creating a large unified range
			if(lowerIndex == pending.existingRangeUpperIndex) {
				lowerIndex = pending.lowerIndex;
			} else {
				// there is no overlap, add the pending range, and then add the succeeding ranges that precede this one
				result.add(pending.from.create(pending.lower, pending.upper));
				pending.clear();
				// at this time, index is the pending range upper index
				if(++index < lowerIndex) {
					result.addAll(ranges.subList(index, lowerIndex));
				} 
			}
		}

		boolean noPending = pending.isEmpty();
		if(lowerIndex < upperIndex) { // spans at least one existing range
			IPAddress newLower;
			IPAddressSeqRange existingRange = ranges.get(lowerIndex);
			if(!noPending) {
				newLower = pending.lower;
			} else if(extendLower) {
				newLower = seqRange.getLower();
			} else {
				newLower = existingRange.getLower();
			}
			if(extendUpper) {
				result.add(existingRange.create(newLower, seqRange.getUpper()));
				if(!noPending) {
					pending.clear();
				}
			} else { 
				// the range ends with the existing range, 
				// which may overlap the next range to check,
				// so we create a pending range to see if it does
				//
				// note: the pending range is unnecessary if the upper address of the existing range does not exceed seqRange.getUpper(), but checking that is not worth the bother 
				if(noPending) {
					pending.from = seqRange;
					pending.lower = newLower;
					pending.lowerIndex = lowerIndex;
				}
				pending.existingRangeUpperIndex = upperIndex;
				pending.upper = ranges.get(upperIndex).getUpper();;
			}
		} else { // spans 0 or 1 existing range
			if(noPending) {
				if(extendLower) {
					if(extendUpper) { // spans no existing range, just add it
						result.add(seqRange);
					} else { // spans the single range at lowerIndex
						// the range ends with the existing range, 
						// which may overlap the next range to check,
						// so we create a pending range to see if it does
						pending.from = seqRange;
						pending.lower = seqRange.getLower();
						pending.lowerIndex = pending.existingRangeUpperIndex = lowerIndex;
						pending.upper = ranges.get(lowerIndex).getUpper();
					}
				} else { 
					// the range is contained in the range at lowerIndex
					// the range ends with the existing range, 
					// which may overlap the next range to check,
					// so we create a pending range to see if it does
					//
					// note: the pending range is unnecessary if the upper address of the existing range does not exceed seqRange.getUpper(), but checking that is not worth the bother 
					IPAddressSeqRange existingRange = ranges.get(lowerIndex);
					pending.from = seqRange;
					pending.lower = existingRange.getLower();
					pending.lowerIndex = pending.existingRangeUpperIndex = lowerIndex;
					pending.upper = existingRange.getUpper();
				}
			} // else we are contained in the same pending range
		}
		return upperIndex;
	}

	/**
	 * Adds the address, if not already in the list.
	 * <p>
	 * If the address version does match existing addresses in the list, the address is not added.
	 * <p>
	 * Returns whether addresses were added, whether the list was changed.
	 * 
	 * @param address
	 * @return
	 */
	@Override
	public boolean add(IPAddress address) {
		if(ranges.size() == 0) {
			addAddressToEmptyList(address);
			return true;
		} else if(!versionsMatch(ranges.get(0), address)) {
			throw new IllegalArgumentException(getMessage("ipaddress.error.mismatched.bit.size"));
		}
		return doAdd(address);
	}

	protected void addAddressToEmptyList(IPAddress address) {
		if(address.isSequential()) {
			IPAddressSeqRange rng = address.coverWithSequentialRange();
			ranges.add(rng);
			rangeSizes.add(rng.getCount());
		} else {
			Iterator<? extends IPAddress> iterator = address.sequentialBlockIterator();
			BigInteger count = BigInteger.ZERO;
			do {
				IPAddressSeqRange rng = iterator.next().coverWithSequentialRange();
				ranges.add(rng);
				count = count.add(rng.getCount());
				rangeSizes.add(count);
			} while(iterator.hasNext());
		}
		changeTracker.changed();
	}

	protected boolean doAdd(IPAddress address) {
		if(address.isSequential()) {
			return addSequential(address, 0) >= 0;
		}
		boolean isChanged = false;
		Iterator<? extends IPAddress> iterator = address.sequentialBlockIterator();
		int startIndex = 0;
		do {
			startIndex = addSequential(iterator.next(), startIndex);
			if(startIndex >= 0) {
				isChanged = true;
			} else {
				startIndex = -(startIndex + 1);
			}
		} while(iterator.hasNext());
		return isChanged;
	}

	private int addSequential(IPAddress address, int startIndex) {
		return addSequential(address, address, address, startIndex);
	}

	/**
	 * Adds the sequential range, if not already in the list.
	 * <p>
	 * If the address version of the addresses in the range does match the version of existing addresses in the list, the range is not added.
	 * <p>
	 * Returns whether addresses in the range were added, whether the list was changed.
	 * 
	 * @param address
	 * @return
	 */
	@Override
	public boolean add(IPAddressSeqRange seqRange) {
		if(ranges.size() == 0) {
			addRangeToEmptyList(seqRange);
			return true;
		} else if(!versionsMatch(ranges.get(0), seqRange)) {
			throw new IllegalArgumentException(getMessage("ipaddress.error.mismatched.bit.size"));
		}
		return doAdd(seqRange);
	}

	protected void addRangeToEmptyList(IPAddressSeqRange seqRange) {
		ranges.add(seqRange);
		rangeSizes.add(seqRange.getCount());
		changeTracker.changed();
	}

	// called from this class and from subclasses
	protected boolean doAdd(IPAddressSeqRange seqRange) {
		return addSequential(seqRange, seqRange.getLower(), seqRange.getUpper(), 0) >= 0;
	}

	// returns true if the collection was changed
	private int addSequential(IPAddressRange rng, IPAddress lowerCompare, IPAddress upperCompare, int startIndex) { 
		int lowerIndex = binarySearchLower(startIndex, lowerCompare);
		boolean extendLower = lowerIndex < 0;
		if(extendLower) {
			lowerIndex = -(lowerIndex + 1);
		}
		int upperIndex;
		boolean extendUpper;
		if(rng.isMultiple() && lowerIndex != ranges.size()) {
			upperIndex = binarySearchUpper(lowerIndex, upperCompare);
			extendUpper = upperIndex < 0;
			if(extendUpper) {
				upperIndex = -(upperIndex + 1);
			}
		} else {
			upperIndex = lowerIndex;
			extendUpper = extendLower;
		}
		// check if the lower address is 1 above the upper address of the previous range
		if(extendLower && lowerIndex > 0 && compareLowerValues(ranges.get(lowerIndex - 1).getUpper().increment(), lowerCompare) == 0) {
			lowerIndex--;
			extendLower = false;
		}	
		// check if the upper address is 1 below the lower address of the next range
		if(extendUpper && upperIndex < ranges.size()) {
			extendUpper = compareUpperValues(ranges.get(upperIndex).getLower().decrement(), upperCompare) != 0;
		}
		if(lowerIndex < upperIndex) { // spans at least one existing range
			IPAddress newLower, newUpper;
			IPAddressSeqRange existingRange = ranges.get(lowerIndex);
			if(extendLower) {
				newLower = lowerCompare.withoutPrefixLength().getLower();
			} else {
				newLower = existingRange.getLower();
			}
			int nextUpperIndex;
			if(extendUpper) {
				newUpper = upperCompare.withoutPrefixLength().getUpper();
				nextUpperIndex = upperIndex;
			} else {
				newUpper = ranges.get(upperIndex).getUpper();
				nextUpperIndex = upperIndex + 1;
			}
			ranges.set(lowerIndex, existingRange.create(newLower, newUpper));
			int nextLowerIndex = lowerIndex + 1;
			if(nextLowerIndex < nextUpperIndex) {
				// remove the ranges from lower index inclusive to upper index exclusive
				ranges.removeRange(nextLowerIndex, nextUpperIndex);
				upperIndex -= nextUpperIndex - nextLowerIndex;
			}
		} else { // spans 0 or 1 existing range
			if(extendLower) {
				if(extendUpper) { // spans no existing range, insert the range
					ranges.add(lowerIndex, rng.coverWithSequentialRange());
				} else { // spans the single range at lowerIndex (which matches upperIndex)
					IPAddressSeqRange existingRange = ranges.get(upperIndex);
					IPAddress newLower = lowerCompare.withoutPrefixLength().getLower();
					ranges.set(lowerIndex, existingRange.create(newLower, existingRange.getUpper()));
				}
			} else {
				// nothing to do, the address is contained in the range at lowerIndex
				upperIndex = -(upperIndex + 1); // we've added something, make return value negative to indicate that
				return upperIndex;
			}
		}
		clearRangeSizesFrom(lowerIndex);
		changeTracker.changed();
		return upperIndex;
	}

	private void clearRangeSizesFrom(int index) {
		int size = rangeSizes.size();
		if(index < size) {
			rangeSizes.removeRange(index, size);
		}
	}

	/**
	 * Intersects this list with the given individual address or subnet.  
	 * Afterwards, this list will include only those addresses in both.
	 * 
	 * @param address
	 * @return true if the sequential list was altered by the intersection
	 */
	public boolean intersect(IPAddress address) {
		if(ranges.size() == 0) {
			return false;
		} else if(!versionsMatch(ranges.get(0), address)) {
			return false;
		}
		int startIndex = 0;
		boolean isChanged = false;
		if(address.isSequential()) {
			startIndex = intersectSequential(address, startIndex, true);
			isChanged = startIndex >= 0;
		} else {
			Iterator<? extends IPAddress> iterator = address.sequentialBlockIterator();
			boolean hasNext;
			do {
				IPAddress next = iterator.next();
				hasNext = iterator.hasNext();
				startIndex = intersectSequential(next, startIndex, !hasNext);
				if(!(isChanged = (startIndex >= 0))) {
					startIndex = -(startIndex + 1);
				}
				if(startIndex >= ranges.size()) {
					break;
				}
			} while(hasNext);
		}
		return isChanged;
	}

	private int intersectSequential(IPAddress address, int startIndex, boolean isLast) {
		return intersectSequential(address, address, address, startIndex, isLast);
	}

	/**
	 * Intersects this list with the given sequential range.  
	 * Afterwards, this list will include only those addresses in both.
	 * 
	 * @param address
	 * @return true if the sequential list was altered by the intersection
	 */
	public boolean intersect(IPAddressSeqRange seqRange) {
		if(ranges.size() == 0) {
			return false;
		} else if(!versionsMatch(ranges.get(0), seqRange)) {
			return false;
		}
		int startIndex = intersectSequential(seqRange, seqRange.getLower(), seqRange.getUpper(), 0, true);
		return startIndex >= 0;
	}

	private int intersectSequential(IPAddressRange rng, IPAddress lowerCompare, IPAddress upperCompare, int startIndex, boolean isLast) { 
		int lowerIndex = binarySearchLower(startIndex, lowerCompare);
		boolean lowerIntersects = lowerIndex >= 0;
		if(!lowerIntersects) {
			lowerIndex = -(lowerIndex + 1);
		}
		int upperIndex;
		boolean upperIntersects;
		if(rng.isMultiple() && lowerIndex != ranges.size()) {
			upperIndex = binarySearchUpper(lowerIndex, upperCompare);
			upperIntersects = upperIndex >= 0;
			if(!upperIntersects) {
				upperIndex = -(upperIndex + 1);
			}
		} else {
			upperIndex = lowerIndex;
			upperIntersects = lowerIntersects;
		}
		if(lowerIntersects) {
			lowerIntersects = compareLowerValues(ranges.get(lowerIndex).getLower(), lowerCompare) != 0;
		}
		if(upperIntersects && compareUpperValues(ranges.get(upperIndex).getUpper(), upperCompare) == 0) {
			upperIntersects = false;
			upperIndex++;
		}
		int lowestChangedIndex = 0;
		if(lowerIndex < upperIndex) { // spans at least one existing range
			if(upperIntersects) {
				// range at upper index gets chopped
				IPAddressSeqRange existingRange = ranges.get(upperIndex);
				IPAddress upper = upperCompare.withoutPrefixLength().getUpper();
				ranges.set(upperIndex, existingRange.create(existingRange.getLower(), upper));
				lowestChangedIndex = upperIndex++;
				if(!isLast) {
					// we need to put back in the remaining in case it might intersect with the next range
					ranges.add(upperIndex, existingRange.upperSplit(upper.increment()));
				}
			}
			if(lowerIntersects) {
				// range at lower index gets chopped
				IPAddressSeqRange existingRange = ranges.get(lowerIndex);
				if(compareLowerValues(existingRange.getLower(), lowerCompare) != 0) {
					IPAddress newLower = lowerCompare.withoutPrefixLength().getLower();
					ranges.set(lowerIndex, existingRange.upperSplit(newLower));
					lowestChangedIndex = lowerIndex;
				} //else the whole lower range intersects
			}
		} else { // spans 0 or 1 existing range
			if(upperIntersects) {
				IPAddressSeqRange existingRange = ranges.get(upperIndex);
				// range at upper index gets chopped
				IPAddress newLower;
				if(lowerIntersects) {
					newLower = lowerCompare.withoutPrefixLength().getLower();
				} else {
					newLower = existingRange.getLower();
				}
				IPAddress upper = upperCompare.withoutPrefixLength().getUpper();
				ranges.set(upperIndex, existingRange.create(newLower, upper));
				lowestChangedIndex = upperIndex++;
				//upperIndex++;
				if(!isLast) {// need to put back the remaining in case it intersects with ranges to come
					ranges.add(upperIndex, existingRange.upperSplit(upper.increment())); 
				}
			} // else intersects with nothing
		}
		boolean isChanged = lowerIntersects || upperIntersects;
		if(startIndex < lowerIndex) {
			upperIndex -= lowerIndex - startIndex;
			ranges.removeRange(startIndex, lowerIndex);
			isChanged = true;
			lowestChangedIndex = startIndex;
		}
		if(isLast && upperIndex < ranges.size()) {
			ranges.removeRange(upperIndex, ranges.size());
			if(!isChanged) {
				lowestChangedIndex = upperIndex;
			}
			isChanged = true;
		}
		if(isChanged) {
			clearRangeSizesFrom(lowestChangedIndex);
			changeTracker.changed();
		} else {
			upperIndex = -(upperIndex + 1); // we've not changed anything, make return value negative to indicate that
		}
		return upperIndex;
	}

	@Override
	public boolean remove(IPAddress address) {
		if(ranges.size() == 0) {
			return false;
		} else if(!versionsMatch(ranges.get(0), address)) {
			return false;
		}
		if(address.isSequential()) {
			return removeSequential(address, 0) >= 0;
		}
		boolean result = false;
		Iterator<? extends IPAddress> iterator = address.sequentialBlockIterator();
		int startIndex = 0;
		do {
			startIndex = removeSequential(iterator.next(), startIndex);
			if(startIndex >= 0) {
				result = true;
			} else {
				startIndex = -(startIndex + 1);
			}
			if(startIndex >= ranges.size()) {
				break;
			}
		} while(iterator.hasNext());
		return result;
	}

	private int removeSequential(IPAddress address, int startIndex) {
		return removeSequential(address, address, address, startIndex);
	}

	@Override
	public boolean remove(IPAddressSeqRange seqRange) {
		if(ranges.size() == 0) {
			return false;
		} else if(!versionsMatch(ranges.get(0), seqRange)) {
			return false;
		}
		return removeSequential(seqRange, seqRange.getLower(), seqRange.getUpper(), 0) >= 0;
	}

	private int removeSequential(IPAddressRange rng, IPAddress lowerCompare, IPAddress upperCompare, int startIndex) { 
		int lowerIndex = binarySearchLower(startIndex, lowerCompare);
		boolean splitLower = lowerIndex >= 0;
		if(!splitLower) {
			lowerIndex = -(lowerIndex + 1);
		}
		int upperIndex;
		boolean splitUpper;
		if(rng.isMultiple() && lowerIndex != ranges.size()) {
			upperIndex = binarySearchUpper(lowerIndex, upperCompare); 
			splitUpper = upperIndex >= 0;
			if(!splitUpper) {
				upperIndex = -(upperIndex + 1);
			}
		} else {
			upperIndex = lowerIndex;
			splitUpper = splitLower;
		}
		IPAddressSeqRange existingRange = null, existingUpperRange = null;
		if(splitLower) {
			existingRange = ranges.get(lowerIndex);
			splitLower = compareLowerValues(existingRange.getLower(), lowerCompare) != 0;
		}
		if(splitUpper) {
			existingUpperRange = ranges.get(upperIndex);
			if(compareUpperValues(existingUpperRange.getUpper(), upperCompare) == 0) {
				splitUpper = false;
				upperIndex++;
			}
		}

		if(lowerIndex < upperIndex) { // spans at least one existing range
			if(splitUpper) {
				ranges.set(upperIndex, existingUpperRange.upperSplit(upperCompare.incrementBoundary()));
			}
			if(splitLower) {
				ranges.set(lowerIndex, existingRange.lowerSplit(lowerCompare));
				int nextIndex = lowerIndex + 1;
				if(nextIndex < upperIndex) {
					ranges.removeRange(nextIndex, upperIndex);
					upperIndex -= upperIndex - nextIndex;
				}
			} else {
				ranges.removeRange(lowerIndex, upperIndex);
				upperIndex -= upperIndex - lowerIndex;
			}
		} else { // spans 0 or 1 existing range
			if(splitLower) {
				// splitUpper must also be true
				// a slab in the middle is removed
				ranges.set(lowerIndex, existingRange.lowerSplit(lowerCompare));
				ranges.add(++upperIndex, existingRange.upperSplit(upperCompare.incrementBoundary()));
			} else if(splitUpper) { // spans the single range at lowerIndex
				// range gets chopped
				ranges.set(lowerIndex, existingUpperRange.upperSplit(upperCompare.incrementBoundary()));
			} else { // spans no existing range, nothing to do
				upperIndex = -(upperIndex + 1);
				return upperIndex;
			}
		}
		clearRangeSizesFrom(lowerIndex);
		changeTracker.changed();
		return upperIndex;
	}

	/**
	 * Equivalent to calling remove(getSeqRange(index)), but does not throw when index is out of bounds
	 * Returns true if the list was changed, which is true if and only if the index was not out of bounds.
	 * @param index
	 * @return
	 */
	public void removeSeqRange(int index) {
		ranges.removeRange(index, index + 1);
		changeTracker.changed();
		clearRangeSizesFrom(index);
	}

	/**
	 * Removes the ranges from fromIndex inclusive to toIndex exclusive.
	 * Does not throw if either index is out of bounds.
	 * Returns true if the list was changed, meaning an index in the range was not out of bounds.
	 * 
	 * @param fromIndex
	 * @param toIndex
	 * @return
	 */
	public void removeSeqRanges(int fromIndex, int toIndex) {
		ranges.removeRange(fromIndex, toIndex);
		changeTracker.changed();
		clearRangeSizesFrom(fromIndex);
	}

	private int binarySearchLower(IPAddress key) {
		return binarySearchForRangeIndex(0, true, key);
	}

	private int binarySearchUpper(IPAddress key) {
		return binarySearchForRangeIndex(0, false, key);
	}

	private int binarySearchLower(int fromIndex, IPAddress key) {
		return binarySearchForRangeIndex(fromIndex, true, key);
	}

	private int binarySearchUpper(int fromIndex, IPAddress key) {
		return binarySearchForRangeIndex(fromIndex, false, key);
	}

	// Returns the index of the range containing the address.
	// Otherwise, returns -(insertion index) - 1 where insertion index is the index at which the address would fit into the list.
	private int binarySearchForRangeIndex(int lowIndex, boolean lower, IPAddress key) {
		ArrayList<IPAddressSeqRange> ranges = this.ranges;
		int highIndex = ranges.size() - 1;

		if(lowIndex <= highIndex) {
			IPAddress seqAddr;
			int cmp;

			// optimization:
			// in cases when adding a list of sorted and disjoint addresses or ranges, 
			// from lowest to highest in order, the newest key will always be above the highest range, so we check that first,
			// checking the entire address space above all the existing ranges
			seqAddr = ranges.get(highIndex).getUpper();
			cmp = lower ? compareLowerValues(seqAddr, key) : compareUpperValues(seqAddr, key);
			if(cmp < 0) {
				return -(ranges.size() + 1);
			} else if(cmp == 0) {
				return highIndex;
			}

			// optimization:
			// now we do the same for the lowest range, checking the entire address space below all the existing ranges
			seqAddr = ranges.get(lowIndex).getLower();
			cmp = lower ? compareLowerValues(seqAddr, key) : compareUpperValues(seqAddr, key);
			if(cmp > 0) {
				return -(lowIndex + 1);
			} else if(cmp == 0 || lowIndex == highIndex) {
				return lowIndex;
			}

			// now we do the binary search
			do {
				int midIndex = (lowIndex + highIndex) >>> 1; 
				IPAddressSeqRange mid = ranges.get(midIndex);
				seqAddr = mid.getLower();
				cmp = lower ? compareLowerValues(seqAddr, key) : compareUpperValues(seqAddr, key);
				if(cmp > 0) {
					highIndex = midIndex - 1;
				} else if(cmp == 0) {
					//System.out.println("hit the opt " + ++counter);
					return midIndex;
				} else {
					seqAddr = mid.getUpper();
					cmp = lower ? compareLowerValues(seqAddr, key) : compareUpperValues(seqAddr, key);
					if(cmp >= 0) {
						return midIndex;
					}
					lowIndex = midIndex + 1;
				}
			} while(lowIndex <= highIndex);
		}
		return -(lowIndex + 1);
	}

	@Override
	public boolean isMultiple() {
		return ranges.size() > 1 || (ranges.size() == 1 && ranges.get(0).isMultiple());
	}

	/**
	 * Returns true if and only if this range list has no elements within.
	 * @return
	 */
	@Override
	public boolean isEmpty() {
		return ranges.isEmpty();
	}

	/**
	 * Returns the number of discontinuous sequential ranges of addresses in this list.
	 * @return
	 */
	public int getSeqRangeCount() {
		return ranges.size();
	}

	/**
	 * Returns whether this list contains the address matching the version of all addresses in this list and having the value of zero.
	 */
	@Override
	public boolean includesZero() {
		return ranges.size() > 0 && ranges.get(0).includesZero();
	}

	/**
	 * Returns whether this list contains the address matching the version of all addresses in this list and has the maximum value for addresses of that address version.
	 */
	@Override
	public boolean includesMax() {
		int size = ranges.size();
		return size > 0 && ranges.get(size - 1).includesMax();
	}

	/**
	 * Returns the sequential range at the given index, the index refers to the sequential ranges in the list, not the contained addresses.
	 * <p>
	 * To get the sequential range at a given address index, use {@link #getContainingSeqRange(BigInteger)}
	 * 
	 * @throws ArrayIndexOutOfBoundsException if index is outside the bounds or the existing ranges
	 * @param index
	 * @return
	 */
	public IPAddressSeqRange getSeqRange(int rangeIndex) {
		return ranges.get(rangeIndex);
	}

	public Iterable<? extends IPAddressSeqRange> getSeqRangeIterable() {
		return new Iterable<IPAddressSeqRange>() {

			@SuppressWarnings("unchecked")
			@Override
			public Iterator<IPAddressSeqRange> iterator() {
				return (Iterator<IPAddressSeqRange>) seqRangeIterator();
			}
			
			@Override
			public Spliterator<IPAddressSeqRange> spliterator() {
				return ranges.spliterator();
			}
		};
	}

	public Iterator<? extends IPAddressSeqRange> seqRangeIterator() {
		return new Iterator<IPAddressSeqRange>() {
			Iterator<IPAddressSeqRange> iter = ranges.iterator();
			int index = -1;
			
			@Override
			public boolean hasNext() {
				return iter.hasNext();
			}

			@Override
			public IPAddressSeqRange next() {
				IPAddressSeqRange next = iter.next();
				index++;
				return next;
			}
			
			@Override
			public void remove() {
				iter.remove();
				clearRangeSizesFrom(index);
			}
		};
	}

	public Iterable<? extends IPAddress> getIterable() {
		return new Iterable<IPAddress>() {

			@SuppressWarnings("unchecked")
			@Override
			public Iterator<IPAddress> iterator() {
				return (Iterator<IPAddress>) IPAddressSeqRangeList.this.iterator();
			}
			
			@SuppressWarnings("unchecked")
			@Override
			public Spliterator<IPAddress> spliterator() {
				return (Spliterator<IPAddress>) IPAddressSeqRangeList.this.spliterator();
			}
		};
	}

	/**
	 * Returns an iterator that iterates through all addresses in ascending order.  This iterator supports the remove operation.
	 * @return
	 */
	@Override
	public Iterator<? extends IPAddress> iterator() {
		return new RangeIterator();
	}

	@Override
	public BigSpliterator<? extends IPAddress> spliterator() {
		return new RangeSpliterator<IPAddress>(this);
	}

	@Override
	public Stream<? extends IPAddress> stream() {
		return StreamSupport.stream(spliterator(), false);
	}

	/**
	 * Returns the sequential ranges in order.
	 * 
	 * @return
	 */
	public IPAddressSeqRange[] getSeqRanges() {
		return ranges.toArray(new IPAddressSeqRange[ranges.size()]);
	}

	/**
	 * Returns the individual address with the lowest numeric value in this sequential range list.
	 * @return
	 */
	@Override
	public IPAddress getLower() {
		if(isEmpty()) {
			return null;
		}
		return ranges.get(0).getLower();
	}

	/**
	 * Returns the individual address with the highest numeric value in this sequential range list.
	 * @return
	 */
	@Override
	public IPAddress getUpper() {
		if(isEmpty()) {
			return null;
		}
		return ranges.get(getSeqRangeCount() - 1).getUpper();
	}

	/**
	 * Returns the lowest sequential range in the list, or null if the list is empty
	 * @return
	 */
	public IPAddressSeqRange getLowerSeqRange() {
		if(isEmpty()) {
			return null;
		}
		return ranges.get(0);
	}

	/**
	 * Returns the highest sequential range in the list, or null if the list is empty
	 * @return
	 */
	public IPAddressSeqRange getUpperSeqRange() {
		if(isEmpty()) {
			return null;
		}
		return ranges.get(getSeqRangeCount() - 1);
	}

	/**
	 * Empties this list
	 */
	@Override
	public void clear() {
		if(!isEmpty()) {
			ranges.clear();
			clearRangeSizesFrom(0);
			changeTracker.changed();
		}
	}

	/**
	 * Removes the individual address at the given index into the lists of addresses.  Returns that address.
	 * Similar to {@link #get(BigInteger)} but also removes the address found.
	 * <p>
	 * If the index is negative or larger than {@link #getCount() - 1}, this method throws IndexOutOfBoundsException.
	 * 
	 * @param index
	 * @return
	 */
	public IPAddress remove(BigInteger addressIndex) {
		return findAddress(addressIndex, true, true);
	}

	/**
	 * Returns the individual address that is the given increment upwards into the list of sequential ranges, with the increment of 0
	 * returning the first address.
	 * <p>
	 * If there are no addresses in this list, then null is returned.
	 * <p>
	 * If the list of ranges has multiple addresses and the increment exceeds the total number (as returned by {@link #getCount()}, 
	 * then the final address (last iterator value) is incremented amount by which the increments exceeds the size - 1.
	 * If that increment exceeds the largest possible address for the version or protocol (eg exceeds IPv4 255.255.255.255), then AddressValueException is thrown.
	 * <p>
	 * If the increment is negative, it is added to the lowest address in the list of sequential ranges (the first iterator value).  
	 * If that increment exceeds the smallest possible address for the version or protocol (eg exceeds IPv4 0.0.0.0), then AddressValueException is thrown.
	 * <p>
	 * A positive increment value is equivalent to the same number of values from the {@link #iterator()}
	 * For instance, a increment of 0 is the first value from the iterator, an increment of 1 is the second value from the iterator, and so on. 
	 * A negative increment added to the total count returned by {@link #getCount(BigInteger)} is equivalent to the same number of values preceding the upper bound of the iterator.
	 * For instance, an increment of count - 1 is the last value from the iterator, an increment of count - 2 is the second last value, and so on.
	 * <p>
	 * An increment of size matching the count gives you the address just above the highest address in the list of sequential ranges.
	 * To get the address just below the lowest address in the list of sequential ranges, use the increment -1.
	 * 
	 * @param increment
	 * @throws AddressValueException in case of underflow or overflow
	 * @return the incremented address, or null if this list is empty.
	 */
	public IPAddress increment(BigInteger addressIndex) {
		return findAddress(addressIndex, false, false);
	}

	/**
	 * Get is similar to {@link #increment(BigInteger)} but does not return any address that is not within this sequential range list, 
	 * and does not throw AddressValueException to indicate overflow or underflow. 
	 * <p>
	 * If the list has no addresses, the increment is negative, or the increment exceeds {@link #getCount()} - 1, then this method throws IndexOutOfBoundsException.
	 * <p>
	 * Otherwise this returns the address that is the given increment upwards into the list of sequential ranges, with the increment of 0
	 * returning the first address.
	 * 
	 * @param index
	 * @return
	 */
	public IPAddress get(BigInteger addressIndex) {
		return findAddress(addressIndex, false, true);
	}

	/**
	 * Gets the sequential range containing the address at the given address index.
	 * <p>
	 * To get the sequential range at a sequential range index, use {@link #getSeqRange(int)}
	 * 
	 * @param index
	 * @return
	 */
	public IPAddressSeqRange getContainingSeqRange(BigInteger addressIndex) {
		int rangeIndex = findRange(addressIndex);
		if(rangeIndex < 0 || rangeIndex == ranges.size()) {
			throw new IndexOutOfBoundsException();
		}
		return getSeqRange(rangeIndex);
	}

	/**
	 * Gets the sequential range containing the address at the given address index.
	 * <p>
	 * To get the sequential range at a sequential range index, use {@link #getSeqRange(int)}
	 * 
	 * @param index
	 * @return
	 */
	public IPAddressSeqRange getContainingSeqRange(long addressIndex) {
		int rangeIndex = findRange(addressIndex);
		if(rangeIndex < 0 || rangeIndex == ranges.size()) {
			throw new IndexOutOfBoundsException();
		}
		return getSeqRange(rangeIndex);
	}

	/**
	 * Removes the individual address at the given index into the lists of addresses.  Returns that address.
	 * Similar to {@link #get(long)} but also removes the address found.
	 * <p>
	 * If the index is negative or larger than {@link #getCount() - 1}, this method throws IndexOutOfBoundsException.
	 * 
	 * @param index
	 * @return
	 */
	public IPAddress remove(long addressIndex) {
		return findAddress(addressIndex, true, true);
	}

	/**
	 * Returns the individual address that is the given increment upwards into the list of sequential ranges, with the increment of 0
	 * returning the first address.
	 * <p>
	 * If there are no addresses in this list, then null is returned.
	 * <p>
	 * If the list of ranges has multiple addresses and the increment exceeds the total number (as returned by {@link #getCount()}, 
	 * then the final address (last iterator value) is incremented amount by which the increments exceeds the size - 1.
	 * If that increment exceeds the largest possible address for the version or protocol (eg exceeds IPv4 255.255.255.255), then AddressValueException is thrown.
	 * <p>
	 * If the increment is negative, it is added to the lowest address in the list of sequential ranges (the first iterator value).  
	 * If that increment exceeds the smallest possible address for the version or protocol (eg exceeds IPv4 0.0.0.0), then AddressValueException is thrown.
	 * <p>
	 * A positive increment value is equivalent to the same number of values from the {@link #iterator()}
	 * For instance, a increment of 0 is the first value from the iterator, an increment of 1 is the second value from the iterator, and so on. 
	 * A negative increment added to the total count returned by {@link #getCount(BigInteger)} is equivalent to the same number of values preceding the upper bound of the iterator.
	 * For instance, an increment of count - 1 is the last value from the iterator, an increment of count - 2 is the second last value, and so on.
	 * <p>
	 * An increment of size matching the count gives you the address just above the highest address in the list of sequential ranges.
	 * To get the address just below the lowest address in the list of sequential ranges, use the increment -1.
	 * <p> 
	 * An increment that goes beyond the minimum or maximum address values results in an AddressValueException being thrown.
	 * 
	 * @param increment
	 * @throws AddressValueException in case of underflow or overflow in the address space
	 * @return the incremented address, or null if this list is empty.
	 */
	public IPAddress increment(long addressIndex) {
		return findAddress(addressIndex, false, false);
	}

	/**
	 * Get is similar to {@link #increment(BigInteger)} but does not return any address that is not within this sequential range list. 
	 * <p>
	 * If the increment is negative, or the increment exceeds {@link #getCount()} - 1, this method throws IndexOutOfBoundsException.
	 * <p>
	 * Otherwise, this returns the address that is the given index upwards into the list of sequential ranges, with the increment of zero
	 * returning the first address.
	 * 
	 * @param index
	 * @return
	 */
	public IPAddress get(long addressIndex) {
		return findAddress(addressIndex, false, true);
	}

	private IPAddress findAddress(BigInteger index, boolean remove, boolean inList) {
		int rangeIndex = findRange(index);
		int rangeCount = ranges.size();
		if(rangeIndex < 0) {
			if(remove || inList) {
				throw new IndexOutOfBoundsException();
			} else if(rangeCount == 0) {
				return null;
			}
			return ranges.get(0).getLower().increment(index);
		}
		if(rangeIndex == rangeCount) {
			if(remove || inList) {
				throw new IndexOutOfBoundsException();
			} else if(rangeCount == 0) {
				return null;
			}
			int lastIndex = rangeCount - 1;
			BigInteger totalRangeSize = rangeSizes.get(lastIndex); // this is the same as getCount()
			return ranges.get(lastIndex).getUpper().increment(index.subtract(totalRangeSize).add(BigInteger.ONE));
		} else if(rangeIndex == 0) {
			IPAddress lower = ranges.get(0).getLower();
			if(index.signum() == 0) {
				if(remove) {
					removeFirstAddress(lower);
				}
				return lower;
			}
			IPAddress increment = lower.increment(index);
			if(remove) {
				removeAddress(increment, 0, index, BigInteger.ZERO);
			}
			return increment;
		}
		IPAddressSeqRange rng = ranges.get(rangeIndex);
		IPAddress lower = rng.getLower();
		BigInteger previousRangesSize = rangeSizes.get(rangeIndex - 1);
		index = index.subtract(previousRangesSize);
		IPAddress increment = lower.increment(index);
		if(remove) {
			removeAddress(increment, rangeIndex, index, previousRangesSize);
		}
		return increment;
	}

	private IPAddress findAddress(long index, boolean remove, boolean inList) {
		int rangeIndex = findRange(index);
		int rangeCount = ranges.size();
		if(rangeIndex < 0) {
			if(remove || inList) {
				throw new IndexOutOfBoundsException();
			} else if(rangeCount == 0) {
				return null;
			}
			return ranges.get(0).getLower().increment(index);
		}
		if(rangeIndex == rangeCount) {
			if(remove || inList) {
				throw new IndexOutOfBoundsException();
			} else if(rangeCount == 0) {
				return null;
			}
			int lastIndex = rangeCount - 1;
			long totalRangeSize = rangeSizes.get(lastIndex).longValue();
			return ranges.get(lastIndex).getUpper().increment((index - totalRangeSize) + 1);
		} else if(rangeIndex == 0) {
			IPAddress lower = ranges.get(0).getLower();
			if(index == 0) {
				if(remove) {
					removeFirstAddress(lower);
				}
				return lower;
			}
			IPAddress increment = lower.increment(index);
			if(remove) {
				removeAddress(increment, 0, BigInteger.valueOf(index), BigInteger.ZERO);
			}
			return increment;
		}
		BigInteger previousRangesSize = rangeSizes.get(rangeIndex - 1);
		index -= previousRangesSize.longValue();
		IPAddress lower = ranges.get(rangeIndex).getLower();
		IPAddress increment = lower.increment(index);
		if(remove) {
			removeAddress(increment, rangeIndex, BigInteger.valueOf(index), previousRangesSize);
		}
		return increment;
	}

	// finds the range containing the address with the given index
	private int findRange(BigInteger index) {
		int signum = index.signum();
		if(signum <= 0) {
			if(signum == 0) {
				return 0;
			}
			return -1;
		}
		return searchForRange(index);
	}

	// finds the range containing the address with the given index
	private int findRange(long index) {
		if(index <= 0) {
			if(index == 0) {
				return 0;
			}
			return -1;
		}
		return searchForRange(BigInteger.valueOf(index));
	}

	private int searchForRange(BigInteger index) {
		// search using the existing range sizes
		int rangeIndex = binarySearchForRange(index);
		if(rangeIndex >= 0) {
			return rangeIndex;
		}
		// create missing range sizes, and see if we fall in one of those ranges
		int rangeSzs = rangeSizes.size();
		BigInteger previousRangeSize = (rangeSzs == 0) ? BigInteger.ZERO : rangeSizes.get(rangeSzs - 1);
		int i = rangeSzs;
		int total = ranges.size();
		for(; i < total; i++) {
			IPAddressSeqRange rng = ranges.get(i);
			BigInteger count = rng.getCount().add(previousRangeSize);
			rangeSizes.add(count);
			if(index.compareTo(count) < 0) {
				return i;
			}
			previousRangeSize = count;
		}
		return total;
	}

	private int binarySearchForRange(BigInteger index) {
		ArrayList<BigInteger> rangeSizes = this.rangeSizes;
		int highIndex = rangeSizes.size();
		if(highIndex == 0) {
			return -1;
		}

		// above the highest
		BigInteger highSize = rangeSizes.get(highIndex - 1);
		if(highSize.compareTo(index) <= 0) {
			return -1;
		}

		int lowIndex = 0;
		while(lowIndex <= highIndex) {
			int midIndex = (lowIndex + highIndex) >>> 1;
			BigInteger midSize = rangeSizes.get(midIndex);
			if(index.compareTo(midSize) >= 0) {
				lowIndex = midIndex + 1;
			} else if (midIndex == 0 || index.compareTo(rangeSizes.get(midIndex - 1)) >= 0){
				return midIndex;
			} else {
				highIndex = midIndex - 1;
			}
		}
		return -1;
	}

	protected void removeFirstAddress(IPAddress address) {
		IPAddressSeqRange rng = ranges.get(0);
		if(rng.isMultiple()) {
			// the lower side is removed
			ranges.set(0, rng.upperSplit(address.increment()));
		} else {
			ranges.removeRange(0, 1);
		}
		clearRangeSizesFrom(0);
		changeTracker.changed();
	}

	protected void removeAddress(IPAddress individualAddress, int rngIndex, BigInteger addressIndexInRange, BigInteger previousRangesSize) {
		IPAddressSeqRange rng = ranges.get(rngIndex);
		BigInteger rngSize = rangeSizes.get(rngIndex).subtract(previousRangesSize); // The range size is populated due to the search that got us here
		if(addressIndexInRange.signum() == 0) {
			// the lower address is removed
			if(rngSize.equals(BigInteger.ONE)) {
				// the whole range is just that one address
				ranges.removeRange(rngIndex, rngIndex + 1);
			} else {
				ranges.set(rngIndex, rng.upperSplit(individualAddress.increment()));
			}
		} else if(rngSize.compareTo(addressIndexInRange.add(BigInteger.ONE)) == 0) {
			// the upper address is removed
			ranges.set(rngIndex, rng.lowerSplit(individualAddress));
		} else {
			// a slab in the middle is removed
			ranges.set(rngIndex, rng.lowerSplit(individualAddress));
			ranges.add(rngIndex + 1, rng.upperSplit(individualAddress.increment()));
		}
		clearRangeSizesFrom(rngIndex);
		changeTracker.changed();
	}

	// gets the count of addresses in the first rangeCount ranges
	protected BigInteger getCount(int rangeCount) {
		RangeList<BigInteger> rangeSizes = this.rangeSizes;
		if(rangeCount > rangeSizes.size()) {
			// always ensure the capacity of rangeSizes is at least the length of the ranges list
			rangeSizes.ensureCapacity(ranges.size());
			int index = rangeSizes.size() - 1;
			BigInteger count = (index < 0) ? BigInteger.ZERO :  rangeSizes.get(index); 
			IPAddressSeqRange seqRange = getSeqRange(++index);
			if(seqRange.isIPv4()) {
				long ipv4Count = count.longValue();
				IPv4AddressSeqRange ipv4Range = (IPv4AddressSeqRange) seqRange;
				ipv4Count += ipv4Range.getIPv4Count();
				rangeSizes.add(BigInteger.valueOf(ipv4Count));
				while(++index < rangeCount) {
					ipv4Range = (IPv4AddressSeqRange) getSeqRange(index);
					ipv4Count += ipv4Range.getIPv4Count();
					rangeSizes.add(BigInteger.valueOf(ipv4Count));
				}
				count = BigInteger.valueOf(ipv4Count);
			} else {
				count = count.add(seqRange.getCount());
				rangeSizes.add(count);
				while(++index < rangeCount) {
					seqRange = getSeqRange(index);
					count = count.add(seqRange.getCount());
					rangeSizes.add(count);
				}
			}
			return count;
		} else if(rangeCount > 0) {
			return rangeSizes.get(rangeCount - 1);
		}
		return BigInteger.ZERO;
	}

	@Override
	public BigInteger getCount() { 
		return getCount(ranges.size());
	}

	/**
	 * Returns the distance of the given address from the initial value of this range.  Indicates where an address sits relative to the range ordering.
	 * <p>
	 * If within or above the range, it is the distance to the lower boundary of the sequential range.  If below the, returns the number of addresses following the address to the lower range boundary.
	 * <p>
	 * You can call {@link #contains(IPAddress)} or you can compare with {@link #getCount()} to check for containment.
	 * An address is in the range if 0 &lt;= {@link #enumerate(IPAddress)} &lt; {@link #getCount()}.
	 * <p>
	 * If the address is above the lower boundary and below the upper boundary of the range list, but id not within a range in the range list, then this method returns null.
	 * <p>
	 * Returns null when the argument is a multi-valued subnet. The argument must be an individual address.
	 * <p>
	 * Returns null when there are no ranges in this sequential range list.
	 * <p>
	 * Returns null when the address version does not match the addresses in this range list.
	 */
	public BigInteger enumerate(IPAddress address) {
		if(address.isMultiple()) {
			return null;
		} else if(ranges.size() == 0) {
			return null;
		} else if(!versionsMatch(ranges.get(0), address)) {
			return null;
		}
		int lowerIndex = binarySearchLower(address);
		if(lowerIndex < 0) {
			lowerIndex = -(lowerIndex + 1);
			if(lowerIndex > 0 && lowerIndex < ranges.size()) {
				return null;
			} else if(lowerIndex == 0) {
				return ranges.get(0).enumerate(address);
			} else { // lowerIndex == ranges.size() && ranges.size() > 0
				int lastRangeIndex = ranges.size() - 1;
				return getCount(lastRangeIndex).add(ranges.get(lastRangeIndex).enumerate(address));
			}
		}
		return getCount(lowerIndex).add(ranges.get(lowerIndex).enumerate(address));
	}

	@Override
	public boolean equals(Object other) {
		if(other instanceof IPAddressSeqRangeList) {
			if(other == this) {
				return true;
			}
			IPAddressSeqRangeList otherList = (IPAddressSeqRangeList) other;
			int rangeCount = getSeqRangeCount();
			if(rangeCount != otherList.getSeqRangeCount()) {
				return false;
			}
			for(int i = 0; i < rangeCount; i++) {
				if(!getSeqRange(i).equals(otherList.getSeqRange(i))) {
					return false;
				}
			}
			return true;
		} else if(other instanceof IPAddressContainmentTrieBase) {
			IPAddressContainmentTrieBase<?, ?> otherColl = (IPAddressContainmentTrieBase<?, ?>) other;
			return getCount().equals(otherColl.getCount()) && contains(otherColl);
		} else if(other instanceof IPAddressCollection) {
			IPAddressCollection<? extends IPAddress,?> otherColl = (IPAddressCollection<?,?>) other;
			return IPAddressContainmentTrieBase.collectionsEqual(this, otherColl);
		}
		return false;
	}

	/**
	 * Copies the IPAddressSeqRangeList.
	 */
	@Override
	public IPAddressSeqRangeList clone() {
		return clone(new ChangeTracker());
	}

	@SuppressWarnings("unchecked")
	private IPAddressSeqRangeList clone(ChangeTracker changeTracker) {
		try {
			IPAddressSeqRangeList cloned = (IPAddressSeqRangeList) super.clone();
			//cloned.set = null;
			cloned.ranges = (RangeList<IPAddressSeqRange>) cloned.ranges.clone();
			cloned.rangeSizes = (RangeList<BigInteger>) cloned.rangeSizes.clone();
			cloned.changeTracker = changeTracker;
			return cloned;
		} catch (CloneNotSupportedException e) {
			return null;
		}
	}

	@Override
	public int hashCode() {
		return ranges.hashCode();
	}

	@Override
	public boolean isSequential() {
		return ranges.size() <= 1;
	}

	@Override
	public String toString() {
		return toCanonicalString();
	}

	public String toCanonicalString() {
		// IPAddressSeqRange::toString uses IPAddressSeqRange::toCanonicalString
		return ranges.toString();
	}

	public String toNormalizedString() {
		return toString(IPAddressSeqRange::toNormalizedString);
	}

	public String toString(Function<? super IPAddressSeqRange, String> rangeStringer) {
		StringBuilder builder = new StringBuilder();
		builder.append('[');
		Iterator<IPAddressSeqRange> iterator = ranges.iterator();
		if(iterator.hasNext()) {
			builder.append(rangeStringer.apply(iterator.next()));
			while(iterator.hasNext()) {
				builder.append(',').append(' ').append(rangeStringer.apply(iterator.next()));
			}
		}
		builder.append(']');
		return builder.toString();
	}

	@Override
	public IPAddressSeqRange coverWithSequentialRange() {
		IPAddress lower = getLower();
		if(lower == null) {
			return null;
		}
		return lower.spanWithRange(getUpper());
	}

	@Override
	public IPAddress coverWithPrefixBlock() {
		IPAddress lower = getLower();
		if(lower == null) {
			return null;
		}
		return lower.coverWithPrefixBlock(getUpper());
	}

	public IPAddress[] spanWithPrefixBlocks() {
		if(ranges.size() == 0) {
			return IPAddressNetwork.EMPTY_ADDRESS;
		}
		return getSpanningBlocks(IPAddressSeqRange::spanWithPrefixBlocks, IPAddress[]::new);
	}

	public IPAddress[] spanWithSequentialBlocks() {
		if(ranges.size() == 0) {
			return IPAddressNetwork.EMPTY_ADDRESS;
		}
		return getSpanningBlocks(IPAddressSeqRange::spanWithSequentialBlocks, IPAddress[]::new);
	}

	@SuppressWarnings("unchecked")
	protected <R extends IPAddressSeqRange, T extends IPAddress> T[] getSpanningBlocks(
			Function<R, T[]> blocksProducer,
			IntFunction<T[]> arrayProducer) {
		List<T> result = new ArrayList<>();
		for(int i = 0; i < ranges.size(); i++) {
			result.addAll((Collection<T>) Arrays.asList(blocksProducer.apply((R) ranges.get(i))));
		}
		return result.toArray(arrayProducer.apply(result.size())); // not in Java 8, only Java 11: return result.toArray(arrayProducer);
	}

	private static boolean versionsMatch(IPAddress one, IPAddress two) {
		return IPAddressSeqRange.versionsMatch(one, two);
	}

	private static boolean versionsMatch(IPAddressSeqRange one, IPAddress two) {
		return IPAddressSeqRange.versionsMatch(one.getLower(), two);
	}

	private static boolean versionsMatch(IPAddressSeqRange one, IPAddressSeqRange two) {
		return IPAddressSeqRange.versionsMatch(one.getLower(), two.getLower());
	}

	class RangeIterator implements Iterator<IPAddress> {
		private Change currentChange = changeTracker.getCurrent();
		private int nextRangeIndex;
		private Iterator<? extends IPAddress> currentIterator = Collections.emptyIterator();
		private IPAddress last;
		private boolean firstOfRange, removedLast;

		// Note: If we used an iterator on the range list, 
		// it would not be enough to handle the change tracking.
		// While it is enough to detect any and all changes,
		// the problem is that when the range list is changed, 
		// we might not actually attempt to use the range iterator again
		// until the current iterator on the current sequential range is extinguished.
		// The ConcurrentModificationException would be delayed.

		@Override
		public boolean hasNext() {
			return currentIterator.hasNext() || nextRangeIndex < ranges.size();
		}

		@Override
		public IPAddress next() {
			changeTracker.changedSince(currentChange);
			if(firstOfRange = !currentIterator.hasNext() && nextRangeIndex < ranges.size()) {
				currentIterator = ranges.get(nextRangeIndex++).iterator();
			} else {
				firstOfRange = removedLast;
			}
			removedLast = false;
			last = null; // set it to null in case currentIterator.next() throws
			return last = currentIterator.next();
		}

		@Override
		public void remove() {
			changeTracker.changedSince(currentChange);
			if(last == null) {
				throw new IllegalStateException();
			}
			int currentRangeIndex = nextRangeIndex - 1;
			// note: there is no need to reset the iterator in any of these cases
			if(firstOfRange) {
				if (!currentIterator.hasNext()) {
					ranges.removeRange(currentRangeIndex, nextRangeIndex--);
				} else {
					ranges.set(currentRangeIndex, ranges.get(currentRangeIndex).upperSplit(last.increment()));
				}
			} else if (!currentIterator.hasNext()) {
				// last of range
				IPAddressSeqRange rng = ranges.get(currentRangeIndex);
				ranges.set(currentRangeIndex, rng.lowerSplit(last));
			} else {
				// in the middle of the range
				IPAddressSeqRange rng = ranges.get(currentRangeIndex);
				ranges.set(currentRangeIndex, rng.lowerSplit(last));
				ranges.add(nextRangeIndex, rng.upperSplit(last.increment()));
				nextRangeIndex++;
			}
			removedLast = true;
			last = null;
			clearRangeSizesFrom(currentRangeIndex);
			currentChange = changeTracker.getCurrent();
		}
	}

	private static class RangeSpliterator<T extends IPAddress> implements BigSpliterator<T> {
		private Change currentChange;

		//Need this here for the case where list is null, otherwise we could have just accessed it always from the list
		private ChangeTracker changeTracker;

		// both of these are null when spliterator is non-null
		private boolean isBig;
		private IPAddressSeqRangeList list;

		// iterator and nextRangeIndex are unused when spliterator is non-null
		private Iterator<T> currentIterator = Collections.emptyIterator();
		private int nextRangeIndex;
		private T lastIterated;

		// when the list is null, we use this spliterator instead of the list and iterator
		private AddressComponentRangeSpliterator<? extends IPAddressSeqRange, T> spliterator;

		// initial constructor
		RangeSpliterator(IPAddressSeqRangeList fromList) {
			changeTracker = fromList.changeTracker;
			currentChange = changeTracker.getCurrent();
			RangeList<IPAddressSeqRange> ranges = fromList.ranges;
			int rangeSize = ranges.size();
			if(rangeSize == 0) {
				list = fromList;
			} else if(rangeSize == 1) {
				spliterator = getSpliterator(ranges.get(0));
			} else {
				// calculate count before cloning so we clone the populated rangeSizes
				isBig = fromList.getCount().compareTo(LONG_MAX) > 0;
				
				// we clone the existing ranges list, because we alter the list when we split
				list = fromList.clone(changeTracker);
			}
		}

		private RangeSpliterator(IPAddressSeqRangeList list, boolean isBig, ChangeTracker changeTracker, Change currentChange) {
			this.isBig = isBig;
			this.list = list;
			this.changeTracker = changeTracker;
			this.currentChange = currentChange;
		}

		private RangeSpliterator(AddressComponentRangeSpliterator<? extends IPAddressSeqRange, T> spliterator, ChangeTracker changeTracker, Change currentChange) {
			this.spliterator = spliterator;
			this.changeTracker = changeTracker;
			this.currentChange = currentChange;
		}

		// Here we split with a multi-pronged approach
		// The iterator is removed, and any addresses remaining in the sequential range being iterated are converted to a sequential range.
		// If there are no addresses remaining, we cannot split.
		// The sequential ranges (the one from the iterator plus others uniterated) are split into two groups by count, producing the split,
		// unless there is just one left, in which case we transition to the spliterator of that range,
		// after which any further splitting deferes to that spliterator.
		@Override
		public RangeSpliterator<T> trySplit() {
			changeTracker.changedSince(currentChange);

			// Use the IPAddressSeqRange spliterator if that is non-null
			if(spliterator != null) {
				AddressComponentRangeSpliterator<? extends IPAddressSeqRange, T> otherSpliterator = spliterator.trySplit();
				if(otherSpliterator == null) {
					return null;
				}
				return new RangeSpliterator<T>(otherSpliterator, changeTracker, currentChange);
			}

			if(list.ranges.size() == 0) {
				// previously everything was iterated, so nothing to split
				return null;
			}

			// Reconstruct the ranges based on what has been iterated so far
			BigInteger count = list.getCount();
			if(nextRangeIndex > 0) { // we iterated
				RangeList<IPAddressSeqRange> ranges = list.ranges;
				count = count.subtract(ranges.get(nextRangeIndex - 1).getCount());
				if(currentIterator.hasNext()) {
					IPAddressSeqRange remaining = ranges.get(--nextRangeIndex).upperSplit(currentIterator.next());
					ranges.set(nextRangeIndex, remaining);
					count = count.add(remaining.getCount());
					if(nextRangeIndex > 0) {
						count = count.subtract(list.getCount(nextRangeIndex));
						ranges.removeRange(0, nextRangeIndex); // iterated through these already
					}
				} else {
					count = count.subtract(list.getCount(nextRangeIndex));
					ranges.removeRange(0, nextRangeIndex);
					if(ranges.size() == 0) {
						// everything has been iterated, nothing is left
						currentIterator = Collections.emptyIterator();
						nextRangeIndex = 0;
						list.clearRangeSizesFrom(0);
						return null;
					}
				}
				currentIterator = Collections.emptyIterator();
				nextRangeIndex = 0;
				list.clearRangeSizesFrom(0);

				// transition to the spliterator with the embedded IPAddressSeqRange spliterator 
				// if only one range is left,
				// which can happen if we iterated a lot
				if(ranges.size() == 1) {

					// ranges were iterated and left just one range, so iteration must have crossed into that final range, or at least finished off the second-last range
					spliterator = getSpliterator(list.ranges.get(0));
					list = null;
					AddressComponentRangeSpliterator<? extends IPAddressSeqRange, T> otherSpliterator = spliterator.trySplit();
					if(otherSpliterator == null) {
						return null;
					}
					return new RangeSpliterator<T>(otherSpliterator, changeTracker, currentChange);
				}
			}

			// divide the ranges based on count, and if an odd number, choose "this" to be the bigger since we may have iterated, shrinking the first range

			RangeSpliterator<T> other;
			BigInteger halfCount = count.shiftRight(1);
			int midRangeIndex = list.findRange(halfCount);

			// this spliterator will include the ranges from index 0 to index rangeIndex
			// the other spliterator will include the ramges from index rangeIndex + 1 onwards
			// Since we are splitting based on address count, the number of ranges on each side may differ widely

			// ensure we include at least one range in the other split
			if(midRangeIndex + 1 == list.ranges.size()) {
				midRangeIndex--;
			}
			int otherRangeIndex = midRangeIndex + 1;
			if(otherRangeIndex + 1 == list.ranges.size()) {

				// transition other to nested spliterator-based
				AddressComponentRangeSpliterator<? extends IPAddressSeqRange, T> otherSpliterator = 
						getSpliterator(list.ranges.get(otherRangeIndex));
				other = new RangeSpliterator<T>(otherSpliterator, changeTracker, currentChange);
			} else {
				BigInteger otherCount = count.subtract(list.getCount(otherRangeIndex));
				IPAddressSeqRangeList newList = new IPAddressSeqRangeList(changeTracker, list.ranges.size() - otherRangeIndex);
				newList.ranges.addAll(list.ranges.subList(otherRangeIndex, list.ranges.size()));
				if(isBig) {
					other = new RangeSpliterator<T>(newList, otherCount.compareTo(LONG_MAX) > 0, changeTracker, currentChange);
				} else {
					other = new RangeSpliterator<T>(newList, false, changeTracker, currentChange);
				}
			}

			if(midRangeIndex == 0) {
				// transition this to nested-spliterator-based
				spliterator = getSpliterator(list.ranges.get(0));
				list = null;
			} else {
				int newSize = otherRangeIndex;
				list.ranges.removeRange(newSize, list.ranges.size());
				// the rangeSizes in this list could remain the same, but truncate anyway to enable garbage collection
				if(list.rangeSizes.size() > newSize) {
					list.rangeSizes.removeRange(newSize, list.rangeSizes.size());
				}
			}
			return other;
		}

		@SuppressWarnings("unchecked")
		private AddressComponentRangeSpliterator<? extends IPAddressSeqRange, T> getSpliterator(IPAddressSeqRange range) {
			return (AddressComponentRangeSpliterator<? extends IPAddressSeqRange, T>) range.spliterator();
		}

		@SuppressWarnings("unchecked")
		private Iterator<T> getIterator(IPAddressSeqRange range) {
			return (Iterator<T>) range.iterator();
		}

		@Override
		public boolean tryAdvance(Consumer<? super T> action) {
			changeTracker.changedSince(currentChange);
			if(spliterator != null) {
				return spliterator.tryAdvance(action);
			} else if(list.ranges.size() > 0) {
				if(currentIterator.hasNext()) {
					action.accept(lastIterated = currentIterator.next());
					return true;
				} else if(nextRangeIndex < list.ranges.size()) {
					currentIterator = getIterator(list.ranges.get(nextRangeIndex++));
					action.accept(lastIterated = currentIterator.next());
					return true;
				}
			} else if(action == null) {
				throw new NullPointerException();
			}
			return false;
		}

		@Override
		public void forEachRemaining(Consumer<? super T> action) { 
			changeTracker.changedSince(currentChange);
			if(spliterator != null) {
				spliterator.forEachRemaining(action);
			} else if(list.ranges.size() > 0) {
				while(true) {
					while(currentIterator.hasNext()) {
						action.accept(lastIterated = currentIterator.next());
					}
					if(nextRangeIndex >= list.ranges.size()) {
						break;
					}
					currentIterator = getIterator(list.ranges.get(nextRangeIndex++));
				}
			} else if(action == null) {
				throw new NullPointerException();
			}
		}

		private BigInteger iteratedSize() {
			if(nextRangeIndex > 0) {
				if(currentIterator.hasNext()) { // did not reach end
					int currentRangeIndex = nextRangeIndex - 1;
					if(currentRangeIndex > 0) {
						return list.getCount(currentRangeIndex).add(list.getSeqRange(currentRangeIndex).enumerate(lastIterated)).add(BigInteger.ONE);
					}
					return list.getSeqRange(currentRangeIndex).enumerate(lastIterated).add(BigInteger.ONE);
				}
				return list.getCount(nextRangeIndex);
			}
			return BigInteger.ZERO;
		}

		@Override
		public long estimateSize() {
			if(spliterator != null) {
				return spliterator.estimateSize();
			} else if(isBig) {
				return Long.MAX_VALUE;
			}
			return list.getCount().subtract(iteratedSize()).longValue();
		}

		@Override
		public BigInteger getSize() {
			if(spliterator != null) {
				return spliterator.getSize();
			}
			return list.getCount().subtract(iteratedSize());
		}

		@Override
		public int characteristics() {
			if(spliterator != null) {
				return spliterator.characteristics();
			}
			int flags = DISTINCT | NONNULL | ORDERED | SORTED;
			if(!isBig) {
				flags |= SIZED | SUBSIZED; 
			}
			return flags;
		}

		@Override
		public Comparator<? super T> getComparator() {
			return null;  // this dictates the use of the natural ordering of T for comparison
		}

		@Override
		public String toString() {
			if(spliterator != null) {
				return spliterator.toString();
			}
			return "spliterator for " + list.toString();
		}
	}
}
