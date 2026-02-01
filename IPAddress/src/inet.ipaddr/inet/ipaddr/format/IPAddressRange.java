/*
 * Copyright 2016-2024 Sean C Foley
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

package inet.ipaddr.format;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.stream.Stream;

import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressAggregation;
import inet.ipaddr.IPAddressContainmentTrieBase;
import inet.ipaddr.IPAddressSeqRange;
import inet.ipaddr.IPAddressSeqRangeList;
import inet.ipaddr.format.util.AddressComponentRangeSpliterator;
import inet.ipaddr.format.util.AddressComponentSpliterator;

/**
 * Represents a range of IP addresses
 * 
 * @author seancfoley
 *
 */
public interface IPAddressRange extends IPAddressAggregation<IPAddress, IPAddressSeqRange>, AddressComponentRange {
	/**
	  * Returns the number of individual addresses in this range.
	  * 
	  * @return
	  */
	@Override
	default BigInteger getCount() {
		return AddressComponentRange.super.getCount();
	}
    
    /**
	 * Returns true if there is more than one address in this range.
	 * 
	 * @return
	 */
    @Override
	boolean isMultiple();
	
	/**
	 * Indicates where an address sits relative to the range ordering.
	 * <p>
	 * Determines how many address elements of a range precede the given address element, if the address is in the range.
	 * If above the range, it is the distance to the upper boundary added to the range count less one, and if below the range, the distance to the lower boundary.
	 * <p>
	 * In other words, if the given address is not in the range but above it, returns the number of addresses preceding the address from the upper range boundary, 
	 * added to one less than the total number of range addresses.  If the given address is not in the subnet but below it, returns the number of addresses following the address to the lower subnet boundary.
	 * <p>
	 * Returns null when the argument is multi-valued. The argument must be an individual address.
	 * <p>
	 * When this is also an individual address, the returned value is the distance (difference) between the two address values.
	 * <p>
	 * If the given address does not have the same version or type, then null is returned.
	 * 
	 * @param other
	 * @return
	 */
	BigInteger enumerate(IPAddress other);

	/**
	 * Useful for using an instance in a "for-each loop", as in <code>for(addr : address.getIterable()) { ... }</code>
	 * <p>
	 * Otherwise just call {@link #iterator()} directly.
	 * @return
	 */
	@Override
	Iterable<? extends IPAddress> getIterable();

	/**
	 * Partitions and traverses through the individual addresses.
	 * 
	 * @return
	 */
	@Override
	AddressComponentRangeSpliterator<? extends IPAddressRange, ? extends IPAddress> spliterator();

	/**
	 * Iterates through the range of prefix blocks in this range instance using the given prefix length.
	 * 
	 * @param prefLength
	 * @return
	 */
	Iterator<? extends IPAddress> prefixBlockIterator(int prefLength);

	/**
	 * Partitions and traverses through the individual prefix blocks for the given prefix length.
	 * 
	 * @return
	 */
	AddressComponentRangeSpliterator<? extends IPAddressRange, ? extends IPAddress> prefixBlockSpliterator(int prefLength);
	
	/**
	 * Returns a sequential stream of the prefix blocks for the given prefix length.  For a parallel stream, call {@link Stream#parallel()} on the returned stream.
	 * 
	 * @return
	 */
	Stream<? extends IPAddress> prefixBlockStream(int prefLength);

	/**
	 * Iterates through the range of prefixes in this range instance using the given prefix length.
	 * 
	 * @param prefixLength
	 * @return
	 */
	Iterator<? extends IPAddressRange> prefixIterator(int prefixLength);

	/**
	 * Partitions and traverses through the individual prefixes for the given prefix length.
	 * 
	 * @return
	 */
	AddressComponentSpliterator<? extends IPAddressRange> prefixSpliterator(int prefLength);

	/**
	 * Returns a sequential stream of the individual prefixes for the given prefix length.  For a parallel stream, call {@link Stream#parallel()} on the returned stream.
	 * 
	 * @return
	 */
	Stream<? extends IPAddressRange> prefixStream(int prefLength);

	/**
	 * Produces a minimal array of prefix blocks that spans the same set of addresses.
	 */
	IPAddress[] spanWithPrefixBlocks();

	/**
	 * Produces a minimal array of blocks that are sequential that cover the same set of addresses.
	 * This array can be shorter than that produced by {@link #spanWithPrefixBlocks()} and is never longer.
	 */
	IPAddress[] spanWithSequentialBlocks();

	/**
	 * @deprecated renamed to coverWithSequentialRange to reflect the fact that the returned range does not always represent the same set of addresses 
	 */
	@Deprecated
	IPAddressSeqRange toSequentialRange();

	/**
	 * Creates a sequential range list from the address, which will contain the same set of individual addresses as this range of addresses.
	 * <p>
	 * Unlike {@link #coverWithSequentialRange()}, the returned list will always contain the same set of addresses as this range, regardless of whether this range of addresses is sequential or not.
	 * 
	 * @return
	 */
	IPAddressSeqRangeList intoSequentialRangeList();
	
	/**
	 * Creates a containment trie from the address, which will contain the same set of individual addresses as this range of addresses.
	 * <p>
	 * While the trie will contain blocks that will differ from this address if this address is not a prefix block or individual address, 
	 * the returned trie will always contain the same set of individual addresses as this range, regardless of whether this range of addresses is sequential or not.
	 * 
	 * @return
	 */
	IPAddressContainmentTrieBase<? extends IPAddress, ? extends IPAddressSeqRange> intoContainmentTrie();
	
	/**
	 * Returns the complement of the address range within the address space.
	 * <p>
	 * Returns a minimal array of IP address sequential ranges instances containing the addresses not contained within this address range.
	 * 
	 * @return
	 */
	IPAddressRange[] complement();

	/**
	 * Produces a string that is unique and consistent for all instances.
	 * @return
	 */
	String toNormalizedString();
	
	/**
	 * Produces a string that is unique and uses the canonical representation for all instances.
	 * @return
	 */
	String toCanonicalString();
}
