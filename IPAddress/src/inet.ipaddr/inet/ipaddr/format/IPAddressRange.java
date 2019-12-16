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

package inet.ipaddr.format;

import java.util.Iterator;
import java.util.stream.Stream;

import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressSeqRange;
import inet.ipaddr.format.util.AddressComponentRangeSpliterator;
import inet.ipaddr.format.util.AddressComponentSpliterator;


public interface IPAddressRange extends AddressComponentRange {
	
	/**
	 * Returns whether this range contains all addresses in the given sequential range
	 * 
	 * @param other
	 * @return
	 */
	boolean contains(IPAddressSeqRange other);

	/**
	 * Returns whether this range contains all addresses in the given address or subnet
	 * 
	 * @param other
	 * @return
	 */
	boolean contains(IPAddress other);

	/**
	 * If this instance represents multiple individual addresses, returns the one with the lowest numeric value.
	 * 
	 * @return
	 */
	@Override
	IPAddress getLower();

	/**
	 * If this instance represents multiple individual addresses, returns the one with the highest numeric value.
	 * 
	 * @return
	 */
	@Override
	IPAddress getUpper();

	/**
	 * Useful for using an instance in a "for-each loop", as in <code>for(addr : address.getIterable()) { ... }</code>
	 * <p>
	 * Otherwise just call {@link #iterator()} directly.
	 * @return
	 */
	@Override
	Iterable<? extends IPAddress> getIterable();

	/**
	 * Iterates through the individual addresses of this address or subnet.
	 * <p>
	 * Call {@link #isMultiple()} to determine if this instance represents multiple, or {@link #getCount()} for the count.
	 * 
	 * @return
	 */
	@Override
	Iterator<? extends IPAddress> iterator();

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
	 * Returns the minimal-size prefix block that covers all the addresses in this range.
	 * The resulting block will have a larger address count than this range, unless this range is already a prefix block.
	 */
	IPAddress coverWithPrefixBlock();

	/**
	 * Produces an array of prefix blocks that spans the same set of addresses.
	 */
	IPAddress[] spanWithPrefixBlocks();

	/**
	 * Produces an array of blocks that are sequential that cover the same set of addresses.
	 * This array can be shorter than that produced by {@link #spanWithPrefixBlocks()} and is never longer.
	 */
	IPAddress[] spanWithSequentialBlocks();

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
