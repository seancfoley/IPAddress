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

import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressSeqRange;


public interface IPAddressRange extends AddressItemRange {
	
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
	 * Iterates through the range of prefix blocks in this range instance using the given prefix length.
	 * 
	 * @param prefLength
	 * @return
	 */
	Iterator<? extends IPAddress> prefixBlockIterator(int prefLength);

	/**
	 * Iterates through the range of prefixes in this range instance using the given prefix length.
	 * 
	 * @param prefixLength
	 * @return
	 */
	Iterator<? extends IPAddressRange> prefixIterator(int prefixLength);

	/**
	 * Produces an array of prefix blocks that cover the same set of addresses.
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
