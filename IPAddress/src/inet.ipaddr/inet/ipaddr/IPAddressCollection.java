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

import java.io.Serializable;

/**
 * IPAddressCollection represents a collection of individual IP addresses.
 * <p>
 * An IPAddressCollection represents a collection that is more expansive and encompassing that an instance of IPAddress or IPAddressSeqRange.  
 * IPAddress represents a IP address subnet or a single IP address, expressed as an address, a CIDR prefix block, or as a subnet with specified segment ranges.  
 * IPAddressSeqRange represents a sequence of one or more consecutive IP addresses, with a starting and ending address.
 * Both can represent a single address.  Both can represent the entire address space for a given IP version.
 * However, both IPAddress and IPAddressSeqRange have structural constraints, constraints that prevent them from representing arbitrary collections of addresses.
 * An IPAddressCollection has no such limitations and can contain arbitrary collections of addresses.
 * <p>
 * It is also possible to maintain collections of individual IP addresses using the Java Collections types,
 * storing addresses individually.  But this is not efficient in terms of performance or memory.
 * Instances of IPAddressCollection are more efficient, storing addresses into a minimal number of prefix blocks or sequential ranges as possible.
 * <p>
 * Two implementations of this interface are provided: IPAddressSeqRangeList and IPAddressContainmentTrie.  They both have IPv4-specific and IPv6-specific counterparts.  
 * IPAddressSeqRangeList is backed by an array of sequential ranges.  IPAddressContainmentTrie is backed by a trie of CIDR prefix blocks.
 * Both offer binary search for containment queries.  
 * Whether one is better than the other may depend on the data set or the underlying processor, 
 * or whether you may need additional operations needed that are specific to one collection or the other.
 * 
 * @author scfoley
 *
 */
public interface IPAddressCollection<T extends IPAddress, R extends IPAddressSeqRange> extends IPAddressAggregation<T, R>, Cloneable, Serializable {
	/**
	 * Adds all the addresses in the given subnet, or the single individual address, to the collection.
	 * Returns true if the collection was changed.
	 * 
	 * @param addr
	 * @return
	 */
	boolean add(T addr);

	/**
	 * Adds all the addresses in the sequential range to the collection.
	 * Returns true if the collection was changed.
	 * 
	 * @param addr
	 * @return
	 */
	boolean add(R rng);

	/**
	 * Removes all the addresses in the given subnet, or the single individual address, from the collection.
	 * Returns true if the collection was changed.
	 * 
	 * @param addr
	 * @return
	 */
	boolean remove(T addr);

	/**
	 * Removes all the addresses in the sequential range from the collection.
	 * Returns true if the collection was changed.
	 * 
	 * @param addr
	 * @return
	 */
	boolean remove(R rng);

	/**
	 * Removes all addresses from this collection.
	 */
	void clear();

	/**
	 * Returns the highest address in the collection less than or equal to the given address.
	 * 
	 * @param addr
	 * @return
	 */
	T floor(T addr);

	/**
	 * Returns the highest address in the collection strictly less than the given address.
	 * 
	 * @param addr
	 * @return
	 */
	T lower(T addr);

	/**
	 * Returns the lowest address in the collection greater than or equal to the given address.
	 * 
	 * @param addr
	 * @return
	 */
	T ceiling(T addr);

	/**
	 * Returns the lowest address in the collection strictly greater than the given address.
	 * 
	 * @param addr
	 * @return
	 */
	T higher(T addr);

	/**
	 * Returns true if there are no addresses in this collection.
	 * 
	 * @return
	 */
	boolean isEmpty();
	
	/**
	 * Clones the collection
	 * 
	 * @return
	 */
	IPAddressCollection<T, R> clone();
}
