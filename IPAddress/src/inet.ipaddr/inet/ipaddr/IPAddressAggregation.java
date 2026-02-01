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
import java.util.Iterator;
import java.util.Spliterator;
import java.util.stream.Stream;

/**
 * An IPAddressAggregation represents an object instance that can represent an aggregation, a multitude, of individual addresses.
 * <p>
 * Types implementing this interface include {@link IPAddress} which represents either individual addresses or subnets, 
 * {@link IPAddressSeqRange} which represents sequential ranges, and the sub-interface {@link IPAddressCollection} which represents collections of IP addresses.
 * IP address collection implementations includes IPAddressSeqRangeList, a collection backed backed by sequential ranges, and IPAddressContainmentTrie, a collection backed by tries of CIDR prefix blocks.
 * 
 * @author scfoley
 *
 * @param <T>
 * @param <R>
 */
public interface IPAddressAggregation<T extends IPAddress, R extends IPAddressSeqRange> {
	/**
	 * Returns whether this aggregation of addresses contains all addresses in the given address or subnet
	 * 
	 * @param other
	 * @return
	 */
	boolean contains(T other);

	/**
	 * Returns whether this aggregation of addresses contains all addresses in the given sequential range
	 * 
	 * @param other
	 * @return
	 */
	boolean contains(R other);

	/**
	 * Returns whether this aggregation of addresses overlaps the addresses in the given address or subnet
	 * 
	 * @param other
	 * @return
	 */
	boolean overlaps(T other);

	/**
	 * Returns whether this aggregation of addresses overlaps the addresses in the given sequential range
	 * 
	 * @param other
	 * @return
	 */
	boolean overlaps(R other);

	/**
	 * Returns the address with the lowest numeric value in this aggregation of addresses.
	 * @return
	 */
	T getLower();

	/**
	 * Returns the address with the highest numeric value in this aggregation of addresses.
	 * @return
	 */
	T getUpper();

	/**
	 * Returns a sequential stream of the individual addresses.  For a parallel stream, call {@link Stream#parallel()} on the returned stream.
	 * 
	 * @return
	 */
	Stream<? extends T> stream();

	/**
	 * Returns an iterator of the individual addresses in ascending order, following the natural order of IPAddress from lowest numeric value to highest.
	 * 
	 * @return
	 */
	Iterator<? extends T> iterator();

	/**
	 * Returns a spliterator of the individual addresses.
	 * 
	 * @return
	 */
    Spliterator<? extends T> spliterator();

    /**
     * Returns the number of individual addresses in this aggregation of addresses.
     * 
     * @return
     */
    BigInteger getCount();
    
	/**
	 * Returns true if there is more than one address in this collection.
	 * This operation can be less expensive than calling getCount() and comparing to zero.
	 * 
	 * @return
	 */
	boolean isMultiple();

	/**
	 * Returns whether this aggregation of addresses contains an address that has the value of zero.
	 */
	boolean includesZero();

	/**
	 * Returns whether this aggregation of addresses contains an address that has the maximum address value for the address version of the addresses included in the collection.
	 */
	boolean includesMax();

	/**
	 * Returns whether the addresses in this aggregation are sequential.
	 * <p>
	 * An aggregation is sequential if, given any two addresses in the aggregation, any address between the two is also in the aggregation.
	 * If the aggregation has no addresses, it satisfies this condition.  In other words, an empty aggregation is sequential.
	 * @return
	 */
	boolean isSequential();
	
	/**
	 * Returns the unique sequential range of minimal size that includes all the addresses in this aggregation.
	 * If there are no addresses in this aggregation, then null is returned.
	 * <p>
	 * The result will represent the same set of addresses if and only if the set of addresses in this aggregation are sequential, in which {@link #isSequential() is true. 
	 */
	IPAddressSeqRange coverWithSequentialRange();

	/**
	 * Returns the unique CIDR prefix block subnet or individual address of minimal size that includes all the addresses in this aggregation.
	 * If there are no addresses in this aggregation, then null is returned.
	 */
	IPAddress coverWithPrefixBlock();
}
