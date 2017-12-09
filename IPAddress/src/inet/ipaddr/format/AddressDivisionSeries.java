/*
 * Copyright 2017 Sean C Foley
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

import inet.ipaddr.AddressNetwork;

/**
 * Represents a series of groups of address segments.  Each group may have a different bit size.
 * 
 * This interface is the super interface of all interfaces and classes representing a series of divisions or segments.
 * 
 * @author sfoley
 *
 */
public interface AddressDivisionSeries extends AddressItem, AddressStringDivisionSeries {
	/**
	 * Use this method to compare the counts of two address series.
	 * 
	 * Rather than calculating counts with getCount(), there can be more efficient ways of comparing whether one series represents more individual address series than another.
	 * 
	 * @return a positive integer if this AddressDivisionSeries has a larger count than the provided, 0 if they are the same, a negative integer if the other has a larger count.
	 */
	int isMore(AddressDivisionSeries other);
	
	/**
	 * @return the given division in this series.  The first is at index 0.
	 */
	@Override
	AddressDivision getDivision(int index);
	
	/**
	 * Whether there exists a prefix.
	 */
	boolean isPrefixed();

	/**
	 * The bit-length of the portion of the address that is not specific to an individual address but common amongst a group of addresses.
	 * <p>
	 * Typically this is the largest number of bits in the upper-most portion of the section for which the remaining bits assume all possible values.
	 * <p>
	 * For IP addresses, this must be explicitly defined when the address is created. For example, 1.2.0.0/16 has a prefix length of 16, while 1.2.*.* has no prefix length,
	 * even though they both represent the same set of addresses and are considered equal.  Prefixes can be considered variable for any given IP addresses and can
	 * depend on the routing table.
	 * <p>
	 * The methods {@link AddressDivisionSeries#getMinPrefixLengthForBlock()} and {@link AddressDivisionSeries#getPrefixLengthForSingleBlock()} can help you to obtain or define a prefix length if one does not exist already.  
	 * 1.2.0.0/16 and 1.2.*.* both the same equivalent and minimum prefix length of 16.
	 * <p>
	 * For MAC addresses, the prefix is initially defined by the range, so 1:2:3:*:*:* has a prefix length of 24 by definition.  Addresses derived from the original may retain the original prefix length regardless of their range.
	 * <p>
	 */
	Integer getPrefixLength();

	/**
	 * Returns whether this address segment series represents a block of addresses associated with its prefix length.
	 * <p>
	 * This returns false if it has no prefix length or if it is a range of addresses that does not include
	 * the entire subnet block for the prefix length.
	 * <p>
	 * If {@link AddressNetwork#getPrefixConfiguration} is set to consider all prefixes as subnets, this returns true for any series with a prefix length.
	 * 
	 * @return
	 */
	boolean isPrefixBlock();
	
	/**
	 * Returns whether the range of values matches a single subnet block for the prefix length
	 * 
	 * @return
	 */
	boolean isSinglePrefixBlock();

	/**
	 * Returns the smallest prefix length possible such that this address division series includes the block of addresses for that prefix.
	 * <p>
	 * If the entire range can be dictated this way, then this method returns the same value as {@link #getPrefixLengthForSingleBlock()}.  
	 * Otherwise, this method will return the minimal possible prefix that can be paired with this address, while {@link #getPrefixLengthForSingleBlock()} will return null.
	 * <p>
	 * In cases where the final bit in this address division series is constant, this returns the bit length of this address division series.
	 *
	 * @return the prefix length
	 */
	int getMinPrefixLengthForBlock();
	
	/**
	 * Returns a prefix length for which the range of this division series matches the the block of addresses for that prefix.
	 * <p>
	 * If the range can be dictated this way, then this method returns the same value as {@link #getMinPrefixLengthForBlock()}.
	 * <p>
	 * If no such prefix exists, returns null.
	 * <p>
	 * If this segment grouping represents a single value, returns the bit length of this address division series.
	 * 
	 * @return the prefix length or null
	 */
	Integer getPrefixLengthForSingleBlock();
	
	/**
	 * Get standard-format strings for each of the divisions in the series.
	 * 
	 * @return
	 */
	String[] getDivisionStrings();
	
	/**
	 * @return the value of the lowest address item represented by this address division series
	 */
	BigInteger getValue();
	
	/**
	 * @return the value of the highest address item represented by this address division series
	 */
	BigInteger getUpperValue();
}
