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
	 * @return > 0 if this AddressDivisionSeries has a larger count than the provided, 0 if they are the same, < 0 if the other has a larger count.
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
	 * 
	 * Typically this is the largest number of bits in the upper-most portion of the section for which the remaining bits assume all possible values.
	 * 
	 * For IP addresses, this must be explicitly defined when the address is created. For example, 1.2.0.0/16 has a prefix length of 16, while 1.2.*.* has no prefix length,
	 * even though they both represent the same set of addresses and are considered equal.  Prefixes can be considered variable for any given IP addresses and can
	 * depend on the routing table.
	 *  
	 * The methods getMinPrefix and getEquivalentPrefix can help you to obtain or define a prefix length if one does not exist already.  
	 * 1.2.0.0/16 and 1.2.*.* both the same equivalent and minimum prefix length of 16.
	 * 
	 * For MAC addresses, the prefix is implicit, so 1:2:3:*:*:* has a prefix length of 24 by definition.  Generally prefixes are not variable for a given address.   
	 * Either an address has a prefix or not, the one assigned by the IEEE.  
	 * 
	 * There is no way to explicitly define the prefix in a representation of a MAC address.  The prefix length is instead determined by the address itself when created.
	 */
	Integer getPrefixLength();
	
	/**
	 * whether there is a prefix and it is less than the bit-count
	 * 
	 * @return
	 */
	boolean isMultipleByPrefix();

	/**
	 * whether there is a prefix and the range of values is dictated entirely by the prefix.
	 * 
	 * @return
	 */
	boolean isRangeEquivalentToPrefix();

	/**
	 * Returns the smallest prefix length possible such that this address paired with that prefix length represents the exact same range of addresses.
	 * 
	 * If no such prefix exists, returns the bit length.
	 *
	 * @return the prefix length
	 */
	int getMinPrefix();
	
	/**
	 * Returns a prefix length for which the range of this division series can be specified only using the section's lower value and the prefix length.
	 * 
	 * If no such prefix exists, returns null.
	 * 
	 * If this segment grouping represents a single value, returns the bit length of the address.
	 * 
	 * @return the prefix length or null
	 */
	Integer getEquivalentPrefix();
}
