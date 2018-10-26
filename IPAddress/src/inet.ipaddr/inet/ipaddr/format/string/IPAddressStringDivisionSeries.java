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

package inet.ipaddr.format.string;

import inet.ipaddr.AddressNetwork;
import inet.ipaddr.IPAddressNetwork;
import inet.ipaddr.format.standard.AddressDivision;

/**
 * A generic part of an IP address for the purpose of producing a string for the address.
 * It is divided into a series of combinations of individual address divisions ({@link AddressDivision}).
 * The number of such series is the division count.
 * 
 * @author sfoley
 *
 */
public interface IPAddressStringDivisionSeries extends AddressStringDivisionSeries {
	
	IPAddressNetwork<?, ?, ?, ?, ?> getNetwork();
	
	@Override
	IPAddressStringDivision getDivision(int index);
	
	/**
	 * Returns whether this address section represents a subnet block of addresses corresponding to the prefix of this series.
	 * 
	 * Returns false if it has no prefix length, if it is a single address with a prefix length (ie not a subnet), or if it is a range of addresses that does not include
	 * the entire subnet block for its prefix length.
	 * 
	 * If {@link AddressNetwork#getPrefixConfiguration} is set to consider all prefixes as subnets, this returns true for any section with a non-null prefix length.
	 * 
	 * @return
	 */
	boolean isPrefixBlock();
	
	/**
	 * Whether there exists a prefix length
	 */
	boolean isPrefixed();

	/**
	 * The number of bits in the upper-most portion of the segment bits representing a prefix, while the remaining bits can assume all possible values.
	 *
	 * For an IP address returns the network prefix, which is 16 for an address like 1.2.0.0/16
	 * If there is no prefix length, returns null.
	 * 
	 * @return the prefix length or null if there is none
	 */
	Integer getPrefixLength();
}
