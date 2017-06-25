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
 * A generic part of an IP address for the purpose of producing a string for the address.
 * It is divided into a series of combinations of individual address divisions ({@link AddressDivision}).
 * The number of such series is the division count.
 * 
 * @author sfoley
 *
 */
public interface IPAddressStringDivisionSeries extends AddressStringDivisionSeries {
	/**
	 * Whether these exists a prefix.
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
