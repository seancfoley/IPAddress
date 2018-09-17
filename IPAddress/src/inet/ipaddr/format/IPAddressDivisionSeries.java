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

import inet.ipaddr.format.string.IPAddressStringDivisionSeries;

/**
 * Represents a series of groups of address divisions or segments.  Each group may have a different bit size.
 * 
 * This interface is the super interface of all interfaces and classes representing a series of divisions or segments.
 * 
 * @author sfoley
 *
 */
public interface IPAddressDivisionSeries extends AddressDivisionSeries, IPAddressStringDivisionSeries {
	/**
	 * Returns the CIDR network prefix length of the series, or null if the series has no associated prefix length.
	 * <p>
	 * Equivalent to {@link inet.ipaddr.format.AddressDivisionSeries#getPrefixLength()}, 
	 * which is the more general concept of set of address series that share the same set of leading bits.
	 * For IP addresses and sections the prefix length and the CIDR network prefix length are the same thing.
	 * <p>
	 * For IP addresses and sections each individual segment has an associated prefix length which is determine by the network prefix length.
	 * The segment prefix lengths follow the pattern:
	 *  null, null, ...., null, x, 0, 0, ..., 0
	 * <p>
	 * For instance, an IPv4 address 1.2.3.4/16 has the network prefix length 16.  The segment prefix lengths are [null, 8, 0, 0]
	 * The segment prefix lengths of 1.2.3.4/22 are [null, null, 6, 0]
	 * 
	 * @return
	 */
	Integer getNetworkPrefixLength();
	
	/**
	 * @return the given division in this series.  The first is at index 0.
	 */
	@Override
	IPAddressGenericDivision getDivision(int index);
}
