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

package inet.ipaddr;


import java.util.Iterator;

import inet.ipaddr.format.AddressGenericDivision;

/**
 * Represents a single segment of an address.
 * <p>
 * The current implementations of this class are the most common representations of IPv4, IPv6 and MAC; 
 * segments are 1 byte for Ipv4, they are two bytes for Ipv6, and they are 1 byte for MAC addresses.
 * <p>
 * There are alternative forms of dividing addresses into segments, such as dotted representation for MAC like 1111.2222.3333,
 * embedded IPv4 representation for IPv6 like f:f:f:f:f:f:1.2.3.4, inet_aton formats like 1.2 for IPv4, and so on.
 * <p>
 * If those alternative representations were to follow the general rules for segment representation, then you could reuse this class
 * for thos alternative representations.
 * <p>
 * The general rules are that segments have a whole number of bytes, and in a given address all segments have the same length.
 * <p>
 * When alternatives forms do not follow the general rules for segments,
 * you can use the {@link inet.ipaddr.format.standard.AddressDivision} interface instead.  
 * Divisions do not have the restriction that divisions of an address are equal length and a whole number of bytes.
 * Divisions can be grouped using {@link inet.ipaddr.format.standard.AddressDivisionGrouping}.
 * <p>
 * AddressSegment objects are immutable and thus also thread-safe.
 * 
 * @author sfoley
 *
 */
public interface AddressSegment extends AddressComponent, AddressGenericDivision {

	AddressNetwork<?> getNetwork();
	
	/**
	 * @return the same value as {@link #getCount()} as an integer
	 */
	int getValueCount();

	/**
	 * returns the lower value
	 */
	int getSegmentValue();
	
	/**
	 * returns the upper value
	 */
	int getUpperSegmentValue();
	
	/**
	 * If this segment represents a range of values, returns a segment representing just the lowest value in the range, otherwise returns this.
	 * @return
	 */
	@Override
	AddressSegment getLower();
	
	/**
	 * If this segment represents a range of values, returns a segment representing just the highest value in the range, otherwise returns this.
	 * @return
	 */
	@Override
	AddressSegment getUpper();
	
	@Override
	AddressSegment reverseBits(boolean perByte);
	
	@Override
	AddressSegment reverseBytes();
	
	@Override
	Iterable<? extends AddressSegment> getIterable();
	
	@Override
	Iterator<? extends AddressSegment> iterator();	
	
	boolean matches(int value);
	
	boolean matchesWithMask(int value, int mask);

	boolean matchesWithMask(int lowerValue, int upperValue, int mask);

	boolean contains(AddressSegment other);
	
	@Override
	boolean equals(Object other);
	
	boolean prefixEquals(AddressSegment other, int prefixLength);
	
	/**
	 * Gets the maximum possible value for this type of segment (for the highest range value of this particular segment, use {@link #getUpper()}
	 * 
	 * @return
	 */
	int getMaxSegmentValue();
}
