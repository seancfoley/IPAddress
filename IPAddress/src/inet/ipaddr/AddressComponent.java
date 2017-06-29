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

package inet.ipaddr;

import java.util.Iterator;

import inet.ipaddr.format.AddressItem;


// The hierarchy is shown in various views
//
// Component view (show a picture showing the relationship between segment/section/address)
// AddressComponent
// | |
// | AddressSegment
// AddressSegmentSeries
// | |
// | AddressSection
// Address
//
//
//Division series view - ways of dividing up addresses into groups of bits
// AddressDivisionSeries
// | |
// | AddressDivisionGrouping (base class for all division groupings, grouping into non-equal length divisions, each division any number of bits)
// AddressSegmentSeries (segment series - grouping into equal length segments, each a whole number of bytes)
// |
// from here you can reference the component view 
// for divisions of addresses that use segments (a segment has a whole numbers of bytes that equals the same byte size of all other segments in the same address)
//
//
//Division view
//AddressDivisionBase
// | |
// | AddressLargeDivision (used for base 85)
// AddressDivision
// | | |
// | | MACDottedSegment
// | MACAddressSegment
// IPAddressDivision
// | | |
// | | IPAddressBitsDivision (currently used for dividing by mutiples of 3 bits for octal)
// | IPAddressJoinedSegments (for joining segments together)
// | |
// | IPv4JoinedSegments (currently used for inet_aton style of joining segments together)
// IPAddressSegment (base class for IPv4 or IPv6 standard segment size)
// | |
// | IPv4AddressSegment
// IPv6AddressSegment
// Here you should expend AddressDivision into all the different divisions and segments
//
//
//
// Everything view
// AddressItem
// | | |
// | | AddressComponent all address components
// | AddressDivisionBase all divisions
// AddressDivisionSeries all series of divisions
//
//
//
//String producer view -
//AddressDivisionSeries and IPAddressDivisionGrouping are not string specific and shown elsewhere.
//The other four are string specific and have "String" in their names.
// AddressStringDivisionSeries
// | | |
// | | AddressStringDivisionGrouping  (for the large division)
// | AddressDivisionSeries (most address division groupings, either segment-based or division-based))
// IPAddressStringDivisionSeries
// | |
// | IPAddressStringDivisionGrouping (for the large division)
// IPAddressDivisionGrouping (most ip address division groupings)
//
public interface AddressComponent extends AddressItem {
	
	/**
	 * If this instance represents multiple address components, returns the one with the lowest numeric value.
	 * 
	 * @return
	 */
	AddressComponent getLower();
	
	/**
	 * If this instance represents multiple address components, returns the one with the highest numeric value.
	 * 
	 * @return
	 */
	AddressComponent getUpper();

	/**
	 * returns the number of bytes in each of the address components represented by this instance
	 * 
	 * @return
	 */
	int getByteCount();
	
	/**
	 * Useful for using an instance in a "for-each loop".  Otherwise just call {@link #iterator()} directly.
	 * @return
	 */
	Iterable<? extends AddressComponent> getIterable();

	/**
	 * An address component can represent a single segment, address, or section, or it can represent multiple,
	 * typically a subnet or range of segment, address, or section values.
	 * 
	 * Call {@link #isMultiple()} to determine if this instance represents multiple.
	 * 
	 * This method iterates through the individual elements.
	 * 
	 * @return
	 */
	Iterator<? extends AddressComponent> iterator();

	/**
	 * Writes this address component as a single hexadecimal value with always the exact same number of characters, with or without a preceding 0x prefix.
	 * 
	 * If this section represents a range of values outside of the network prefix length, then this is printed as a range of two hex values.
	 */
	String toHexString(boolean with0xPrefix);

	/**
	 * Produces a string that is somewhat similar for all address components of the same type.
	 * @return
	 */
	String toNormalizedString();
	
	/**
	 * Returns a new AddressComponent with the bits reversed.
	 * 
	 * If this component represents a range of values that cannot be reversed, then this throws AddressTypeException.  In a range the most significant bits stay constant
	 * while the least significant bits range over different values, so reversing that scenario results in a series of non-consecutive values, in most cases,
	 * which cannot be represented with a single AddressComponent object.
	 * 
	 * In such cases where isMultiple() is true, call iterator(), getLower(), getUpper() or some other methods to break the series down into a series representing a single value.
	 * 
	 * @param perByte if true, only the bits in each byte are reversed, if false, then all bits in the component are reversed
	 * @throw AddressTypeException if isMultiple() returns true, since most ranges when reversed are no longer ranges
	 * @return
	 */
	AddressComponent reverseBits(boolean perByte);
	
	/**
	 * Returns an AddressComponent with the bytes reversed.
	 * 
	 * If this component represents a range of values that cannot be reversed, then this throws AddressTypeException.  In a range the most significant bits stay constant
	 * while the least significant bits range over different values, so reversing that scenario results in a series of non-consecutive values, in most cases,
	 * which cannot be represented with a single AddressComponent object.
	 * 
	 * In such cases where isMultiple() is true, call iterator(), getLower(), getUpper() or some other methods to break the series down into a series representing a single value.
	 * 
	 * @throw AddressTypeException if isMultiple() returns true, since most ranges when reversed are no longer ranges
	 * @return
	 */
	AddressComponent reverseBytes();
}
