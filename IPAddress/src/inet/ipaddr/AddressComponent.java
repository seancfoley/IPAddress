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

import inet.ipaddr.format.AddressItemRange;


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
// IPAddressSegmentSeries
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
public interface AddressComponent extends AddressItemRange {
	/**
	 * Writes this address component as a single hexadecimal value with always the exact same number of characters, with or without a preceding 0x prefix.
	 * <p>
	 * If this component represents a range of values outside of the network prefix length, then this is printed as a range of two hex values.
	 * <p>
	 * For instance, for IPv4 addresses there are 8 hex characters, for IPv6 addresses there are 32 hex characters.
	 */
	String toHexString(boolean with0xPrefix);

	/**
	 * Produces a string that is consistent for all address components of the same type and version.
	 * @return
	 */
	String toNormalizedString();
	
	/**
	 * Returns a new AddressComponent with the bits reversed.
	 * 
	 * If this component represents a range of values that cannot be reversed, then this throws {@link IncompatibleAddressException}.  In a range the most significant bits stay constant
	 * while the least significant bits range over different values, so reversing that scenario results in a series of non-consecutive values, in most cases,
	 * which cannot be represented with a single AddressComponent object.
	 * <p>
	 * In such cases where isMultiple() is true, call iterator(), getLower(), getUpper() or some other methods to break the series down into a series representing a single value.
	 * 
	 * @param perByte if true, only the bits in each byte are reversed, if false, then all bits in the component are reversed
	 * @throws IncompatibleAddressException when subnet addresses cannot be reversed
	 * @return
	 */
	AddressComponent reverseBits(boolean perByte);
	
	/**
	 * Returns an AddressComponent with the bytes reversed.
	 * 
	 * If this component represents a range of values that cannot be reversed, then this throws {@link IncompatibleAddressException}.  In a range the most significant bits stay constant
	 * while the least significant bits range over different values, so reversing that scenario results in a series of non-consecutive values, in most cases,
	 * which cannot be represented with a single AddressComponent object.
	 * <p>
	 * In such cases where isMultiple() is true, call iterator(), getLower(), getUpper() or some other methods to break the series down into a series representing a single value.
	 * 
	 * @throws IncompatibleAddressException when subnet addresses cannot be reversed
	 * @return
	 */
	AddressComponent reverseBytes();
	
	@Override
	AddressComponent getLower();

	@Override
	AddressComponent getUpper();
	
	@Override
	Iterable<? extends AddressComponent> getIterable();

	/**
	 * Iterates through the individual elements of this address component.
	 * <p>
	 * An address component can represent a single segment, address, or section, or it can represent multiple,
	 * typically a subnet of addresses or a range of segment or section values.
	 * <p>
	 * Call {@link #isMultiple()} to determine if this instance represents multiple.
	 * 
	 * @return
	 */
	@Override
	Iterator<? extends AddressComponent> iterator();
}
