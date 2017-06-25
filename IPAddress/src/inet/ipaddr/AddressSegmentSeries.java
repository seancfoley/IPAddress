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

import inet.ipaddr.format.AddressDivisionSeries;

/**
 * Represents a series of address segments, each of equal byte size, the byte size being a whole number of bytes.
 * 
 * Each segment can potentially range over multiple values, and thus this series of segments can represent many different values as well.
 * 
 * 
 * @author sfoley
 *
 */
public interface AddressSegmentSeries extends AddressDivisionSeries, AddressComponent {
	
	int getSegmentCount();
	
	int getBitsPerSegment();
	
	int getBytesPerSegment();
	
	/**
	 * Gets the subsection from the series starting from the given index
	 * 
	 * @throws IndexOutOfBoundsException if index < 0
	 * @param index
	 * @return
	 */
	AddressSection getSection(int index);
	
	/**
	 * Gets the subsection from the series starting from the given index and ending just before the give endIndex
	 * 
	 * @throws IndexOutOfBoundsException if index < 0 or endIndex extends beyond the end of the series
	 * @param index
	 * @param endIndex
	 * @return
	 */
	AddressSection getSection(int index, int endIndex);

	AddressSegment getSegment(int index);
	
	void getSegments(AddressSegment segs[]);
	
	/**
	 * get the segments from start to end and insert into the segs array at the the given index
	 * @param start
	 * @param end
	 * @param segs
	 * @param index
	 */
	void getSegments(int start, int end, AddressSegment segs[], int index);
	
	AddressSegment[] getSegments();
	
	@Override
	AddressSegmentSeries getLower();
	
	@Override
	AddressSegmentSeries getUpper();
	
	@Override
	Iterable<? extends AddressSegmentSeries> getIterable();
	
	@Override
	Iterator<? extends AddressSegmentSeries> iterator();
	
	Iterator<? extends AddressSegment[]> segmentsIterator();

	/**
	 * Produces the canonical representation of the address
	 * @return
	 */
	String toCanonicalString();

	/**
	 * Produces a short representation of the address while remaining within the confines of standard representation(s) of the address
	 * @return
	 */
	String toCompressedString();
	
	/**
	 * Returns a new segment series with the segments reversed.
	 * 
	 * This does not throw AddressTypeException.
	 * 
	 * @return
	 */
	AddressSegmentSeries reverseSegments();
	
	/**
	 * Returns a new segment series with the bits reversed.
	 * 
	 * @throws AddressTypeException if reversing the bits within a single segment cannot be done 
	 * because the segment represents a range, and when all values in that range are reversed, the result is not contiguous.
	 * 
	 * In practice this means that to be reversible the range must include all values except possibly the largest and/or smallest.
	 * 
	 * @return
	 */
	@Override
	AddressSegmentSeries reverseBits(boolean perByte);

	/**
	 * Returns a new segment series with the bytes reversed.
	 * 
	 * @throws AddressTypeException if the segments have more than 1 bytes, 
	 * and if reversing the bits within a single segment cannot be done because the segment represents a range that is not the entire segment range.
	 * 
	 * @return
	 */
	@Override
	AddressSegmentSeries reverseBytes();
	
	/**
	 * Returns a new segment series with the bytes reversed within each segment.
	 * 
	 * @throws AddressTypeException if the segments have more than 1 bytes, 
	 * and if reversing the bits within a single segment cannot be done because the segment represents a range that is not the entire segment range.
	 * 
	 * @return
	 */
	AddressSegmentSeries reverseBytesPerSegment();
	
	/**
	 * Removes the prefix.  
	 * 
	 * When the series already had a prefix, the bits previously not within the prefix are zero.
	 * 
	 * @param nextSegment
	 * @return
	 */
	AddressSegmentSeries removePrefixLength();
	
	/**
	 * Increases or decreases prefix length to the next segment boundary.
	 * 
	 * When prefix length is increased, the bits moved within the prefix are zero.
	 * 
	 * @param nextSegment
	 * @return
	 */
	AddressSegmentSeries adjustPrefixBySegment(boolean nextSegment);
	
	/**
	 * Increases or decreases prefix length by the given increment.
	 * 
	 * When prefix length is increased, the bits moved within the prefix become zero.
	 * 
	 * When the prefix is extended beyond the segment series boundary, it is removed.
	 * 
	 * @param nextSegment
	 * @return
	 */
	AddressSegmentSeries adjustPrefixLength(int adjustment);
	
	/**
	 * Sets the prefix length.
	 * 
	 * When the series already had a prefix, and the prefix length is increased, the bits moved within the prefix are zero.
	 * 
	 * When the prefix is extended beyond the segment series boundary, it is removed.
	 * 
	 * @param nextSegment
	 * @return
	 */
	AddressSegmentSeries setPrefixLength(int prefixLength);
	
	/**
	 * Applies the given prefix length to create a new segment series representing all segment series starting with the same prefix.
	 * 
	 * When this series already has a prefix length that is smaller, then this method returns this series.
	 */
	AddressSegmentSeries applyPrefixLength(int networkPrefixLength);
}
