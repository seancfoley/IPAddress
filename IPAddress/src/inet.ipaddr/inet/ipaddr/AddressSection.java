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

/**
 * @author sfoley
 *
 */
public interface AddressSection extends AddressSegmentSeries {
	
	/**
	 * Determines if one section contains another.
	 * <p>
	 * Sections must have the same number of segments to be comparable.
	 * <p>
	 * For sections which are aware of their position in an address (IPv6 and MAC), their respective positions must match to be comparable.
	 * 
	 * @param other
	 * @return whether this section contains the given address section
	 */
	boolean contains(AddressSection other);
	
	/**
	 * Determines if the argument section matches this section up to the prefix length of this section.
	 * <p>
	 * The entire prefix of this section must be present in the other section to be comparable.  
	 * <p>
	 * For sections which are aware of their position in an address (IPv6 and MAC), 
	 * the argument section must have the same or an earlier position in the address to match all prefix segments of this section,
	 * and the matching is lined up relative to the position.
	 * 
	 * @param other
	 * @return whether the argument section has the same address section prefix as this
	 */
	boolean prefixEquals(AddressSection other);
	
	@Override
	AddressSection getLower();
	
	@Override
	AddressSection getUpper();
	
	@Override
	AddressSection reverseSegments();
	
	@Override
	AddressSection reverseBits(boolean perByte);
	
	@Override
	AddressSection reverseBytes();
	
	@Override
	AddressSection reverseBytesPerSegment();
	
	@Override
	AddressSection toPrefixBlock();

	@Override
	AddressSection removePrefixLength();
	
	@Override
	AddressSection withoutPrefixLength();
	
	@Override @Deprecated
	AddressSection removePrefixLength(boolean zeroed);

	@Override
	AddressSection adjustPrefixBySegment(boolean nextSegment);
	
	@Override
	AddressSection adjustPrefixBySegment(boolean nextSegment, boolean zeroed);

	@Override
	AddressSection adjustPrefixLength(int adjustment);

	@Override
	AddressSection adjustPrefixLength(int adjustment, boolean zeroed);

	@Override
	AddressSection setPrefixLength(int prefixLength);

	@Override
	AddressSection setPrefixLength(int prefixLength, boolean zeroed);

	@Override
	AddressSection applyPrefixLength(int networkPrefixLength);

	@Override
	Iterable<? extends AddressSection> getIterable();

	@Override
	Iterator<? extends AddressSection> iterator();
	
	@Override
	Iterator<? extends AddressSection> prefixIterator();
	
	@Override
	Iterator<? extends AddressSection> prefixBlockIterator();
	
	@Override
	AddressSection increment(long increment);

	@Override
	AddressSection incrementBoundary(long increment);
}
