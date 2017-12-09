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

/**
 * @custom.core
 * @author sfoley
 *
 */
public interface AddressSection extends AddressSegmentSeries {
	
	/**
	 * Determines if one section contains another.
	 * 
	 * Sections must have the same number of segments to be comparable.
	 * 
	 * For sections which are aware of their position in an address (IPv6 and MAC), their respective positions must match to be comparable.
	 * 
	 * @param other
	 * @return whether this section contains the given address section
	 */
	boolean contains(AddressSection other);

	@Override
	AddressSection getSection(int index);

	@Override
	AddressSection getSection(int index, int endIndex);
	
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
	AddressSection removePrefixLength();

	@Override
	AddressSection adjustPrefixBySegment(boolean nextSegment);

	@Override
	AddressSection adjustPrefixLength(int adjustment);

	@Override
	AddressSection setPrefixLength(int prefixLength);

	@Override
	AddressSection applyPrefixLength(int networkPrefixLength);

	@Override
	Iterable<? extends AddressSection> getIterable();

	@Override
	Iterator<? extends AddressSection> iterator();
}
