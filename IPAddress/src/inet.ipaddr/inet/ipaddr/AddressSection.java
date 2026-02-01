/*
 * Copyright 2016-2024 Sean C Foley
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

import java.math.BigInteger;
import java.util.Iterator;
import java.util.stream.Stream;

import inet.ipaddr.format.util.AddressComponentSpliterator;

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
	 * Determines if one section overlaps another.
	 * <p>
	 * Sections must have the same number of segments to be comparable.
	 * <p>
	 * For sections which are aware of their position in an address (IPv6 and MAC), their respective positions must match to be comparable.
	 * 
	 * @param other
	 * @return whether this section overlaps the given address section
	 */
	boolean overlaps(AddressSection other);

	/**
	 * Indicates where an address section sits relative to the ordering of individual address sections within this section.
	 * <p>
	 * Determines how many address section elements precede the given address section element, if the given address section is within this address section.
	 * If above the range, it is the distance to the upper boundary added to the address section count less one, and if below the range, the distance to the lower boundary.
	 * <p>
	 * In other words, if the given address section is not in this section but above it, returns the number of individual address sections preceding the given address section from the upper section boundary, 
	 * added to one less than the total number of individual address sections within.  If the given address section is not in this section but below it, returns the number of individual address sections following the given address section to the lower section boundary.
	 * <p>
	 * enumerate returns null when the argument is a multi-valued section. The argument must be an individual address section.
	 * <p>
	 * When this address section is also single-valued, the returned value is the distance (difference) between this address section and the argument address section.
	 * <p>
	 * enumerate is the inverse of the increment method:
	 * <ul><li>section.enumerate(section.increment(inc)) = inc</li>
	 * <li>section.increment(section.enumerate(individualSection)) = individualSection</li></ul>
	 *
	 * If the given address section does not have the same version or type as this address section, then null is returned.
	 * If the given address section is the same version and type, but has a different segment count, then SizeMismatchException is thrown.
	 */
	BigInteger enumerate(AddressSection other);

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

	@Override @Deprecated
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

	@Deprecated
	@Override
	AddressSection applyPrefixLength(int networkPrefixLength);

	@Override
	Iterable<? extends AddressSection> getIterable();

	@Override
	Iterator<? extends AddressSection> iterator();

	@Override
	AddressComponentSpliterator<? extends AddressSection> spliterator();

	@Override
	Stream<? extends AddressSection> stream();

	@Override
	Iterator<? extends AddressSection> prefixIterator();

	@Override
	AddressComponentSpliterator<? extends AddressSection> prefixSpliterator();

	@Override
	public abstract Stream<? extends AddressSection> prefixStream();

	@Override
	Iterator<? extends AddressSection> prefixBlockIterator();

	@Override
	AddressComponentSpliterator<? extends AddressSection> prefixBlockSpliterator();

	@Override
	public abstract Stream<? extends AddressSection> prefixBlockStream();

	@Override
	AddressSection increment(long increment);
	
	@Override
	AddressSection increment(BigInteger increment);

	@Override
	AddressSection incrementBoundary(long increment);

	@Override
	AddressSegmentSeries increment();

	@Override
	AddressSegmentSeries decrement();

	@Override
	AddressSegmentSeries incrementBoundary();
}
