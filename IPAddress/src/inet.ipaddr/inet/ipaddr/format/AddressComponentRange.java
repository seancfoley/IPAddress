/*
 * Copyright 2016-2020 Sean C Foley
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

import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.function.Function;
import java.util.stream.Stream;

import inet.ipaddr.AddressComponent;
import inet.ipaddr.format.util.AddressComponentRangeSpliterator;

/**
 * Represents a range of address components
 * 
 * @author seancfoley
 *
 */
@SuppressWarnings("deprecation")
public interface AddressComponentRange extends AddressItem, AddressItemRange {
	/**
	 * If this instance represents multiple address items, returns the one with the lowest numeric value.
	 * 
	 * @return
	 */
	AddressComponent getLower();
	
	/**
	 * If this instance represents multiple address items, returns the one with the highest numeric value.
	 * 
	 * @return
	 */
	AddressComponent getUpper();
	
	/**
	 * Useful for using an instance in a "for-each loop".  Otherwise just call {@link #iterator()} directly.
	 * @return
	 */
	Iterable<? extends AddressComponent> getIterable();

	/**
	 * Iterates through the individual address components.
	 * <p>
	 * An address component can represent an individual segment, address, or section, or it can represent multiple,
	 * typically a subnet of addresses or a range of segment or section values.
	 * <p>
	 * Call {@link #isMultiple()} to determine if this instance represents multiple, or {@link #getCount()} for the count.
	 * 
	 * @return
	 */
	Iterator<? extends AddressComponent> iterator();

	/**
	 * Partitions and traverses through the individual address components.
	 * 
	 * @return
	 */
	AddressComponentRangeSpliterator<? extends AddressComponentRange, ? extends AddressComponent> spliterator();
	
	/**
	 * Returns a sequential stream of the individual address components.  For a parallel stream, call {@link Stream#parallel()} on the returned stream.
	 * 
	 * @return
	 */
	Stream<? extends AddressComponent> stream();
	
	/**
	 * Given a list of components, and a lambda that returns a stream for that component type, 
	 * returns a combined stream produced by applying that lambda to all the components.
	 * 
	 * @param addrStreamFunc
	 * @param components
	 * @return
	 */
	@SafeVarargs
	static <T extends AddressComponent> Stream<T> stream(Function<T, Stream<? extends T>> addrStreamFunc,  T ...components) {
		return Arrays.stream(components).map(addrStreamFunc).flatMap(s -> s);
	}
	
	/**
	 * Given a list of components, and a lambda that returns a stream for that component type, 
	 * returns a sequential combined stream produced by applying that lambda to all the components.
	 * For a parallel stream, call {@link Stream#parallel()} on the returned stream.
	 * 
	 * @param addrStreamFunc
	 * @param components
	 * @return
	 */
	static <T extends AddressComponent> Stream<T> stream(Function<T, Stream<? extends T>> addrStreamFunc,  Collection<? extends T> components) {
		return components.stream().map(addrStreamFunc).flatMap(s -> s);
	}
}
