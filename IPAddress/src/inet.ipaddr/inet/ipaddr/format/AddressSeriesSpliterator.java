/*
 * Copyright 2019 Sean C Foley
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

import java.math.BigInteger;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.ToLongFunction;

import inet.ipaddr.AddressComponent;
import inet.ipaddr.format.AddressDivisionGroupingBase.AddressItemRangeSpliterator;
import inet.ipaddr.format.AddressDivisionGroupingBase.IteratorProvider;
import inet.ipaddr.format.AddressDivisionGroupingBase.SplitterSink;
import inet.ipaddr.format.util.AddressComponentSpliterator;

/**
 * AddressSeriesSpliterator provides a Spliterator implementation for address components,
 * in which the items providing the iteration are the same type as the items that are the result of the iteration.
 * 
 * @author seancfoley
 *
 * @param <T>
 */
class AddressSeriesSpliterator<T extends AddressComponent>
	extends AddressItemRangeSpliterator<T, T> implements AddressComponentSpliterator<T> {
	
	AddressSeriesSpliterator(
			T forIteration,
			Predicate<SplitterSink<T,T>> splitter,
			IteratorProvider<T, T> iteratorProvider,
			Function<T, BigInteger> sizer /* can be null */,
			Predicate<T> downSizer,
			ToLongFunction<T> longSizer /* not to be used if sizer not null */) {
		super(forIteration, splitter, iteratorProvider, sizer, downSizer, longSizer);
	}
	
	AddressSeriesSpliterator(
			T forIteration,
			Predicate<SplitterSink<T,T>> splitter,
			IteratorProvider<T, T> iteratorProvider,
			boolean isLowest,
			Function<T, BigInteger> sizer /* can be null */,
			Predicate<T> downSizer,
			ToLongFunction<T> longSizer /* not to be used if sizer not null */) {
		super(forIteration, splitter, iteratorProvider, isLowest, false, sizer, downSizer, longSizer);
	}
	
	@Override
	protected AddressSeriesSpliterator<T> createSpliterator(
			T split, 
			boolean isLowest,
			Function<T, BigInteger> sizer,
			Predicate<T> downSizer,
			ToLongFunction<T> longSizer) {
		return new AddressSeriesSpliterator<T>(split, splitter, iteratorProvider, isLowest, sizer, downSizer, longSizer);
	}

	@Override
	public AddressSeriesSpliterator<T> trySplit() {
		return (AddressSeriesSpliterator<T>) super.trySplit();
	}
}
