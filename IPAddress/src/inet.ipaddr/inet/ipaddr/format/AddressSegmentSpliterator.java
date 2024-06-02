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
import java.util.Iterator;
import java.util.function.Consumer;
import java.util.function.Supplier;

import inet.ipaddr.AddressSegment;
import inet.ipaddr.format.AddressDivisionBase.IntBinaryIteratorProvider;
import inet.ipaddr.format.AddressDivisionBase.SegmentCreator;
import inet.ipaddr.format.util.AddressComponentSpliterator;

/**
 * AddressSegmentSpliterator provides a {@link java.util.Spliterator} implementation for segment types in this library.
 * <p>
 * The implementation of estimateSize() and getExactSizeIfKnown() provide exact sizes at all times.
 * <p>
 * An AddressSegmentSpliterator instance has the spliterator characteristics of being concurrent, non-null, sorted, ordered, distinct, sized and sub-sized. 
 * <p>
 * Unlike the default spliterator that you get with any iterator, which has linear-time splitting, all instances of AddressSegmentSpliterator split in constant-time,
 * therefore allowing for instant fully parallel iteration over subnets or subnet components.
 * <p>
 * Any AddressSegmentSpliterator of size of 2 or larger can be split at any time.
 * <p>
 * An instance of AddressSegmentSpliterator is not thread-safe.  
 * Parallel iteration derives from handing each additional AddressSegmentSpliterator returned from trySplit() to other threads.
 * 
 * 
 * @author seancfoley
 *
 * @param <T>
 */
class AddressSegmentSpliterator<T extends AddressSegment>
	extends SpliteratorBase<T, T> implements AddressComponentSpliterator<T> {
	
	private Iterator<T> iterator;
	private T splitForIteration, currentForIteration;
	
	// either segment values or segment prefix values
	private int value;
	private int upperValue;

	private Supplier<Iterator<T>> iteratorProvider;
	protected boolean isLowest;
	private final boolean isHighest;

	private final IntBinaryIteratorProvider<T> subIteratorProvider;
	private final SegmentCreator<T> itemProvider;

	AddressSegmentSpliterator(
			int value,
			int upperValue,
			Supplier<Iterator<T>> iteratorProvider,
			IntBinaryIteratorProvider<T> subIteratorProvider,
			SegmentCreator<T> itemProvider) {
		this(null, value, upperValue, iteratorProvider, subIteratorProvider, itemProvider);
	}
	
	AddressSegmentSpliterator(
			T splitForIteration,
			int value,
			int upperValue,
			Supplier<Iterator<T>> iteratorProvider,
			IntBinaryIteratorProvider<T> subIteratorProvider,
			SegmentCreator<T> itemProvider) {
		this(value, upperValue, iteratorProvider, subIteratorProvider, true, true, itemProvider);
		this.splitForIteration = splitForIteration;
	}
	
	private AddressSegmentSpliterator(
			int value,
			int upperValue,
			Supplier<Iterator<T>> iteratorProvider,
			IntBinaryIteratorProvider<T> subIteratorProvider,
			boolean isLowest,
			boolean isHighest,
			SegmentCreator<T> itemProvider) {
		this.iteratorProvider = iteratorProvider;
		this.subIteratorProvider = subIteratorProvider;
		this.isLowest = isLowest;
		this.isHighest = isHighest;
		this.itemProvider = itemProvider;
		this.value = value;
		this.upperValue = upperValue;
	}

	private int getCurrentValue() {
		return value + ((int) iteratedCountL);
	}

	@Override
	public BigInteger getSize() {
		return BigInteger.valueOf(estimateSize());
	}

	/**
	 * Returns an exact count of the number of elements that would be
     * encountered by a {@link #forEachRemaining} traversal.
	 * @return
	 */
	@Override
	public long estimateSize() {
		return ((long) upperValue) - getCurrentValue() + 1;
	}

	public T getCurrentItem() {
		if(estimateSize() == 0) {
			return null;
		}
		T item = currentForIteration;
		if(item == null) {
			currentForIteration = item = itemProvider.applyAsInt(getCurrentValue(), upperValue);
		}
		return item;
	}

	@Override
	public T getAddressItem() {
		T item = splitForIteration;
		if(item == null) {
			splitForIteration = item = itemProvider.applyAsInt(value, upperValue);
		}
		return item;
	}

	private Iterator<T> provideIterator() {
		if(iterator == null) {
			if(iteratorProvider != null) {
				iterator = iteratorProvider.get();
			} else {
				iterator = subIteratorProvider.applyAsInt(isLowest, isHighest, value, upperValue);
			}
		}
		return iterator;
	}

	@Override
	public boolean tryAdvance(Consumer<? super T> action) {
		if(!inForEach && getCurrentValue() < upperValue) {
			currentForIteration = null;
			return tryAdvance(provideIterator(), action);
		}
		return false;
	}

	@Override
	public void forEachRemaining(Consumer<? super T> action) {
		if(inForEach) {
			return;
		}
		inForEach = true;
		try {
			currentForIteration = null;
			forEachRemaining(provideIterator(), action, (upperValue - value) + 1);
		} finally {
			inForEach = false;
		}
	}

	@Override
	public AddressComponentSpliterator<T> trySplit() {
		if(inForEach) {
			return null;
		}
		int lower = getCurrentValue();
		int size = upperValue - lower;
		if(size <= 1) {
			return null;
		}
		splitForIteration = null;
		currentForIteration = null;
		iteratorProvider = null;
		int mid = lower + (size >>> 1);
		value = mid + 1;
		iteratedCountL = 0;
		AddressSegmentSpliterator<T> result = new AddressSegmentSpliterator<T>(lower, mid, null, subIteratorProvider, isLowest, false, itemProvider);
		result.iterator = iterator;
		isLowest = false;
		iterator = null;
		return result;
	}
}
