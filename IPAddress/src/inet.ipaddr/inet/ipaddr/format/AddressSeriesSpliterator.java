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
