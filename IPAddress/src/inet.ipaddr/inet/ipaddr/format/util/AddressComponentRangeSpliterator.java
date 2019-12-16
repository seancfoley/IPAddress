package inet.ipaddr.format.util;

import java.math.BigInteger;
import java.util.Comparator;
import java.util.Spliterator;

import inet.ipaddr.format.AddressComponentRange;

/**
 * AddressComponentSpliterator is a {@link java.util.Spliterator} for address items.
 * <p>
 * The implementation of estimateSize() and getExactSizeIfKnown() provide exact sizes if the size is no larger than Long.MAX_VALUE.
 * It also provides a getSize() method returning BigInteger providing the exact size at all times.
 * <p>
 * An AddressComponentSpliterator instance has the spliterator characteristics of being concurrent, non-null, sorted, ordered, and distinct. 
 * When the size is no larger than Long.MAX_VALUE, it is also sized and sub-sized, 
 * but practically speaking it is actually always sized and sub-sized since the exact size as a BigInteger is always available from getSize(),
 * which is not a part of the {@link java.util.Spliterator} interface.
 * <p>
 * Unlike the default spliterator that you get with any iterator, which has linear-time splitting, all instances of AddressItemRangeSpliterator split in constant-time,
 * therefore allowing for instant parallel iteration over subnets or subnet components.
 * <p>
 * Splitting can be attempted at any time, including after iteration has started.  All spliterators will split the address component range roughly in half.
 * Segment spliterators will split the remaining range exactly in half.  Other spliterators will split the original range roughly in half.
 * <p>
 * An instance of AddressItemRangeSpliterator is not thread-safe.  
 * Parallel iteration derives from handing each additional AddressItemRangeSpliterator returned from trySplit() to other threads.
 * 
 * 
 * @author seancfoley
 *
 * @param <T>
 */
public interface AddressComponentRangeSpliterator<S extends AddressComponentRange, T> extends Spliterator<T> {
	
	/**
	 * Returns an exact count of the number of elements that would be
     * encountered by a {@link #forEachRemaining} traversal.
	 * @return
	 */
	BigInteger getSize();

	/**
	 * @return the item corresponding to this spliterator when it was last split or created
	 */
	S getAddressItem();
	
	/**
     * If this spliterator can be partitioned, returns a Spliterator
     * covering elements, that will, upon return from this method, not
     * be covered by this Spliterator.
     *
     * <p>The returned Spliterator will cover a strict prefix of the elements, preserving the ordering of the address items.
     *
     * <p>Repeated calls to {@code trySplit()} will eventually return {@code null}.
     * Upon non-null return, the sizes of the new spliterator and this spliterator as given by {@link #getSize()}
     * will add up to the size of this spliterator before splitting.
     *
     *<p>The remaining elements of segment spliterators will be divided exactly in half.
     *<p>
     * Other address item spliterators divide the original address item roughly in half, not the remaining elements.
     * Because the original address item is divided instead of dividing the remaining elements, 
     * the resulting spliterators will not be roughly equal in size if 
     * a disproportionate amount of traversing using {@link #tryAdvance(java.util.function.Consumer)} occurred before splitting.
     * In fact, the splitting will not happen at all if half the elements
     * have already been traversed.
     *
     * @return a {@code Spliterator} covering some portion of the
     * elements, or {@code null} if this spliterator cannot be split
     */
	@Override
	AddressComponentRangeSpliterator<S, T> trySplit();
	
	@Override
	default Comparator<? super T> getComparator() {
       return null;
    }
}
