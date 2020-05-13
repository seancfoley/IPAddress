/*
 * Copyright 2020 Sean C Foley
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
package inet.ipaddr.format.util;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;

import inet.ipaddr.Address;
import inet.ipaddr.AddressSegmentSeries;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressSegmentSeries;

/**
 * Represents a partition of an element, such as a subnet,
 * into one or elements of the same type that represent the same set of values.
 * <p>
 * For instance, it can represent the partition of a subnet into prefix blocks, or a partition into individual addresses.
 * <p>
 * You can use the methods {@link #partitionWithSingleBlockSize(AddressSegmentSeries)} or {@link #partitionWithSpanningBlocks(IPAddress)}
 * to create a partition, or you can create your own.
 * <p>
 * You can use this class with the trie classes to easily partition an address for applying an operation to the trie.
 * Given an address or subnet s, you can partition into addresses or blocks that can used with a trie class using
 * <code>Partition.partitionWithSpanningBlocks(s)</code> or <code>Partition.partitionWithSingleBlockSize(s)</code>.
 * Once you have your partition, you choose a method in the Partition class whose argument type matches the signature of the trie method you wish to use.
 * <p>
 * For instance, you can use methods like {@link AddressTrieOps#contains(inet.ipaddr.Address)} or {@link AddressTrieOps#remove(inet.ipaddr.Address)} with {@link Partition#predicateForAny(Predicate)} or {@link Partition#predicateForEach(Predicate)} 
 * since the contains or remove method matches the Predicate interface.
 * Methods that return non-boolean values would match the {@link Partition#applyForEach(Function)} or {@link Partition#forEach(Consumer)} methods, as in the following code example for a given subnet s of type E:
 * <code>Map&lt;E, TrieNode&lt;E&gt;&gt; all = Partition.partitionWithSingleBlockSize(s).applyForEach(trie::getNode)</code>
 *
 * @author scfoley
 *
 * @param <E> the type being partitioned
 */
public class Partition<E> {
	/**
	 * The partitioned address.
	 */
	public final E original;
	
	/**
	 * A field containing a partition into a single value.
	 * <p>
	 * When {@link #blocks} is null, 
	 * the partition result is stored in this field.
	 * This will match {@link #original} in terms of equality,
	 * but might not have the same prefix length.
	 * 
	 */
	public final E single;
	
	/**
	 * An iterator supplying the partitioned addresses.
	 * <p>
	 * When {@link #single} is null, the partition result is stored in this field.
	 * <p>
	 * If the partition result is multiple addresses or blocks, 
	 * they are supplied by this iterator.
	 * <p>
	 * If the partition result is just a single address, 
	 * the result may be supplied by this iterator, or optionally this iterator may be null,
	 * in which case the result is given by {@link #single}.
	 */
	public final Iterator<? extends E> blocks;
	
	/**
	 * The address or block count.
	 * <p>
	 * If the result is greater than 1, the blocks are supplied by {@link #blocks}.
	 * If the result is 1, then the single block or address is supplied by {@link #blocks} if it is non-null,
	 * otherwise the single block or address is in {@link #single}.
	 */
	public final BigInteger count;
	
	public Partition(E original) {
		this.count = BigInteger.ONE;
		this.single = original;
		this.blocks = null;
		this.original = original;
	}
	
	public Partition(E original, E single) {
		this.count = BigInteger.ONE;
		this.single = single;
		this.blocks = null;
		this.original = original;
	}
	
	public Partition(E original, Iterator<? extends E> blocks, BigInteger count) {
		this.count = count;
		this.single = null;
		this.blocks = blocks;
		this.original = original;
	}
	
	
	public Partition(E original, Iterator<? extends E> blocks, int count) {
		this.count = BigInteger.valueOf(count);
		this.single = null;
		this.blocks = blocks;
		this.original = original;
	}

	/**
	 * Supplies to the given function each element of this partition,
	 * inserting non-null return values into the returned map.
	 * 
	 * @param <R>
	 * @param func
	 * @return
	 */
	public <R> Map<E, R> applyForEach(Function<? super E, ? extends R> func) {
		TreeMap<E, R> results = new TreeMap<>();
		forEach(address -> {
			R result = func.apply(address);
			if(result != null) {
				results.put(address, result);
			}
		});
		return results;
	}

	/**
	 * Supplies to the consumer each element of this partition.
	 * 
	 * @param action
	 */
	public void forEach(Consumer<? super E> action) {
		if(blocks == null) {
			action.accept(single);
		} else {
			Iterator<? extends E> iterator = blocks;
			while(iterator.hasNext()) {
				action.accept(iterator.next());
			}
		}
	}

	/**
	 * Applies the operation to each element of the partition,
	 * returning true if they all return true, false otherwise
	 * @param predicate
	 * @return
	 */
	public boolean predicateForEach(Predicate<? super E> predicate) {
		return predicateForEach(predicate, false);
	}

	/**
	 * Applies the operation to each element of the partition,
	 * returning true if they all return true, false otherwise
	 * @param predicate
	 * @param returnEarly returns as soon as one application of the predicate returns false (determining the overall result)
	 * @return
	 */
	public boolean predicateForEach(Predicate<? super E> predicate, boolean returnEarly) {
		if(blocks == null) {
			return predicate.test(single);
		}
		boolean result = true;
		Iterator<? extends E> iterator = blocks;
		while(iterator.hasNext()) {
			if(!predicate.test(iterator.next())) {
				result = false;
				if(returnEarly) {
					break;
				}
			}
		}
		return result;
	}

	/**
	 * Applies the operation to each element of the partition, 
	 * returning true if the given predicate returns true for any of the elements.
	 * 
	 * @param predicate
	 * @param returnEarly returns as soon as one call to the predicate returns true
	 * @return
	 */
	public boolean predicateForAny(Predicate<? super E> predicate, boolean returnEarly) {
		return !predicateForEach((addr) -> !predicate.test(addr), returnEarly);
	}

	/**
	 * Applies the operation to each element of the partition, 
	 * returning true if the given predicate returns true for any of the elements.
	 * 
	 * @param predicate
	 * @return
	 */
	public boolean predicateForAny(Predicate<? super E> predicate) {
		return predicateForAny(predicate, false);
	}

	/**
	 * Partitions the address series into prefix blocks and single addresses.
	 * <p>
	 * If null is returned, the argument is already an individual address or prefix block.
	 * <p>
	 * This method iterates through a list of prefix blocks of different sizes that span the entire subnet.
	 * 
	 * @param newAddr
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public static <E extends IPAddress> Partition<E> partitionWithSpanningBlocks(E newAddr) {
		if(!newAddr.isMultiple()) {
			if(!newAddr.isPrefixed()) {
				return new Partition<E>(newAddr);
			}
			return new Partition<E>(newAddr, (E) newAddr.withoutPrefixLength());
		} else if(newAddr.isSinglePrefixBlock()) {
			return new Partition<E>(newAddr);
		}
		E blocks[] = (E[]) newAddr.spanWithPrefixBlocks();
		Iterator<? extends E> blocksIterator = Arrays.asList(blocks).iterator();
		return new Partition<E>(newAddr, blocksIterator, blocks.length);
	}

	/**
	 * Partitions the address series into prefix blocks and single addresses.
	 * <p>
	 * If null is returned, the argument is already an individual address or prefix block.
	 * <p>
	 * This method chooses the maximum block size for a list of prefix blocks contained by the address or subnet,
	 *  and then iterates to produce blocks of that size.
	 * 
	 * @param newAddr
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public static <E extends AddressSegmentSeries> Partition<E> partitionWithSingleBlockSize(E newAddr) {
		if(!newAddr.isMultiple()) {
			if(!newAddr.isPrefixed()) {
				return new Partition<E>(newAddr);
			}
			return new Partition<E>(newAddr, (E) newAddr.withoutPrefixLength());
		} else if(newAddr.isSinglePrefixBlock()) {
			return new Partition<E>(newAddr);
		}
		// prefix blocks are handled as prefix blocks, 
		// such as 1.2.*.*, which is handled as prefix block iterator for 1.2.0.0/16,
		// but 1.2.3-4.5 is handled as iterator with no prefix lengths involved
		if(newAddr instanceof IPAddressSegmentSeries) {
			IPAddressSegmentSeries series = ((IPAddressSegmentSeries) newAddr).assignMinPrefixForBlock();
			if(series.getPrefixLength() != newAddr.getBitCount()) {
				Iterator<? extends E> iterator = (Iterator<? extends E>) series.prefixBlockIterator();
				return new Partition<E>(newAddr, iterator, series.getPrefixCount(series.getPrefixLength()));
			}
		} else {
			int prefLen = newAddr.getMinPrefixLengthForBlock();
			if(prefLen != newAddr.getBitCount()) {
				AddressSegmentSeries series = newAddr.setPrefixLength(prefLen, false);
				Iterator<? extends E> iterator = (Iterator<? extends E>) series.prefixBlockIterator();
				return new Partition<E>(newAddr, iterator, series.getPrefixCount(series.getPrefixLength()));
			}
		}
		Iterator<? extends E> iterator = (Iterator<? extends E>) newAddr.withoutPrefixLength().iterator();
		return new Partition<E>(newAddr, iterator, newAddr.getCount());
	}

	/**
	 * If the given address is a single prefix block, it is returned.
	 * If it can be converted to a single prefix block or address (by adjusting the prefix length), the converted block is returned.
	 * Otherwise, null is returned.
	 * 
	 * @param <E>
	 * @param addr
	 * @return
	 */
	public static <E extends Address> E checkBlockOrAddress(E addr) {
		 return AbstractTree.checkBlockOrAddress(addr, false);
	}
}