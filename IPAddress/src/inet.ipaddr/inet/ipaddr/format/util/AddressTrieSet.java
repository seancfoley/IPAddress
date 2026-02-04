/*
 * Copyright 2020-2024 Sean C Foley
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

import java.io.Serializable;
import java.util.AbstractSet;
import java.util.Collection;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.NavigableSet;
import java.util.NoSuchElementException;
import java.util.Queue;
import java.util.Spliterator;
import java.util.function.Function;

import inet.ipaddr.Address;
import inet.ipaddr.format.util.AddressTrie.AddressBounds;
import inet.ipaddr.format.util.BinaryTreeNode.KeyIterator;

/**
 * Wraps a {@link inet.ipaddr.format.util.AddressTrie} to view it as a Java Collections Framework set, 
 * implementing the {@link java.util.Set}, {@link java.util.SortedSet} and {@link java.util.NavigableSet} interfaces.
 * <p>
 * Like {@link java.util.TreeSet}, this set is backed by a binary tree and implements the same interfaces that {@link java.util.TreeSet} does.  
 * But there are some significant differences between the two binary tree implementations.
 * See {@link inet.ipaddr.format.util.AddressTrieMap} for a description of some of the differences.
 * {@link java.util.TreeMap} is backed by a {@link java.util.TreeSet} and 
 * {@link inet.ipaddr.format.util.AddressTrieMap} is backed by an {@link inet.ipaddr.format.util.AddressTrie} just like {@link inet.ipaddr.format.util.AddressTrie},
 * so all of the same implementation comparisons apply equally between the map implementations and the set implementations.
 * <p>
 * With the trie set, only addresses that are either individual address or prefix block subnets of the same type and version can be added to the trie,
 * see {@link inet.ipaddr.format.util.AddressTrie.AddressComparator} for a comparator for the ordering.
 * <p>
 * Should you wish to store, in a collection, address instances that are not individual address or prefix block subnets,
 * you can use {@link java.util.TreeSet} or any other Java collections framework set to store addresses of any type,
 * or addresses of different versions or types in the same set,
 * since all address items in this library are comparable with a natural ordering.  
 * There are additional orderings provided by this library as well, see {@link inet.ipaddr.AddressComparator}.
 * 
 * @author scfoley
 *
 * @param <E> the address type
 */
public class AddressTrieSet<E extends Address> extends AbstractSet<E> implements NavigableSet<E>, Cloneable, Serializable {

	private static final long serialVersionUID = 1L;

	private AddressTrie<E> trie; // the backing trie
	private final boolean isReverse;
	private final Range<E> bounds;

	private AddressTrieSet<E> descending; //cached

	public AddressTrieSet(AddressTrie<E> trie) {
		this.trie = trie;
		this.isReverse = false;
		this.bounds = null;
		if(trie.set == null) {
			trie.set = this;
		}
	}

	public AddressTrieSet(AddressTrie<E> trie, Collection<? extends E> collection) {
		this.trie = trie;
		this.isReverse = false;
		this.bounds = null;
		if(trie.set == null) {
			trie.set = this;
		}
        addAll(collection);
    }

	AddressTrieSet(AddressTrie<E> trie, Range<E> bounds, boolean isReverse) {
		this.trie = trie;
		this.bounds = bounds;
		this.isReverse = isReverse;
		if(trie.set == null && !isReverse && bounds == null) {
			trie.set = this;
		}
	}

	public static class Range<E extends Address> implements Serializable {

		private static final long serialVersionUID = 1L;

		final AddressBounds<E> wrapped;

		Range<E> reversed;
		final boolean isReverse;

		Range(AddressBounds<E> wrapped) {
			this(wrapped, false);
		}

		Range(AddressBounds<E> wrapped, boolean isReverse) {
			if(wrapped == null) {
				throw new NullPointerException();
			}
			this.wrapped = wrapped;
			this.isReverse = isReverse;
		}

		Range<E> reverse() {
			Range<E> result = reversed;
			if(result == null) {
				result = new Range<E>(wrapped, !isReverse);
				reversed = result;
				result.reversed = this;
			}
			return result;
		}

		public boolean isInBounds(E addr) {
			return isWithinLowerBound(addr) && isWithinUpperBound(addr);
		}

		public E getLowerBound() {
			return isReverse ? wrapped.getUpperBound() : wrapped.getLowerBound();
		}

		public E getUpperBound() {
			return isReverse ? wrapped.getLowerBound() : wrapped.getUpperBound();
		}

		public boolean lowerIsInclusive() {
			return isReverse ? wrapped.upperIsInclusive() : wrapped.lowerIsInclusive();
		}

		public boolean upperIsInclusive() {
			return isReverse ? wrapped.lowerIsInclusive() : wrapped.upperIsInclusive();
		}

		public boolean isLowerBounded() {
			return getLowerBound() != null;
		}

		public boolean isUpperBounded() {
			return getUpperBound() != null;
		}

		public boolean isBelowLowerBound(E addr) {
			return isReverse ? wrapped.isAboveUpperBound(addr) : wrapped.isBelowLowerBound(addr);
		}

		public boolean isAboveUpperBound(E addr) {
			return isReverse ? wrapped.isBelowLowerBound(addr) : wrapped.isAboveUpperBound(addr);
		}

		public boolean isWithinLowerBound(E addr) {
			return !isBelowLowerBound(addr);					
		}

		public boolean isWithinUpperBound(E addr) {
			return !isAboveUpperBound(addr);
		}

		@Override
		public String toString() {
			Function<? super E, String> stringer = Address::toCanonicalString;
			return AddressBounds.toString(
					getLowerBound(), lowerIsInclusive(), 
					getUpperBound(), upperIsInclusive(), stringer, " -> ", stringer);
		}
	}

	private boolean isBounded() {
		return bounds != null;
	}

	@Override
	public AddressTrieSet<E> descendingSet() {
		AddressTrieSet<E> desc = descending;
		if(desc == null) {
			Range<E> reverseBounds = isBounded() ?  bounds.reverse() : null;
			desc = new AddressTrieSet<E>(trie, reverseBounds, !isReverse);
			descending = desc;
			desc.descending = this;
		}
		return desc;
	}

	/**
	 * Returns a trie representing this set.
	 * <p>
	 * If this set has a restricted range, {@link #hasRestrictedRange()}, this generates a new trie for the set with only the nodes pertaining to the subset.
	 * Otherwise this returns the backing trie for this set.
	 * <p>
	 * When a new trie is generated, the original backing trie for this set remains the same, it is not changed to the new trie.
	 * <p>
	 * The returned trie will always have the same natural trie ordering,
	 * even if this set has the reverse ordering.
	 * 
	 */
	public AddressTrie<E> asTrie() {
		if(isBounded()) {
			return trie.clone();
		}
		if(!isReverse) {
			trie.set = this;// in case we constructed the set first, we put a reference back to us
		}
		return trie;
	}

	/**
	 * Returns whether this set is the result of a call to {@link #headSet(Address)}, {@link #tailSet(Address)},
	 * {@link #subSet(Address, Address)} or any of the other six methods with the same names.
	 * 
	 * @return
	 */
	public boolean hasRestrictedRange() {
		return isBounded();
	}

	/**
	 * Returns the range if this set has a restricted range, see {@link #hasRestrictedRange()}.  Otherwise returns null.
	 * 
	 * @return
	 */
	public Range<E> getRange() {
		return bounds;
	}

	/**
     * Returns the number of elements in this set.  
     * This is a constant time operation, unless the set has a restricted range, see {@link #hasRestrictedRange()},
     * in which case it is a linear time operation proportional to the number of elements.
     * 
     * @return the number of elements in this set
     */
	@Override
	public int size() {
		return trie.size();
	}

	@Override
	public boolean isEmpty() {
		return trie.isEmpty();
    }

	@SuppressWarnings("unchecked")
	@Override
	public boolean contains(Object o) {
		return trie.contains((E) o);
	}

	/**
	 * Adds the given single address or prefix block subnet to this set.
	 * <p>
	 * If the given address is not a single address nor prefix block, then this method throws IllegalArgumentException. 
	 * <p>
	 * See {@link AddressTrie}
	 */
	@Override
	public boolean add(E e) {
		return trie.add(e);
	}

	@SuppressWarnings("unchecked")
	@Override
	public boolean remove(Object o) {
		return trie.remove((E) o);
	}

	@Override
	public void clear() {
		trie.clear();
	}

	@Override
	public int hashCode() {
		return trie.hashCode();
	}

	@Override
	public boolean equals(Object o) {
		if(o instanceof AddressTrieSet<?>) {
			AddressTrieSet<?> other = (AddressTrieSet<?>) o;
			// note that isReverse is ignored, intentionally
			// two sets are equal if they have the same elements
			return trie.equals(other.trie);
		} 
		return super.equals(o);
	}

	/**
	 * Clones the set along with the backing trie.  If the set had a restricted range, the clone does not.
	 */
	@SuppressWarnings("unchecked")
	@Override
	public AddressTrieSet<E> clone() {
		try {
			AddressTrieSet<E> clone = (AddressTrieSet<E>) super.clone();
			clone.trie = trie.clone();
			// cloned tries have no bounds, so we need to put the bounds back, 
			// even though there are no longer trie elements outside the bounds,
			// they still need to be part of this set
			clone.trie.bounds = trie.bounds; 
			clone.descending = null;
			return clone;
		} catch (CloneNotSupportedException cannotHappen) {
			return null;
		}
	}

	@Override
	public boolean removeAll(Collection<?> collection) {
		if(collection instanceof List || collection instanceof Queue || collection.size() < size()) {
			boolean result = false;
			for (Object object : collection) {
				if(remove(object)) {
					result = true;
				}
			}
			return result;
		}
		return removeIf(collection::contains);
    }

	@Override
	public Iterator<E> iterator() {
		return isReverse ? trie.descendingIterator() : trie.iterator();
	}

	@Override
	public Iterator<E> descendingIterator() {
		return isReverse ? trie.iterator() : trie.descendingIterator();
	}

	/**
	 * Returns an iterator that visits containing subnet blocks before their contained addresses and subnet blocks.
	 */
	public Iterator<E> containingFirstIterator() {
		return new KeyIterator<E>(trie.containingFirstIterator(!isReverse));
	}

	/**
	 * Returns an iterator that visits contained addresses and subnet blocks before their containing subnet blocks.
	 */
	public Iterator<E> containedFirstIterator() {
		return new KeyIterator<E>(trie.containedFirstIterator(!isReverse));
	}

	@Override
	public Spliterator<E> spliterator() {
		return isReverse ? trie.descendingSpliterator() : trie.spliterator();
    }

	@Override
	public Comparator<E> comparator() {
		return isReverse ? AddressTrie.reverseComparator() : AddressTrie.comparator();
	}

	/**
	 * Iterates from largest prefix blocks to smallest to individual addresses.
	 * Blocks of equal size are iterated in set order.
	 * 
	 * @return
	 */
	public Iterator<E> blockSizeIterator() {
		return new KeyIterator<E>(trie.blockSizeNodeIterator(!isReverse));
	}

	private AddressTrieSet<E> toSubSet(E fromElement, boolean fromInclusive, E toElement, boolean toInclusive) {
		if(isReverse) {
			E tmp = fromElement;
			boolean tmpInc = fromInclusive;
			fromElement = toElement;
			fromInclusive = toInclusive;
			toElement = tmp;
			toInclusive = tmpInc;
		}
		Range<E> range = bounds;
		AddressBounds<E> bounds, newBounds;
		if(range != null) {
			bounds = range.wrapped;
		} else {
			bounds = null;
		}
		if(bounds == null) {
			newBounds = AddressBounds.createNewBounds(fromElement, fromInclusive, toElement,  toInclusive, trie.getComparator());
		} else {
			newBounds = bounds.restrict(fromElement, fromInclusive, toElement, toInclusive);
		}
		if(newBounds == null) {
			return this;
		}
		Range<E> newRange = new Range<E>(newBounds, isReverse);
		return new AddressTrieSet<E>(trie.createSubTrie(newBounds), newRange, isReverse);
	}

	@Override
	public AddressTrieSet<E> subSet(E fromElement, E toElement) {
		return subSet(fromElement, true, toElement, false);
    }

	@Override
	public AddressTrieSet<E> subSet(E fromElement, boolean fromInclusive, E toElement, boolean toInclusive) {
		if(fromElement == null || toElement == null) {
			throw new NullPointerException();
		}
		return toSubSet(fromElement, fromInclusive, toElement, toInclusive);
	}

	@Override
	public AddressTrieSet<E> headSet(E toElement) {
		return headSet(toElement, false);
    }

	@Override
	public AddressTrieSet<E> headSet(E toElement, boolean inclusive) {
		if(toElement == null) {
			throw new NullPointerException();
		}
		return toSubSet(null, true, toElement, inclusive);
	}

	@Override
	public AddressTrieSet<E> tailSet(E fromElement) {
		return tailSet(fromElement, true);
    }

	@Override
	public AddressTrieSet<E> tailSet(E fromElement, boolean inclusive) {
		if(fromElement == null) {
			throw new NullPointerException();
		}
		return toSubSet(fromElement, inclusive, null, false);
	}

	@Override
	public E first() {
		BinaryTreeNode<E> first = isReverse ? trie.lastAddedNode() : trie.firstAddedNode();
    	if(first == null) {
    		throw new NoSuchElementException();
    	}
    	return first.getKey();
    }

    @Override
	public E last() {
    	BinaryTreeNode<E> last = isReverse ? trie.firstAddedNode() : trie.lastAddedNode();
    	if(last == null) {
    		throw new NoSuchElementException();
    	}
    	return last.getKey();
    }

	@Override
	public E lower(E e) {
		return isReverse ? trie.higher(e) : trie.lower(e);
	}

	@Override
	public E floor(E e) {
		return isReverse ? trie.ceiling(e) : trie.floor(e);
	}

	@Override
	public E ceiling(E e) {
		return isReverse ? trie.floor(e) : trie.ceiling(e);
	}

	@Override
	public E higher(E e) {
		return isReverse ? trie.lower(e) : trie.higher(e);
	}

	@Override
	public E pollFirst() {
		BinaryTreeNode<E> first = isReverse ? trie.lastAddedNode() : trie.firstAddedNode();
    	if(first == null) {
    		return null;
    	}
    	first.remove();
    	return first.getKey();
	}

	@Override
	public E pollLast() {
		BinaryTreeNode<E> last = isReverse ? trie.firstAddedNode() : trie.lastAddedNode();
    	if(last == null) {
    		return null;
    	}
    	last.remove();
    	return last.getKey();
	}

	public String toTrieString() {
		return trie.toString();
	}

	// was not necessary to add the methods below

	/**
	 * Returns a subset consisting of those addresses in the set contained by the given address.
	 * The subset will have a restricted range matching the range of the given subnet or address.
	 * <p>
	 * If the subset would be the same size as this set, then this set is returned.
	 * The subset will the same backing trie as this set.
	 * 
	 * @param addr
	 * @return
	 */
	public AddressTrieSet<E> elementsContainedBy(E addr) {
		AddressTrie<E> newTrie = trie.elementsContainedByToSubTrie(addr);
		if(trie == newTrie) {
			return this;
		}
		if(newTrie.bounds == null) {
			return new AddressTrieSet<E>(newTrie, null, isReverse);
		}
		Range<E> newRange = new Range<E>(newTrie.bounds, isReverse);
		return new AddressTrieSet<E>(newTrie, newRange, isReverse);
	}

	/**
	 * Returns a subset consisting of those addresses in the set that contain the given address.
	 * The subset will have the same restricted range (if any) as this set.
	 * <p>
	 * If the subset would be the same size as this set, then this set is returned.
	 * Otherwise, the subset is backed by a new trie.
	 * 
	 * @param addr
	 * @return
	 */
	public AddressTrieSet<E> elementsContaining(E addr) {
		AddressTrie<E> newTrie = trie.elementsContainingToTrie(addr);
		if(trie == newTrie) {
			return this;
		}
		if(newTrie.bounds == null) {
			return new AddressTrieSet<E>(newTrie, null, isReverse);
		}
		Range<E> newRange = new Range<E>(newTrie.bounds, isReverse);
		return new AddressTrieSet<E>(newTrie, newRange, isReverse);
	}

	/**
	 * Returns true if a subnet or address in the set contains the given subnet or address.
	 * 
	 * @param addr
	 * @return
	 */
	public boolean elementContains(E addr) {
		return trie.elementContainsBounds(addr);
	}

	/**
	 * Returns the element with the longest prefix match with the given address.
	 * @param addr
	 * @return
	 */
	public E longestPrefixMatch(E addr) {
		return trie.longestPrefixMatchBounds(addr);
	}
}
