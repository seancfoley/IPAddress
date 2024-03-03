/*
 * Copyright 2024 Sean C Foley
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
import java.util.Comparator;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Spliterator;
import java.util.function.BiFunction;
import java.util.function.BiPredicate;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.UnaryOperator;

import inet.ipaddr.Address;
import inet.ipaddr.IPAddress;
import inet.ipaddr.format.util.AddressTrie.TrieNode;
import inet.ipaddr.format.util.AddressTrieOps.AddressTrieAddOps;
import inet.ipaddr.format.util.BinaryTreeNode.ChangeTracker;
import inet.ipaddr.format.util.BinaryTreeNode.ChangeTracker.Change;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv6.IPv6Address;


/**
 * Contains a pair of IPv4 and IPv6 tries for a data structure that can have fast look-up and containment checks of both IPv4 and IPv6 addresses.
 *   
 * For a tree that is either IPv4 or IPv6, you can just use #{@link AddressTrie}.
 * 
 * @author scfoley
 *
 */
public abstract class BaseDualIPv4v6Tries<T4 extends AddressTrie<IPv4Address>, T6 extends AddressTrie<IPv6Address>> implements Iterable<IPAddress>, Serializable, Cloneable {
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * returns the contained IPv4 trie
	 * @return
	 */
	public abstract T4 getIPv4Trie();
	
	/**
	 * returns the contained IPv6 trie
	 * @return
	 */
	public abstract T6 getIPv6Trie();
	
	private ChangeTracker ipv4Tracker, ipv6Tracker;
	
	BaseDualIPv4v6Tries(AddressTrie<IPv4Address> ipv4Trie, AddressTrie<IPv6Address> ipv6Trie) {
		assignTrackers(ipv4Trie, ipv6Trie);
	}
	
	void assignTrackers(AddressTrie<IPv4Address> ipv4Trie, AddressTrie<IPv6Address> ipv6Trie) {
		this.ipv4Tracker = ipv4Trie.absoluteRoot().changeTracker;
		this.ipv6Tracker = ipv6Trie.absoluteRoot().changeTracker;
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public BaseDualIPv4v6Tries<T4, T6> clone() {
		try {
			return (BaseDualIPv4v6Tries<T4, T6>) super.clone();
		} catch (CloneNotSupportedException e) {
			return null;
		}
	}
	
	@Override
	public String toString() {
		return AddressTrie.toString(true, getIPv4Trie(), getIPv6Trie());
	}

	static boolean addressPredicateOp(IPAddress addr, Predicate<IPv4Address> ipv4Op, Predicate<IPv6Address> ipv6Op) {
		if(addr.isIPv4()) {
			return ipv4Op.test(addr.toIPv4());
		} else if(addr.isIPv6()) {
			return ipv6Op.test(addr.toIPv6());
		} 
		return false;
	}

	static <T> T addressFuncOp(IPAddress addr, Function<IPv4Address, T> ipv4Op, Function<IPv6Address, T> ipv6Op) {
		if(addr.isIPv4()) {
			return ipv4Op.apply(addr.toIPv4());
		} else if(addr.isIPv6()) {
			return ipv6Op.apply(addr.toIPv6());
		} 
		return null;
	}
	
	static <V> V addressValValBiFuncOp(IPAddress addr, V value, BiFunction<IPv4Address, V, V> ipv4Op, BiFunction<IPv6Address, V, V> ipv6Op) {
		if(addr.isIPv4()) {
			return ipv4Op.apply(addr.toIPv4(), value);
		} else if(addr.isIPv6()) {
			return ipv6Op.apply(addr.toIPv6(), value);
		} 
		return null;
	}
	
	static <V, R> R addressValBiFuncOp(IPAddress addr, V value, BiFunction<IPv4Address, V, R> ipv4Op, BiFunction<IPv6Address, V, R> ipv6Op) {
		if(addr.isIPv4()) {
			return ipv4Op.apply(addr.toIPv4(), value);
		} else if(addr.isIPv6()) {
			return ipv6Op.apply(addr.toIPv6(), value);
		} 
		return null;
	}
	
	static <V> boolean addressValBiPredicateOp(IPAddress addr, V value, BiPredicate<IPv4Address, V> ipv4Op, BiPredicate<IPv6Address, V> ipv6Op) {
		if(addr.isIPv4()) {
			return ipv4Op.test(addr.toIPv4(), value);
		} else if(addr.isIPv6()) {
			return ipv6Op.test(addr.toIPv6(), value);
		} 
		return false;
	}
	
	@SuppressWarnings("unchecked")
	static <T extends TrieNode<? extends IPAddress>, 
		R extends TrieNode<? extends IPAddress>,
		R1 extends TrieNode<IPv4Address>, 
		R2 extends TrieNode<IPv6Address>> R unaryOp(T trie, UnaryOperator<R1> ipv4Op, UnaryOperator<R2> ipv6Op) {
		IPAddress addr = trie.getKey();
		if(addr.isIPv4()) {
			return (R) ipv4Op.apply((R1) trie);
		} else if(addr.isIPv6()) {
			return (R) ipv6Op.apply((R2) trie);
		} 
		return null;
	}

	/**
	 * Returns the number of elements in the tries.  
	 * Only added nodes are counted.
	 * When zero is returned, {@link #isEmpty()} returns true.
	 * 
	 * @return
	 */
	public int size() {
		return getIPv4Trie().size() + getIPv6Trie().size();
	}

	/**
	 * Returns true if there are no added nodes within the two tries
	 */
	public boolean isEmpty() {
		return getIPv4Trie().isEmpty() && getIPv6Trie().isEmpty();
	}

	/**
	 * Adds the given single address or prefix block subnet to one of the two tries.
	 * <p>
	 * If the given address is not a single address nor prefix block, then this method throws IllegalArgumentException. 
	 * <p>
	 * If not a single address nor prefix block, the {@link Partition} class can be used to convert the address before calling this method.  
	 * Given a subnet s of type E and a trie of type AddressTrie&lt;E&gt;, such as {@link inet.ipaddr.ipv4.IPv4Address} and {@link inet.ipaddr.ipv4.IPv4AddressTrie},
	 * you can convert and add the spanning prefix blocks with <code>Partition.partitionWithSpanningBlocks(s).predicateForEach(trie::add)</code>,
	 * or you can convert and add using a single max block size with <code>Partition.partitionWithSingleBlockSize(s).predicateForEach(trie::add)</code>.
	 * <p>
	 * Returns true if the prefix block or address was inserted, false if already in one of the two tries.
	 * 
	 * @param addr
	 * @return
	 */
	public boolean add(IPAddress addr) {
		return addressPredicateOp(addr, getIPv4Trie()::add, getIPv6Trie()::add);
	}

	/**
	 * Returns whether the given address or prefix block subnet is in one of the two tries (as an added element).
	 * <p>
	 * If the given address is not a single address nor prefix block, then this method throws IllegalArgumentException.
	 * <p>
	 * If not a single address nor prefix block, the {@link Partition} class can be used to convert the address before calling this method.  
	 * See {@link AddressTrieAddOps#add(Address)} for more details.
	 * <p>
	 * Returns true if the prefix block or address address exists already in one the two tries, false otherwise.
	 * <p>
	 * Use {@link #getAddedNode(IPAddress)} to get the node for the address rather than just checking for its existence.
	 * 
	 * @param addr
	 * @return
	 */
	public boolean contains(IPAddress addr) {
		return addressPredicateOp(addr, getIPv4Trie()::contains, getIPv6Trie()::contains);
	}

	/**
	 * Removes the given single address or prefix block subnet from the tries.
	 * <p>
	 * Removing an element will not remove contained elements (nodes for contained blocks and addresses).
	 * <p>
	 * If the given address is not a single address nor prefix block, then this method throws IllegalArgumentException. 
	 * <p>
	 * If not a single address nor prefix block, the {@link Partition} class can be used to convert the address before calling this method.  
	 * See {@link AddressTrieAddOps#add(Address)} for more details.
	 * <p>
	 * Returns true if the prefix block or address was removed, false if not already in one of the two tries.
	 * <p>
	 * You can also remove by calling {@link #getAddedNode(IPAddress)} to get the node and then calling {@link BinaryTreeNode#remove()} on the node.
	 * <p>
	 * When an address is removed, the corresponding node may remain in the trie if it remains a subnet block for two sub-nodes.
	 * If the corresponding node can be removed from the trie, it will be.
	 * 
	 * @see #removeElementsContainedBy(IPAddress)
	 * @param addr
	 * @return
	 */
	public boolean remove(IPAddress addr) {
		return addressPredicateOp(addr, getIPv4Trie()::remove, getIPv6Trie()::remove);
	}

	/**
	 * Checks if a prefix block subnet or address in ones of the two tries contains the given subnet or address.
	 * <p>
	 * If the given address is not a single address nor prefix block, then this method throws IllegalArgumentException.
	 * <p>
	 * If not a single address nor prefix block, the {@link Partition} class can be used to convert the address before calling this method.  
	 * See {@link AddressTrieAddOps#add(Address)} for more details.
	 * <p>
	 * Returns true if the subnet or address is contained by a trie element, false otherwise.
	 * <p>
	 * To get all the containing addresses, use {@link #elementsContaining(IPAddress)}.
	 * 
	 * @param addr
	 * @return
	 */
	public boolean elementContains(IPAddress addr) {
		return addressPredicateOp(addr, getIPv4Trie()::elementContains, getIPv6Trie()::elementContains);
	}

	public TrieNode<? extends IPAddress> elementsContaining(IPAddress addr) {
		return addressFuncOp(addr, getIPv4Trie()::elementsContaining, getIPv6Trie()::elementsContaining);
	}

	public TrieNode<? extends IPAddress> elementsContainedBy(IPAddress addr) {
		return addressFuncOp(addr, getIPv4Trie()::elementsContainedBy, getIPv6Trie()::elementsContainedBy);
	}

	public TrieNode<? extends IPAddress> removeElementsContainedBy(IPAddress addr) {
		return addressFuncOp(addr, getIPv4Trie()::removeElementsContainedBy, getIPv6Trie()::removeElementsContainedBy);
	}

	public TrieNode<? extends IPAddress> getAddedNode(IPAddress addr) {
		return addressFuncOp(addr, getIPv4Trie()::getAddedNode, getIPv6Trie()::getAddedNode);
	}

	public TrieNode<? extends IPAddress> longestPrefixMatchNode(IPAddress addr) {
		return addressFuncOp(addr, getIPv4Trie()::longestPrefixMatchNode, getIPv6Trie()::longestPrefixMatchNode);
	}

	public IPAddress longestPrefixMatch(IPAddress addr) {
		return addressFuncOp(addr, getIPv4Trie()::longestPrefixMatch, getIPv6Trie()::longestPrefixMatch);
	}

	public TrieNode<? extends IPAddress> addNode(IPAddress addr) {
		return addressFuncOp(addr, getIPv4Trie()::addNode, getIPv6Trie()::addNode);
	}

	public TrieNode<? extends IPAddress> addTrie(TrieNode<? extends IPAddress> trie) {
		return unaryOp(trie, getIPv4Trie()::addTrie, getIPv6Trie()::addTrie);
	}

	public TrieNode<? extends IPAddress> floorAddedNode(IPAddress addr) {
		return addressFuncOp(addr, getIPv4Trie()::floorAddedNode, getIPv6Trie()::floorAddedNode);
	}

	public TrieNode<? extends IPAddress> lowerAddedNode(IPAddress addr) {
		return addressFuncOp(addr, getIPv4Trie()::lowerAddedNode, getIPv6Trie()::lowerAddedNode);
	}

	public TrieNode<? extends IPAddress> ceilingAddedNode(IPAddress addr) {
		return addressFuncOp(addr, getIPv4Trie()::ceilingAddedNode, getIPv6Trie()::ceilingAddedNode);
	}

	public TrieNode<? extends IPAddress> higherAddedNode(IPAddress addr) {
		return addressFuncOp(addr, getIPv4Trie()::higherAddedNode, getIPv6Trie()::higherAddedNode);
	}

	public IPAddress floor(IPAddress addr) {
		return AddressTrie.getNodeKey(floorAddedNode(addr));
	}

	public IPAddress lower(IPAddress addr) {
		return AddressTrie.getNodeKey(lowerAddedNode(addr));
	}

	public IPAddress ceiling(IPAddress addr) {
		return AddressTrie.getNodeKey(ceilingAddedNode(addr));
	}

	public IPAddress higher(IPAddress addr) {
		return AddressTrie.getNodeKey(higherAddedNode(addr));
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPAddress> iterator() {
		Iterator<? extends IPAddress> ipv4Iterator = getIPv4Trie().iterator(), ipv6Iterator = getIPv6Trie().iterator();
		return new DualIterator<IPAddress>((Iterator<IPAddress>) ipv4Iterator, (Iterator<IPAddress>) ipv6Iterator, true);
	}

	@SuppressWarnings("unchecked")
	public Iterator<IPAddress> descendingIterator() {
		Iterator<? extends IPAddress> ipv4Iterator = getIPv4Trie().descendingIterator(), ipv6Iterator = getIPv6Trie().descendingIterator();
		return new DualIterator<IPAddress>((Iterator<IPAddress>) ipv4Iterator, (Iterator<IPAddress>) ipv6Iterator, false);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Spliterator<IPAddress> spliterator() {
		Spliterator<? extends IPAddress> ipv4Iterator = getIPv4Trie().spliterator(), ipv6Iterator = getIPv6Trie().spliterator();
		return new DualSpliterator<IPAddress>((Spliterator<IPAddress>) ipv4Iterator, (Spliterator<IPAddress>) ipv6Iterator);
	}

	@SuppressWarnings("unchecked")
	public Spliterator<IPAddress> descendingSpliterator() {
		Spliterator<? extends IPAddress> ipv4Iterator = getIPv4Trie().descendingSpliterator(), ipv6Iterator = getIPv6Trie().descendingSpliterator();
		return new DualSpliterator<IPAddress>((Spliterator<IPAddress>) ipv6Iterator, (Spliterator<IPAddress>) ipv4Iterator);
	}
	
	@SuppressWarnings("unchecked")
	<T extends TrieNode<? extends IPAddress>> Iterator<T> combineNodeIterators(
			boolean forward,
			Iterator<? extends T> ipv4It, 
			Iterator<? extends T> ipv6It) {
		Iterator<T> ipv4I = (Iterator<T>) ipv4It;
		Iterator<T> ipv6I = (Iterator<T>) ipv6It;
		return new DualIterator<T>(ipv4I, ipv6I, forward);
	}
	
	@SuppressWarnings("unchecked")
	<T extends TrieNode<? extends IPAddress>> Iterator<T> combineBlockSizeNodeIterators(
			boolean lowerSubNodeFirst,
			Iterator<? extends T> ipv4It, 
			Iterator<? extends T> ipv6It) {
		Iterator<T> ipv4I = (Iterator<T>) ipv4It;
		Iterator<T> ipv6I = (Iterator<T>) ipv6It;
		return new DualBlockSizeIterator<T>(lowerSubNodeFirst, ipv4I, ipv6I);
	}
	
	public abstract Iterator<? extends TrieNode<? extends IPAddress>> nodeIterator(boolean forward);

	public abstract Iterator<? extends TrieNode<? extends IPAddress>> containingFirstIterator(boolean forwardSubNodeOrder);
	
	public abstract Iterator<? extends TrieNode<? extends IPAddress>> containedFirstIterator(boolean forwardSubNodeOrder);
	
	public abstract Iterator<? extends TrieNode<? extends IPAddress>> blockSizeNodeIterator(boolean lowerSubNodeFirst);
	
	public abstract Spliterator<? extends TrieNode<? extends IPAddress>> nodeSpliterator(boolean forward);
	
	@SuppressWarnings("unchecked")
	<T extends TrieNode<? extends IPAddress>> Spliterator<T> combineNodeSpliterators(
			boolean forward,
			Spliterator<? extends T> ipv4It, 
			Spliterator<? extends T> ipv6It) {
		Spliterator<T> ipv4I = (Spliterator<T>) ipv4It;
		Spliterator<T> ipv6I = (Spliterator<T>) ipv6It;
		if(forward) {
			return new DualSpliterator<T>(ipv4I, ipv6I);
		} 
		return new DualSpliterator<T>(ipv6I, ipv4I);
	}
	
	static class BlockSizeComp<E extends Address> implements Comparator<E> {
		private final boolean reverseBlocksEqualSize;
	
		BlockSizeComp(boolean reverseBlocksEqualSize) {
			this.reverseBlocksEqualSize = reverseBlocksEqualSize;
		}
	
		@Override
		public int compare(E addr1, E addr2) {
			if(addr1 == addr2) {
				return 0;
			}
			if(addr1.isPrefixed()) {
				if(addr2.isPrefixed()) {
					int val = (addr2.getBitCount() - addr2.getPrefixLength())
							- (addr1.getBitCount() - addr1.getPrefixLength());
					if(val == 0) {
						int compVal = compareLowValues(addr1, addr2);
						return reverseBlocksEqualSize ? -compVal : compVal;
					}
					return val;
				}
				return -1;
			}
			if(addr2.isPrefixed()) {
				return 1;
			}
			int compVal = compareLowValues(addr1, addr2);
			return reverseBlocksEqualSize ? -compVal : compVal;
		}
	};
	
	static int compareLowValues(Address one, Address two) {
		return Address.ADDRESS_LOW_VALUE_COMPARATOR.compare(one, two);
	}
	
	static final Comparator<?> BLOCK_SIZE_COMP = new BlockSizeComp<>(false), REVERSE_BLOCK_SIZE_COMP = new BlockSizeComp<>(true);

	class BaseDualIterator {
		Change ipv4CurrentChange, ipv6CurrentChange;
		
		BaseDualIterator() {
			if(ipv4Tracker != null) {
				ipv4CurrentChange = ipv4Tracker.getCurrent();
			}
			if(ipv6Tracker != null) {
				ipv6CurrentChange = ipv6Tracker.getCurrent();
			}
		}
		
		void changedSince() {
			if(ipv4Tracker != null) {
				ipv4Tracker.changedSince(ipv4CurrentChange);
			}
			if(ipv6Tracker != null) {
				ipv6Tracker.changedSince(ipv6CurrentChange);
			}
		}
	}

	class DualBlockSizeIterator<T extends TrieNode<? extends IPAddress>> extends BaseDualIterator implements Iterator<T> {
		T ipv4Item, ipv6Item; 
		Iterator<T> ipv4Iterator, ipv6Iterator;
		T lastItem;
		Comparator<IPAddress> comp;

		@SuppressWarnings("unchecked")
		DualBlockSizeIterator(boolean lowerSubNodeFirst, Iterator<T> ipv4Iterator, Iterator<T> ipv6Iterator) {
			boolean reverseBlocksEqualSize = !lowerSubNodeFirst;
			comp = (Comparator<IPAddress>) (reverseBlocksEqualSize ? REVERSE_BLOCK_SIZE_COMP : BLOCK_SIZE_COMP);
			this.ipv4Iterator = ipv4Iterator;
			this.ipv6Iterator = ipv6Iterator;
		}
		
		@Override
		public boolean hasNext() {
			return ipv4Item != null || ipv6Item != null || ipv4Iterator.hasNext() || ipv6Iterator.hasNext();
		}

		@Override
		public T next() {
			if(hasNext()) {
				changedSince();
			} else {
				throw new NoSuchElementException();
			}

			// replace whatever was returned previously
			if(ipv4Item == null && ipv4Iterator.hasNext()) {
				ipv4Item = ipv4Iterator.next();
			} else if(ipv6Item == null && ipv6Iterator.hasNext()) {
				ipv6Item = ipv6Iterator.next();
			}
			
			T result;
			
			// now return the lowest of the two
			if(ipv4Item == null) {
				result = lastItem = ipv6Item;
				ipv6Item = null;
			} else if(ipv6Item == null) {
				result = lastItem = ipv4Item;
				ipv4Item = null;
			} else {
				int cmp = comp.compare(ipv4Item.getKey(), ipv6Item.getKey());
				if(cmp < 0) {
					result = lastItem = ipv4Item;
					ipv4Item = null;
				} else {
					result = lastItem = ipv6Item;
					ipv6Item = null;
				}
			}
			return result;
		}
		
		@Override
		public void remove() {
			if(lastItem == null) {
				throw new IllegalStateException();
			}
			changedSince();
			if(lastItem.getKey().isIPv4()) {
				ipv4Iterator.remove();
				ipv4CurrentChange = ipv4Tracker.getCurrent();
			} else {
				ipv6Iterator.remove();
				ipv6CurrentChange = ipv6Tracker.getCurrent();
			}
			lastItem = null;
	    }
	}
	
	class DualIterator<T> extends BaseDualIterator implements Iterator<T> {
		private Iterator<T> current; // always points to the previously-used iterator, so that "remove" works as intended, and any caching functionality as well
		private Iterator<T> first, last;
		private boolean firstIsIPv4;
		
		DualIterator(Iterator<T> ipv4Iterator, Iterator<T> ipv6Iterator, boolean forward) {
			if(forward) {
				this.first = ipv4Iterator;
				this.last = ipv6Iterator;
			} else {
				this.first = ipv6Iterator;
				this.last = ipv4Iterator;
			}
			current = first;
			firstIsIPv4 = forward;
		}
		
		@Override
		public boolean hasNext() {
			if(current == last) {
				return last.hasNext();
			}
			return current.hasNext() || last.hasNext();
		}
		
		@Override
		public T next() {
			if(current != last && !first.hasNext()) {
				current = last;
			}
			
			// note that the next element is always pre-prepared for 
			// all iterator subtypes of AbstractNodeIterator
			// so that means we know we can trust the result of hasNext
			// even when the trie has been changed.
			if(current.hasNext()) {
				changedSince();
			}
			return current.next();
		}
		
		@Override
		public void remove() {
			changedSince();
			
			current.remove();
	        
	        if(current == first ? firstIsIPv4 : !firstIsIPv4) {
	        	if(ipv4Tracker != null) {
    				ipv4CurrentChange = ipv4Tracker.getCurrent();
    			}
	        } else if(ipv6Tracker != null) {
    			ipv6CurrentChange = ipv6Tracker.getCurrent();
	        }
	    }
	}
	
	class DualSpliterator<T> extends BaseDualIterator implements Spliterator<T> {
		// before the first split we use first and second,
		// after that we use current
		Spliterator<T> first, second, current;

		DualSpliterator(Spliterator<T> first, Spliterator<T> second) {
			this.first = first;
			this.second = second;
		}
		
		@Override
		public boolean tryAdvance(Consumer<? super T> action) {
			changedSince();
			if(current == null) {
				if(first.tryAdvance(action)) {
					return true;
				}
				return second.tryAdvance(action);
			}
			return current.tryAdvance(action);
		}
	
		@Override
		public Spliterator<T> trySplit() {
			changedSince();
			if(current == null) {
				current = second;
				return first;
			}
			return current.trySplit();
		}
	
		@Override
		public void forEachRemaining(Consumer<? super T> action) {
			changedSince();
			if(current == null) {
				current = second;
				first.forEachRemaining(action);
				second.forEachRemaining(action);
			} else {
				current.forEachRemaining(action);
			}
	    }
		
		@Override
		public long estimateSize() {
			if(current == null) {
				return first.estimateSize() + second.estimateSize();
			}
			return current.estimateSize();
		}
	
		@Override
		public int characteristics() {
			if(current == null) {
				return first.characteristics() & second.characteristics();
			}
			return current.characteristics();
		}
	}
}
