/*
 * Copyright 2026 Sean C Foley
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
import java.util.Comparator;
import java.util.Iterator;
import java.util.Spliterator;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import inet.ipaddr.format.util.AddressComponentSpliterator;
import inet.ipaddr.format.util.AddressTrie.TrieNode;
import inet.ipaddr.format.util.IPAddressTrie;
import inet.ipaddr.format.util.IPAddressTrie.IPAddressTrieNode;
import inet.ipaddr.format.validate.ChangeTracker;

/**
 * IPAddressContainmentTrieBase is the base class for a collection of IP addresses stored in CIDR prefix blocks within a trie.
 * <p>
 * The elements of this collection are individual addresses.  
 * The address elements do not correspond to any specific node in the trie.
 * As addresses are added and removed, the backing trie changes shape so that it contains a minimal number of prefix blocks and a minimal number of nodes indicating the contained elements if the collection.
 * An individual address can appear in only one added block in a containment trie.  
 * Direct access to the trie inside a containment trie is not allowed to ensure these structural invariants are not invalidated.
 * <p>
 * This differs from {@link inet.ipaddr.format.util.AddressTrieSet}, in which the elements of the set correspond to the added nodes of the trie, 
 * and an individual address and a larger prefix block that contains that address can be added to the trie as separate trie elements.
 * The elements of a trie or its corresponding AddressTrieSet are the prefix blocks and individual addresses corresponding to nodes added to the trie.
 * <p>
 * Both IPAddress and IPAddressSeqRange instances can be provided as arguments to methods provided by this class.  
 * Those arguments will be converted to CIDR prefix blocks by this class prior to their insertion or removal from the backing trie.
 * The same is true for contains, overlaps, for all operations.
 * There are no restrictions on what types of addresses or ranges can be used as arguments to the API methods of this class.
 * <p>
 * Subclasses IPv4AddressContainmentTrie and IPv6AddressContainmentTrie provide collections restricted to more specific IP address versions.
 * The subclass IPAddressContainmentTrie provides a trie that can accept either IPv4 or IPv6 addresses, but not both at the same time.
 * <p>
 * {@link IPAddressSeqRangeList} is the other implementation of {@link IPAddressCollection}.  An {@link IPAddressSeqRangeList} is considered equal to an IPAddressContainmentTrieBase
 * if both collections contain the same set of individual addresses.
 * 
 * 
 * @author scfoley
 *
 * @param <T> the address type
 * @param <R> the address sequential range type
 */
public class IPAddressContainmentTrieBase<T extends IPAddress, R extends IPAddressSeqRange> implements IPAddressCollection<T, R> {

	private static final long serialVersionUID = 1L;

	static class CollectionTrie extends IPAddressTrie {

		private static final long serialVersionUID = 1L;

		CollectionTrie(ChangeTracker changeTracker) {
			super(changeTracker);
		}

		public TrieNode<IPAddress>[] removeElementsIntersected(IPAddress addr) {
			return removeElementsIntersectedBy(addr, false);
		}
		
		@Override
		protected boolean addFromParent(TrieNode<IPAddress> parent, IPAddress addr) {
			return super.addFromParent(parent, addr);
		}

		@Override
		public IPAddressTrieNode addIfNoElementsContaining(IPAddress addr) {
			return addIfNoElementsContaining(addr, false);
		}

		@Override
		public IPAddressTrieNode containingFloorAddedNode(IPAddress addr) {
			return containingFloorAddedNodeNoCheck(addr);
		}

		@Override
		public IPAddressTrieNode containingHigherAddedNode(IPAddress addr) {
			return containingHigherAddedNodeNoCheck(addr);
		}

		@Override
		public IPAddressTrieNode containingCeilingAddedNode(IPAddress addr) {
			return containingCeilingAddedNodeNoCheck(addr);
		}

		@Override
		public IPAddressTrieNode containingLowerAddedNode(IPAddress addr) {
			return containingLowerAddedNodeNoCheck(addr);
		}
		
		@Override
		public CollectionTrie clone(ChangeTracker tracker) {
			return (CollectionTrie) super.clone(tracker);
		}
	}
	
	private ChangeTracker changeTracker = new ChangeTracker();
	CollectionTrie trie = new CollectionTrie(changeTracker);

	@SuppressWarnings("unchecked")
	private boolean removeBlock(T block) {
		TrieNode<IPAddress> nodes[] = trie.removeElementsIntersected(block);
		if(nodes != null) {
			TrieNode<IPAddress> deletedNode = nodes[0];
			IPAddress nodeKey = deletedNode.getKey();
			// nodeKey can be null if the entire tree was removed, because the IPAddressTrie, unlike IPv4AddressTrie or IPv6AddressTrie, has no root when empty
			if(nodeKey != null && nodeKey.contains(block) && !nodeKey.equals(block)) { // if nodeKey contains addresses that should not have been removed, need to put them back
				IPAddress remainder[] = nodeKey.subtract(block);
				TrieNode<IPAddress> parentNode = nodes[1];
				for(int i = 0; i < remainder.length; i++) {
					IPAddress newBlocks[] = remainder[i].spanWithPrefixBlocks();
					for(int j = 0; j < newBlocks.length; j++) {
						IPAddress newBlock = newBlocks[j];
						if(newBlock.isPrefixed() && !newBlock.isMultiple()) {
							newBlock = (T) newBlock.withoutPrefixLength();
						}
						trie.addFromParent(parentNode, newBlock);
					}
				}
			}
			return true;
		}
		return false;
	}

	private boolean addBlock(T block) {
		// The node is added to the trie if no existing elements in trie contain the new key.
		// The added node is returned.  
		// Go up the chain of parents of the returned node.  If any such parent (which are all non-added) is full according to the contained count, we record it and keep going up.  
		// After, the highest such node is set to added, and its two subnodes are removed.  Otherwise, the subnodes of the added node are removed.
		IPAddressTrieNode node = trie.addIfNoElementsContaining(block);
		if(node != null) {
			IPAddressTrieNode parent = node.getParent(), largestFull = null;
			while(parent != null) {
				if(parent.containingMaxElements()) {
					largestFull = parent;
				}
				parent = parent.getParent();
			}
			if(largestFull == null) {
				node.removeChildren();
			} else {
				largestFull.setAdded();// set to "added" first so the containment count roll-up is simpler for the children removal
				largestFull.removeChildren();
			}
			return true;
		}
		return false;
	}

	@SuppressWarnings("unchecked")
	private static <T extends IPAddress> boolean addressPredicateOp(T addr, Predicate<T> op, boolean all, boolean breakEarly, boolean stripSingleAddressPrefLen) {
		if(!addr.isMultiple()) {
			if(!addr.isPrefixed()) {
				return op.test(addr);
			}
			return op.test((T) addr.withoutPrefixLength());
		} else if(addr.isSinglePrefixBlock()) { // fast track for prefix blocks
			return op.test(addr);
		}
		return blocksPredicateOp((T[]) addr.spanWithPrefixBlocks(), op, all, breakEarly, stripSingleAddressPrefLen);
	}

	@SuppressWarnings("unchecked")
	private static <T extends IPAddress> boolean blocksPredicateOp(T blocks[], Predicate<T> op, boolean all, boolean breakEarly, boolean stripSingleAddressPrefLen) {
		boolean result = all;
		for(int i = 0; i < blocks.length; i++) {
			T block = blocks[i];
			if(stripSingleAddressPrefLen && block.isPrefixed() && !block.isMultiple()) {
				block = (T) block.withoutPrefixLength();
			}
			boolean res = op.test(block);
			if(all) { // all must return true for the full operation to be true
				if(!res) {
					result = false;
					if(breakEarly) { // exit once the return value is finalized
						break;
					}
				}
			} else { // any can return true for the full operation to be true
				if(res) {
					result = true;
					if(breakEarly) { // exit once the return value is finalized
						break;
					}
				}
			}
		}
		return result;
	}

	@SuppressWarnings("unchecked")
	private static <T extends IPAddress, R extends IPAddressSeqRange> boolean rangePredicateOp(R rng, Predicate<T> op, boolean all, boolean breakEarly, boolean stripSingleAddressPrefLen) {
		if(!rng.isMultiple()) {
			return op.test((T) rng.getLower());
		}
		return blocksPredicateOp((T[]) rng.spanWithPrefixBlocks(), op, all, breakEarly, stripSingleAddressPrefLen);
	}

	@Override
	public void clear() {
		trie.clear();
	}

	@Override
	public boolean add(T addr) {
		return addressPredicateOp(addr, this::addBlock, false, false, true);
	}

	@Override
	public boolean add(R rng) {
		return rangePredicateOp(rng, this::addBlock, false, false, true);
	}

	@Override
	public boolean remove(T addr) {
		return addressPredicateOp(addr, this::removeBlock, false, false, false);
	}

	@Override
	public boolean remove(R rng) {
		return rangePredicateOp(rng, this::removeBlock, false, false, false);
	}

	@Override
	public boolean contains(T addr) {
		return addressPredicateOp(addr, trie::elementContains, true, true, false);
	}

	@Override
	public boolean contains(R rng) {
		return rangePredicateOp(rng, trie::elementContains, true, true, false);
	}

	/**
	 * Returns if the given subnet overlaps with blocks or addresses in the trie.
	 * <p>
	 * In a trie of prefix blocks, for a block to overlap with another block means that one of the two blocks contains the other, or they are equal.
	 * 
	 * @param addr
	 * @return
	 */
	@Override
	public boolean overlaps(T addr) {
		return addressPredicateOp(addr, trie::elementOverlaps, false, true, false);
	}

	/**
	 * Returns if the given sequential range overlaps with blocks or addresses in the trie.
	 * <p>
	 * In a trie of prefix blocks, for a block to overlap with another block means that one of the two blocks contains the other, or they are equal.
	 * 
	 * @param rng
	 * @return
	 */
	@Override
	public boolean overlaps(R rng) {
		return rangePredicateOp(rng, trie::elementOverlaps, false, true, false);
	}

	@Override
	@SuppressWarnings("unchecked")
	public T lower(T addr) {
		addr = (T) addr.getLower();
		TrieNode<IPAddress> node = trie.containingLowerAddedNode(addr);
		if(node == null) {
			return null;
		}
		IPAddress key = node.getKey();
		if(key.contains(addr)) {
			return (T) addr.withoutPrefixLength().decrement();
		}
		return (T) key.withoutPrefixLength().getUpper();
	}

	@Override
	@SuppressWarnings("unchecked")
	public T floor(T addr) {
		addr = (T) addr.getLower();
		TrieNode<IPAddress> node = trie.containingFloorAddedNode(addr);
		if(node == null) {
			return null;
		}
		IPAddress key = node.getKey();
		if(key.contains(addr)) {
			return (T) addr.withoutPrefixLength();
		}
		return (T) key.withoutPrefixLength().getUpper();
	}

	@Override
	@SuppressWarnings("unchecked")
	public T ceiling(T addr) {
		addr = (T) addr.getUpper();
		TrieNode<IPAddress> node = trie.containingCeilingAddedNode(addr);
		if(node == null) {
			return null;
		}
		IPAddress key = node.getKey();
		if(key.contains(addr)) {
			return (T) addr.withoutPrefixLength();
		}
		return (T) key.withoutPrefixLength().getLower();
	}

	@Override
	@SuppressWarnings("unchecked")
	public T higher(T addr) {
		addr = (T) addr.getUpper();
		TrieNode<IPAddress> node = trie.containingHigherAddedNode(addr);
		if(node == null) {
			return null;
		}
		IPAddress key = node.getKey();
		if(key.contains(addr)) {
			return (T) addr.withoutPrefixLength().increment();
		}
		return (T) key.withoutPrefixLength().getLower();
	}

	@Override
	@SuppressWarnings("unchecked")
	public T coverWithPrefixBlock() {
		TrieNode<IPAddress> root = trie.getRoot();
		TrieNode<IPAddress> coveringNode;
		if(root.isAdded()) {
			coveringNode = root;
		} else {
			TrieNode<IPAddress> lower = root.getLowerSubNode();
			TrieNode<IPAddress> upper = root.getUpperSubNode();
			if(lower == null) {
				if(upper == null) {
					return null;
				} else {
					coveringNode = upper;
				}
			} else if(upper == null) {
				coveringNode = lower;
			} else {
				coveringNode = root;
			}
		}
		return (T) coveringNode.getKey();
	}
	
	@Override
	@SuppressWarnings("unchecked")
	public R coverWithSequentialRange() {
		T lower = getLower();
		if(lower == null) {
			return null;
		}
		return (R) lower.spanWithRange(getUpper());
	}

	@Override
	public BigInteger getCount() {
		return trie.getMatchingAddressCount();
	}

	@Override
	@SuppressWarnings("unchecked")
	public T getLower() {
		IPAddressTrieNode firstNode = trie.firstAddedNode();
		if(firstNode == null) {
			return null;
		}
		return (T) firstNode.getKey().getLower();
	}

	@Override
	@SuppressWarnings("unchecked")
	public T getUpper() {
		IPAddressTrieNode lastNode = trie.lastAddedNode();
		if(lastNode == null) {
			return null;
		}
		return (T) lastNode.getKey().getUpper();
	}

	@Override
	public Stream<T> stream() {
		return StreamSupport.stream(spliterator(), false);
	}

	/**
	 * Iterates through the individual IP addresses in this collection.
	 * This iterator does not support the remove operation.
	 */
	@Override
	public Iterator<T> iterator() {
		return new Iterator<T>() {
			private ChangeTracker.Change currentChange = changeTracker.getCurrent();
			
			@SuppressWarnings("unchecked")
			private Iterator<T> trieIterator = (Iterator<T>) trie.iterator(); 
			private Iterator<T> blockIterator;

			@Override
			public boolean hasNext() {
				return (blockIterator != null && blockIterator.hasNext()) || trieIterator.hasNext();
			}

			@SuppressWarnings("unchecked")
			@Override
			public T next() {
				if(blockIterator != null && blockIterator.hasNext()) {
					changeTracker.changedSince(currentChange);
					return blockIterator.next();
				}
				blockIterator = null;
				T block = trieIterator.next();
				if(block.isMultiple()) {
					blockIterator = (Iterator<T>) block.withoutPrefixLength().iterator();
					return blockIterator.next();
				}
				return block;
			}
		};
	}
	
	private static class ContainmentTrieSpliterator<T extends IPAddress> implements Spliterator<T> {
		private ChangeTracker changeTracker;
		private ChangeTracker.Change currentChange;

		private Spliterator<T> trieSpliterator;
		private AddressComponentSpliterator<T> blockSpliterator;
		
		private BigInteger estimatedSize;

		ContainmentTrieSpliterator(Spliterator<T> trieSpliterator, ChangeTracker changeTracker, BigInteger size) {
			this.changeTracker = changeTracker;
			this.trieSpliterator = trieSpliterator;
			currentChange = changeTracker.getCurrent();
			estimatedSize = size;
		}
		
		ContainmentTrieSpliterator(Spliterator<T> trieSpliterator, ChangeTracker changeTracker, ChangeTracker.Change currentChange, BigInteger estimatedSize) {
			this.changeTracker = changeTracker;
			this.trieSpliterator = trieSpliterator;
			this.currentChange = currentChange;
			this.estimatedSize = estimatedSize;
		}
		
		@SuppressWarnings("unchecked")
		@Override
		public boolean tryAdvance(Consumer<? super T> action) {
			if(blockSpliterator != null) {
				changeTracker.changedSince(currentChange);
				if(blockSpliterator.tryAdvance(action)) {
					return true;
				}
				blockSpliterator = null;
			}

			boolean hasBlock = trieSpliterator.tryAdvance(addr -> {
				if(addr.isMultiple()) {
					blockSpliterator = (AddressComponentSpliterator<T>) addr.withoutPrefixLength().spliterator();
					blockSpliterator.tryAdvance(action);
				} else {
					action.accept(addr);
				}
			});
			
			return hasBlock;
		}

		@Override
		public Spliterator<T> trySplit() {
			if(blockSpliterator != null) {
				changeTracker.changedSince(currentChange);
				// Note: whatever is in the block spliterator precedes whatever is left in the trie spliterator
				// So, splitting the block spliterator when the trie spliterator cannot be split,
				// that remains consistent with the characteristics SORTED and ORDERED,
				// which dictates that a split "splits a strict prefix of elements"
				//
				// For that same reason, we must always split the block spliterator if it exists
				return blockSpliterator.trySplit();
			}
			Spliterator<T> split = trieSpliterator.trySplit();
			if(split == null) {
				return null;
			}
			estimatedSize = estimatedSize.shiftRight(1);
			return new ContainmentTrieSpliterator<T>(split, changeTracker, currentChange, estimatedSize);
		}

		@Override
		public long estimateSize() {
			if(estimatedSize.compareTo(IPAddressSeqRangeList.LONG_MAX) >= 0) {
				return Long.MAX_VALUE;
			}
			return estimatedSize.longValue();
		}

		@Override
		public int characteristics() {
			// Trie spliterators are only SIZED (exact size is known) when they are first created, at which time the size of the whole trie is known.
			// After that, the spliterator sizes are estimated.
			// That coincides with this spliterator, when first created, we use the exact size, then later it is an estimate.
			return trieSpliterator.characteristics(); // see NodeSpliterator, NONNULL | SORTED | ORDERED | DISTINCT and sometimes SIZED
				// the block spliterators are CONCURRENT | NONNULL | SORTED | ORDERED | DISTINCT | SIZED | SUBSIZED;
		}

		@Override
		public Comparator<? super T> getComparator() {
			// this dictates the use of the natural ordering of T for comparison
			// we do not use the trie ordering or the trie comparator here (although it works the same for individual addresses)
			return null; 
		}
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public Spliterator<T> spliterator() {
		return new ContainmentTrieSpliterator<T>((Spliterator<T>) trie.spliterator(), changeTracker, getCount());
	}
	
	/**
	 * Returns an iterator for iterating through the prefix blocks in the backing trie, in sorted order.
	 * <p>
	 * These prefix blocks are the minimal set of disjoint prefix blocks for containing the addresses in this collection of addresses.
	 * 
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public Iterator<T> prefixBlockIterator() {
		return (Iterator<T>) trie.iterator();
	}
	
	/**
	 * Returns the number of prefix blocks in the backing trie.
	 * <p>
	 * The prefix blocks are the minimal set of disjoint prefix blocks for containing the addresses in this  collection of addresses.
	 * 
	 * @return
	 */
	public int getPrefixBlockCount() {
		return trie.size();
	}
	
	/**
	 * Returns the lowest prefix block in the backing trie, or null if the trie is empty
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public T getLowerPrefixBlock() {
		return (T) trie.firstAddedNode().getKey();
	}

	/**
	 * Returns the highest prefix block in the backing trie, or null if the trie is empty
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public T getUpperPrefixBlock() {
		return (T) trie.lastAddedNode().getKey();
	}

	/**
	 * Returns an iterable for iterating or spliterating through the prefix blocks in the backing trie, in sorted order.
	 * <p>
	 * These prefix blocks are the minimal set of disjoint prefix blocks for containing the addresses in this  collection of addresses.
	 * 
	 * @return
	 */
	public Iterable<T> getPrefixBlockIterable() {
		return new Iterable<T>() {
	
			@Override
			public Iterator<T> iterator() {
				return prefixBlockIterator();
			}
			
			@SuppressWarnings("unchecked")
			@Override
			public Spliterator<T> spliterator() {
				return (Spliterator<T>) trie.spliterator();
			}
		};
	}

	@Override
	public boolean isEmpty() {
		return trie.isEmpty();
	}

	@Override
	public boolean isMultiple() {
		IPAddressTrieNode firstNode = trie.firstAddedNode();
		if(firstNode != null) {
			return firstNode.getKey().isMultiple() || firstNode != trie.lastAddedNode();
		}
		return false;
	}

	@Override
	public boolean includesZero() {
		IPAddressTrieNode firstNode = trie.firstAddedNode();
		return firstNode != null && firstNode.getKey().includesZero();
	}

	@Override
	public boolean includesMax() {
		IPAddressTrieNode lastNode = trie.lastAddedNode();
		return lastNode != null && lastNode.getKey().includesMax();
	}

	@Override
	public boolean isSequential() {
		IPAddress lower = getLower();
		if(lower == null) {
			return true;
		}
		IPAddress upper = getUpper();
		return lower.enumerate(upper).add(BigInteger.ONE).equals(getCount());
	}

	@Override
	public String toString() {
		return trie.toString(true, false, true);
	}

	static boolean collectionsEqual(IPAddressCollection<? extends IPAddress,?> one, IPAddressCollection<? extends IPAddress,?> other) {
		if(one.getCount().equals(other.getCount())) {
			Iterator<? extends IPAddress> otherIter = other.iterator();
			Iterator<? extends IPAddress> iter = one.iterator();
			while(iter.hasNext()) {
				if(!iter.next().equals(otherIter.next())) {
					return false;
				}
			}
			return true;
		}
		return false;
	}

	@Override
	public boolean equals(Object other) {
		if(other instanceof IPAddressContainmentTrieBase){
			if(this == other) {
				return true;
			}
			IPAddressContainmentTrieBase<?, ?> otherColl = (IPAddressContainmentTrieBase<?, ?>) other;
			return trie.equals(otherColl.trie);
		} else if(other instanceof IPAddressSeqRangeList) {
			IPAddressSeqRangeList otherColl = (IPAddressSeqRangeList) other;
			return getCount().equals(otherColl.getCount()) && otherColl.contains(this);
		} else if(other instanceof IPAddressCollection) {
			IPAddressCollection<? extends IPAddress,?> otherColl = (IPAddressCollection<?,?>) other;
			return collectionsEqual(this, otherColl);
		}
		return false;
	}

	@SuppressWarnings("unchecked")
	@Override
	public IPAddressContainmentTrieBase<T, R> clone() {
		try {
			IPAddressContainmentTrieBase<T, R> cloned = (IPAddressContainmentTrieBase<T, R>) super.clone();
			cloned.changeTracker = new ChangeTracker();
			cloned.trie = trie.clone(cloned.changeTracker);
			return cloned;
		} catch (CloneNotSupportedException e) {
			return null;
		}
	}

	@Override
	public int hashCode() {
		return trie.hashCode();
	}
}
