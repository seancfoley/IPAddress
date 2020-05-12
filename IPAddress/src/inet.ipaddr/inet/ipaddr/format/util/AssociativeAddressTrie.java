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

import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import java.util.Spliterator;
import java.util.function.Function;
import java.util.function.Supplier;

import inet.ipaddr.Address;
import inet.ipaddr.format.util.AddressTrieOps.AssociativeAddressTriePutOps;
import inet.ipaddr.format.util.BinaryTreeNode.CachingIterator;
import inet.ipaddr.format.util.BinaryTreeNode.ChangeTracker.Change;

/**
 * An address trie in which each node is is associated with a value.
 * <p>
 * The trie can also be used as the backing data structure for a {@link AddressTrieMap} which is a @{link java.util.NavigableMap}.
 * Unlike {@link java.util.TreeMap} this data structure provides access to the nodes and the associated subtrie with each node,
 * which corresponds with their associated CIDR prefix block subnets.
 * <p>
 * When using the {@link #add(Address)} methods the value will be null.  
 * Use one of the put methods to add nodes with values or to change the values of existing nodes.
 * <p>
 * Mapped tries are thread-safe when not being modified (ie mappings added or removed), but are not thread-safe when a thread is modifying the trie.
 * <p>
 * To make them thread-safe during addition and removal you could access them through the collection provided by {@link java.util.Collections#synchronizedMap},
 * applied to the map from {@link #asMap()}
 * 
 * @author scfoley
 *
 * @param <K>
 * @param <V>
 */ 
public abstract class AssociativeAddressTrie<K extends Address, V> extends AddressTrie<K> implements AssociativeAddressTriePutOps<K, V> {

	private static final long serialVersionUID = 1L;

	public static abstract class AssociativeTrieNode<K extends Address, V> extends TrieNode<K> implements Map.Entry<K, V>, AssociativeAddressTrieOps<K, V> {

		private static final long serialVersionUID = 1L;

		private V value;

		protected AssociativeTrieNode(K item) {
			super(item);
		}

		@Override
		public V getValue() {
			return value;
		}

		@Override
		public V setValue(V value) {
			V result = getValue();
			this.value = value;
			return result;
		}

		public void clearValue() {
			this.value = null;
		}

		@SuppressWarnings("unchecked")
		@Override
		public AssociativeTrieNode<K,V> getUpperSubNode() {
			return (AssociativeTrieNode<K,V>) super.getUpperSubNode();
		}

		@SuppressWarnings("unchecked")
		@Override
		public AssociativeTrieNode<K,V> getLowerSubNode() {
			return (AssociativeTrieNode<K,V>) super.getLowerSubNode();
		}

		@SuppressWarnings("unchecked")
		@Override
		public AssociativeTrieNode<K,V> getParent() {
			return (AssociativeTrieNode<K,V>) super.getParent();
		}

		@SuppressWarnings("unchecked")
		@Override
		public V get(K addr) {
			addr = checkBlockOrAddress(addr, true);
			OpResult<K> result = new OpResult<>(addr, Operation.LOOKUP);
			matchBits(result);
			AssociativeTrieNode<K,V> node = (AssociativeTrieNode<K,V>) result.existingNode;
			return node == null ? null : node.getValue();
		}

		/**
		 * The has code is the same as that specified by {@link java.util.Map.Entry#hashCode()}
		 */
		@Override
		public int hashCode() {
			if(value == null) {
				return super.hashCode();
			}
			return super.hashCode() ^ value.hashCode();
		}

		/**
		 * Clones the subtrie starting with this node as root. 
		 * The nodes are cloned, the keys and values are not cloned.
		 */
		@SuppressWarnings("unchecked")
		@Override
		public AssociativeTrieNode<K,V> cloneTree() {
			return (AssociativeTrieNode<K,V>) super.cloneTree();
		}

		/**
		 * Clones the node.  Keys and values are not cloned, but parent node, lower and upper sub-nodes, 
		 * are all set to null.
		 */
		@SuppressWarnings("unchecked")
		@Override
		public AssociativeTrieNode<K,V> clone() {
			return (AssociativeTrieNode<K,V>) super.clone();
		}

		/**
		 * Returns whether the key and mapped value match those of the given node
		 */
		@SuppressWarnings("unchecked")
		@Override
		public boolean equals(Object o) {
			if (o == this) {
				return true;
			} else if(o instanceof AssociativeTrieNode<?,?>) {
				AssociativeTrieNode<K,V> other = ((AssociativeTrieNode<K,V>) o);
				return super.equals(o) && Objects.equals(getValue(), other.getValue());
			}
			return false;
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<? extends AssociativeTrieNode<K,V>> nodeIterator(boolean forward) {
			return (Iterator<? extends AssociativeTrieNode<K,V>>) super.nodeIterator(forward);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<? extends AssociativeTrieNode<K,V>> allNodeIterator(boolean forward) {
			return (Iterator<? extends AssociativeTrieNode<K,V>>) super.allNodeIterator(forward);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<? extends AssociativeTrieNode<K,V>> blockSizeNodeIterator(boolean lowerSubNodeFirst) {
			return (Iterator<? extends AssociativeTrieNode<K,V>>) super.blockSizeNodeIterator(lowerSubNodeFirst);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<? extends AssociativeTrieNode<K,V>> blockSizeAllNodeIterator(boolean lowerSubNodeFirst) {
			return (Iterator<? extends AssociativeTrieNode<K,V>>) super.blockSizeAllNodeIterator(lowerSubNodeFirst);
		}

		@SuppressWarnings("unchecked")
		@Override
		public <C> CachingIterator<? extends AssociativeTrieNode<K,V>, K, C> blockSizeCachingAllNodeIterator() {
			return (CachingIterator<? extends AssociativeTrieNode<K,V>, K, C>) super.blockSizeCachingAllNodeIterator();
		}

		@SuppressWarnings("unchecked")
		@Override
		public <C> CachingIterator<? extends AssociativeTrieNode<K,V>, K, C> containingFirstIterator(boolean forwardSubNodeOrder) {
			return (CachingIterator<? extends AssociativeTrieNode<K,V>, K, C>) super.containingFirstIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public <C> CachingIterator<? extends AssociativeTrieNode<K,V>, K, C> containingFirstAllNodeIterator(boolean forwardSubNodeOrder) {
			return (CachingIterator<? extends AssociativeTrieNode<K,V>, K, C>) super.containingFirstAllNodeIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<? extends AssociativeTrieNode<K,V>> containedFirstIterator(boolean forwardSubNodeOrder) {
			return (Iterator<? extends AssociativeTrieNode<K,V>>) super.containedFirstIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<? extends AssociativeTrieNode<K,V>> containedFirstAllNodeIterator(boolean forwardSubNodeOrder) {
			return (Iterator<? extends AssociativeTrieNode<K,V>>) super.containedFirstAllNodeIterator(forwardSubNodeOrder);
		}

		@Override
		public Spliterator<? extends AssociativeTrieNode<K,V>> nodeSpliterator(boolean forward) {
			return nodeSpliterator(forward, true);
		}

		@Override
		public Spliterator<? extends AssociativeTrieNode<K,V>> allNodeSpliterator(boolean forward) {
			return nodeSpliterator(forward, false);
		}

		@Override
		@SuppressWarnings("unchecked")
		Spliterator<? extends AssociativeTrieNode<K,V>> nodeSpliterator(boolean forward, boolean addedNodesOnly) {
			return (Spliterator<? extends AssociativeTrieNode<K, V>>) super.nodeSpliterator(forward, addedNodesOnly);
		}

		@SuppressWarnings("unchecked")
		@Override
		public AssociativeTrieNode<K,V> previousAddedNode() {
			return (AssociativeTrieNode<K,V>) super.previousAddedNode();
		}

		@SuppressWarnings("unchecked")
		@Override
		public AssociativeTrieNode<K,V> nextAddedNode() {
			return (AssociativeTrieNode<K,V>) super.nextAddedNode();
		}

		@SuppressWarnings("unchecked")
		@Override
		public AssociativeTrieNode<K,V> nextNode() {
			return (AssociativeTrieNode<K,V>) super.nextNode();
		}

		@SuppressWarnings("unchecked")
		@Override
		public AssociativeTrieNode<K,V> previousNode() {
			return (AssociativeTrieNode<K,V>) super.previousNode();
		}

		@SuppressWarnings("unchecked")
		@Override
		public AssociativeTrieNode<K,V> firstNode() {
			return (AssociativeTrieNode<K,V>) super.firstNode();
		}

		@SuppressWarnings("unchecked")
		@Override
		public AssociativeTrieNode<K,V> lastNode() {
			return (AssociativeTrieNode<K,V>) super.lastNode();
		}

		@SuppressWarnings("unchecked")
		@Override
		public AssociativeTrieNode<K,V> firstAddedNode() {
			return (AssociativeTrieNode<K,V>) super.firstAddedNode();
		}

		@SuppressWarnings("unchecked")
		@Override
		public AssociativeTrieNode<K,V> lastAddedNode() {
			return (AssociativeTrieNode<K,V>) super.lastAddedNode();
		}

		@SuppressWarnings("unchecked")
		@Override
		public AssociativeTrieNode<K,V> lowerAddedNode(K addr) {
			return (AssociativeTrieNode<K, V>) super.lowerAddedNode(addr);
		}

		@SuppressWarnings("unchecked")
		@Override
		public AssociativeTrieNode<K,V> floorAddedNode(K addr) {
			return (AssociativeTrieNode<K, V>) super.floorAddedNode(addr);
		}

		@SuppressWarnings("unchecked")
		@Override
		public AssociativeTrieNode<K,V> higherAddedNode(K addr) {
			return (AssociativeTrieNode<K, V>) super.higherAddedNode(addr);
		}

		@SuppressWarnings("unchecked")
		@Override
		public AssociativeTrieNode<K,V> ceilingAddedNode(K addr) {
			return (AssociativeTrieNode<K, V>) super.ceilingAddedNode(addr);
		}

		@SuppressWarnings("unchecked")
		@Override
		public AssociativeTrieNode<K,V> getAddedNode(K addr) {
			return (AssociativeTrieNode<K,V>) super.getAddedNode(addr);
		}
		
		@SuppressWarnings("unchecked")
		@Override
		public AssociativeTrieNode<K,V> getNode(K addr) {
			return (AssociativeTrieNode<K, V>) super.getNode(addr);
		}

		@SuppressWarnings("unchecked")
		@Override
		public AssociativeTrieNode<K,V> removeElementsContainedBy(K addr) {
			return (AssociativeTrieNode<K, V>) super.removeElementsContainedBy(addr);
		}

		@SuppressWarnings("unchecked")
		@Override
		public AssociativeTrieNode<K,V> elementsContainedBy(K addr) {
			return (AssociativeTrieNode<K, V>) super.elementsContainedBy(addr);
		}

		@SuppressWarnings("unchecked")
		@Override
		public AssociativeTrieNode<K,V> elementsContaining(K addr) {
			return (AssociativeTrieNode<K, V>) super.elementsContaining(addr);
		}

		@Override
		@SuppressWarnings("unchecked")
		void matchedInserted(OpResult<K> result) {
			super.matchedInserted(result);
			result.existingValue = getValue();
			setValue((V) result.newValue);
		}

		@Override
		@SuppressWarnings("unchecked")
		void added(OpResult<K> result) {
			super.added(result);
			setValue((V) result.newValue);
		}

		/**
		 * 
		 * @param result
		 * @return true if a new node needs to be created (match is null) or added (match is non-null)
		 */
		@Override
		@SuppressWarnings("unchecked")
		boolean remap(OpResult<K> result, boolean isMatch) {
			Function<? super V, ? extends Object> remapper = (Function<? super V, ? extends Object>) result.remapper;
			Object newValue;
			Change change = changeTracker.getCurrent();
			V existingValue = isMatch ? getValue() : null;
			result.existingValue = existingValue;
			newValue = remapper.apply(existingValue);
			if(newValue == REMAP_ACTION.DO_NOTHING) {
				return false;
			} else if(newValue == REMAP_ACTION.REMOVE_NODE) { 
				if(isMatch) {
					changeTracker.changedSince(change);
					clearValue();
					remove(result);
				}
				return false;
			} else if (isMatch) {
				if(newValue != existingValue) {
					changeTracker.changedSince(change);
					result.newValue = newValue;
					return true;
				} // else node already has the value we want
				return false;
			} else {
				result.newValue = newValue;
				return true;
			}
		}

		/**
		 * The node remains in the trie, but is no longer an added node.
		 * Even if the node is removed from the trie, we must remove the value,
		 * this is needed for the compute method, which returns the value (which must be null when we have removed).
		 */
		@Override
		void removed() {
			super.removed();
			clearValue();
		}

		@SuppressWarnings("unchecked")
		@Override
		protected void replaceThisRoot(BinaryTreeNode<K> replacement) {
			super.replaceThisRoot(replacement);
			if(replacement == null) {
				setValue(null);
			} else {
				setValue(((AssociativeTrieNode<K,V>) replacement).getValue());
			}
		}

		@Override
		String getNodeIdentifier() {
			String label = super.getNodeIdentifier();
			String middle = " = ";
			V value = getValue();
			int valueLen;
			if(value instanceof CharSequence) {
				valueLen = ((CharSequence) value).length();
			} else {
				valueLen = 50;
			}
			StringBuilder builder = new StringBuilder(label.length() + middle.length() + valueLen);
			return builder.append(label).append(middle).append(value).toString();
		}
	}

	static enum REMAP_ACTION { DO_NOTHING, REMOVE_NODE }

	AddressTrieMap<K,V> map;

	public AssociativeAddressTrie(AssociativeTrieNode<K, V> root) {
		super(root);
	}

	protected AssociativeAddressTrie(AssociativeTrieNode<K, V> root, AddressBounds<K> bounds) {
		super(root, bounds);
	}

	@SuppressWarnings("unchecked")
	@Override
	protected AssociativeTrieNode<K, V> absoluteRoot() {
		return (AssociativeTrieNode<K, V>) super.absoluteRoot();
	}

	@SuppressWarnings("unchecked")
	@Override
	public AssociativeTrieNode<K, V> getRoot() {
		return (AssociativeTrieNode<K, V>) super.getRoot();
	}

	@SuppressWarnings("unchecked")
	@Override
	public V put(K addr, V value) {
		addr = checkBlockOrAddress(addr, true);
		if(bounds != null) {
			if(!bounds.isInBounds(addr)) {
				throwOutOfBounds();
			}
		}
		adjustRoot(addr);
		AssociativeTrieNode<K, V> root = absoluteRoot();
		OpResult<K> result = new OpResult<>(addr, Operation.INSERT);
		result.newValue = value;
		root.matchBits(result);
		return (V) result.existingValue;
	}

	@Override
	public boolean putNew(K addr, V value) {
		addr = checkBlockOrAddress(addr, true);
		if(bounds != null) {
			if(!bounds.isInBounds(addr)) {
				throwOutOfBounds();
			}
		}
		adjustRoot(addr);
		AssociativeTrieNode<K, V> root = absoluteRoot();
		OpResult<K> result = new OpResult<>(addr, Operation.INSERT);
		result.newValue = value;
		root.matchBits(result);
		return !result.exists;
	}

	@SuppressWarnings("unchecked")
	@Override
	public AssociativeTrieNode<K, V> addNode(K addr) {
		return (AssociativeTrieNode<K, V>) super.addNode(addr);
	}
	@SuppressWarnings("unchecked")
	@Override
	TrieNode<K> addNode(OpResult<K> result, TrieNode<K> fromNode, TrieNode<K> nodeToAdd, boolean withValues) {
		if(withValues && nodeToAdd instanceof AssociativeTrieNode) {
			AssociativeTrieNode<K, V> node = (AssociativeTrieNode<K, V>) nodeToAdd;
			result.newValue = node.getValue();
		}
		return super.addNode(result, fromNode, nodeToAdd, withValues);
	}

	@SuppressWarnings("unchecked")
	@Override
	public AssociativeTrieNode<K, V> putTrie(AssociativeTrieNode<K, V> trie) {
		return (AssociativeTrieNode<K, V>) addTrie(trie, true);
	}

	@SuppressWarnings("unchecked")
	@Override
	public AssociativeTrieNode<K, V> putNode(K addr, V value) {
		addr = checkBlockOrAddress(addr, true);
		if(bounds != null) {
			if(!bounds.isInBounds(addr)) {
				throwOutOfBounds();
			}
		}
		adjustRoot(addr);
		AssociativeTrieNode<K, V> root = absoluteRoot();
		OpResult<K> result = new OpResult<>(addr, Operation.INSERT);
		result.newValue = value;
		root.matchBits(result);
		TrieNode<K> node = result.existingNode;
		if(node == null) {
			node = result.inserted;
		}
		return (AssociativeTrieNode<K, V>) node;
	}

	@Override
	public AssociativeTrieNode<K, V> remap(K addr, Function<? super V, ? extends V> remapper) {
		return remapImpl(addr, existingAddr -> {
			V result = remapper.apply(existingAddr);
			return result == null ? REMAP_ACTION.REMOVE_NODE : result;
		});
	}

	@Override
	public AssociativeTrieNode<K, V> remapIfAbsent(K addr, Supplier<? extends V> remapper, boolean insertNull) {
		return remapImpl(addr, existingVal -> {
			if(existingVal == null) {
				V result = remapper.get();
				if(result != null || insertNull) {
					return result;
				}
			}
			return REMAP_ACTION.DO_NOTHING;
		});
	}

	@SuppressWarnings("unchecked")
	private AssociativeTrieNode<K, V> remapImpl(K addr, Function<? super V, ? extends Object> remapper) {
		addr = checkBlockOrAddress(addr, true);
		AssociativeTrieNode<K, V> subRoot;
		if(bounds != null) {
			if(!bounds.isInBounds(addr)) {
				throwOutOfBounds();
			}
			subRoot = getRoot();
			if(subRoot == null) {
				subRoot = absoluteRoot();
			}
		} else {
			subRoot = absoluteRoot();
		}
		OpResult<K> result = new OpResult<>(addr, Operation.REMAP);
		result.remapper = remapper;
		subRoot.matchBits(result);
		TrieNode<K> node = result.existingNode;
		if(node == null) {
			node = result.inserted;
		}
		return (AssociativeTrieNode<K, V>) node;
	}

	@Override
	public V get(K addr) {
		AssociativeTrieNode<K,V> subRoot;
		if(bounds != null) {
			addr = checkBlockOrAddress(addr, true);
			if(!bounds.isInBounds(addr)) {
				return null;
			}
			subRoot = getRoot();
			if(subRoot == null) {
				return null;
				//subRoot = root();
			}
		} else {
			subRoot = absoluteRoot();
		}
		return subRoot.get(addr);
	}

	@SuppressWarnings("unchecked")
	@Override
	public AssociativeTrieNode<K, V> getAddedNode(K addr) {
		return (AssociativeTrieNode<K, V>) super.getAddedNode(addr);
	}

	@SuppressWarnings("unchecked")
	@Override
	public AssociativeTrieNode<K, V> getNode(K addr) {
		return (AssociativeTrieNode<K, V>) super.getNode(addr);
	}

	@SuppressWarnings("unchecked")
	@Override
	public AssociativeTrieNode<K,V> removeElementsContainedBy(K addr) {
		return (AssociativeTrieNode<K,V>) super.removeElementsContainedBy(addr);
	}

	@SuppressWarnings("unchecked")
	@Override
	public AssociativeTrieNode<K,V> elementsContainedBy(K addr) {
		return (AssociativeTrieNode<K,V>) super.elementsContainedBy(addr);
	}

	@SuppressWarnings("unchecked")
	@Override
	public AssociativeTrieNode<K,V> elementsContaining(K addr) {
		return (AssociativeTrieNode<K,V>) super.elementsContainedBy(addr);
	}

	public AddressTrieMap<K,V> asMap() {
		AddressTrieMap<K,V> map = this.map;
		if(map == null) {
			map = new AddressTrieMap<K,V>(this);
		}
		return map;
	}

	@Override
	@SuppressWarnings("unchecked")
	AssociativeAddressTrie<K,V> elementsContainedByToSubTrie(K addr) {
		return (AssociativeAddressTrie<K, V>) super.elementsContainedByToSubTrie(addr);
	}

	@Override
	@SuppressWarnings("unchecked")
	AssociativeAddressTrie<K,V> elementsContainingToTrie(K addr) {
		return (AssociativeAddressTrie<K, V>) super.elementsContainingToTrie(addr);
	}

	// creates a new one-node trie with a new root and the given bounds
	@Override
	protected abstract AssociativeAddressTrie<K,V> createNew(AddressBounds<K> bounds);

	// create a trie with the same root as this one, but different bounds
	@Override
	protected abstract AssociativeAddressTrie<K,V> createSubTrie(AddressBounds<K> bounds);

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<? extends AssociativeTrieNode<K,V>> nodeIterator(boolean forward) {
		return (Iterator<? extends AssociativeTrieNode<K, V>>) super.nodeIterator(forward);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<? extends AssociativeTrieNode<K,V>> allNodeIterator(boolean forward) {
		return (Iterator<? extends AssociativeTrieNode<K, V>>) super.allNodeIterator(forward);
	}

	@SuppressWarnings("unchecked")
	@Override
	public <C> CachingIterator<? extends AssociativeTrieNode<K,V>, K, C> blockSizeCachingAllNodeIterator() {
		return (CachingIterator<? extends AssociativeTrieNode<K, V>, K, C>) super.blockSizeCachingAllNodeIterator();
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<? extends AssociativeTrieNode<K,V>> blockSizeNodeIterator(boolean lowerSubNodeFirst) {
		return (Iterator<? extends AssociativeTrieNode<K, V>>) super.blockSizeNodeIterator(lowerSubNodeFirst);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<? extends AssociativeTrieNode<K,V>> blockSizeAllNodeIterator(boolean lowerSubNodeFirst) {
		return (Iterator<? extends AssociativeTrieNode<K, V>>) super.blockSizeAllNodeIterator(lowerSubNodeFirst);
	}

	@SuppressWarnings("unchecked")
	@Override
	public <C> CachingIterator<? extends AssociativeTrieNode<K,V>, K, C> containingFirstIterator(boolean lowerSubNodeFirst) {
		return (CachingIterator<? extends AssociativeTrieNode<K, V>, K, C>) super.containingFirstIterator(lowerSubNodeFirst);
	}

	@SuppressWarnings("unchecked")
	@Override
	public <C> CachingIterator<? extends AssociativeTrieNode<K,V>, K, C> containingFirstAllNodeIterator(boolean lowerSubNodeFirst) {
		return (CachingIterator<? extends AssociativeTrieNode<K, V>, K, C>) super.containingFirstAllNodeIterator(lowerSubNodeFirst);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<? extends AssociativeTrieNode<K,V>> containedFirstIterator(boolean forwardSubNodeOrder) {
		return (Iterator<? extends AssociativeTrieNode<K, V>>) super.containedFirstIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<? extends AssociativeTrieNode<K,V>> containedFirstAllNodeIterator(boolean forwardSubNodeOrder) {
		return (Iterator<? extends AssociativeTrieNode<K, V>>) super.containedFirstAllNodeIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	Spliterator<? extends AssociativeTrieNode<K,V>> nodeSpliterator(boolean forward, boolean addedNodesOnly) {
		return (Spliterator<? extends AssociativeTrieNode<K, V>>) super.nodeSpliterator(forward, addedNodesOnly);
	}

	@Override
	public Spliterator<? extends AssociativeTrieNode<K,V>> nodeSpliterator(boolean forward) {
		return nodeSpliterator(forward, true);
	}

	@Override
	public Spliterator<? extends AssociativeTrieNode<K,V>> allNodeSpliterator(boolean forward) {
		return nodeSpliterator(forward, false);
	}

	@Override
	@SuppressWarnings("unchecked")
	public AssociativeTrieNode<K,V> firstNode() {
		return (AssociativeTrieNode<K, V>) super.firstNode();
	}

	@Override
	@SuppressWarnings("unchecked")
	public AssociativeTrieNode<K,V> lastNode() {
		return (AssociativeTrieNode<K, V>) super.lastNode();
	}

	@Override
	@SuppressWarnings("unchecked")
	public AssociativeTrieNode<K,V> firstAddedNode() {
		return (AssociativeTrieNode<K, V>) super.firstAddedNode();
	}

	@Override
	@SuppressWarnings("unchecked")
	public AssociativeTrieNode<K,V> lastAddedNode() {
		return (AssociativeTrieNode<K, V>) super.lastAddedNode();
	}

	@Override
	@SuppressWarnings("unchecked")
	public AssociativeTrieNode<K, V> lowerAddedNode(K addr) {
		return (AssociativeTrieNode<K, V>) super.lowerAddedNode(addr);
	}

	@Override
	@SuppressWarnings("unchecked")
	public AssociativeTrieNode<K, V> floorAddedNode(K addr) {
		return (AssociativeTrieNode<K, V>) super.floorAddedNode(addr);
	}

	@Override
	@SuppressWarnings("unchecked")
	public AssociativeTrieNode<K, V> higherAddedNode(K addr) {
		return (AssociativeTrieNode<K, V>) super.higherAddedNode(addr);
	}

	@Override
	@SuppressWarnings("unchecked")
	public AssociativeTrieNode<K, V> ceilingAddedNode(K addr) {
		return (AssociativeTrieNode<K, V>) super.ceilingAddedNode(addr);
	}

	@SuppressWarnings("unchecked")
	@Override
	public AssociativeAddressTrie<K, V> clone() {
		AssociativeAddressTrie<K, V> result = (AssociativeAddressTrie<K, V>) super.clone();
		result.map = null;
		return result;
	}

	@Override
	public boolean equals(Object o) {
		return o instanceof AssociativeAddressTrie && super.equals(o);
	}
}
