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
package inet.ipaddr.ipv4;

import java.util.Iterator;
import java.util.Spliterator;
import java.util.function.Function;
import java.util.function.Supplier;

import inet.ipaddr.format.util.AssociativeAddedTree;
import inet.ipaddr.format.util.AssociativeAddressTrie;
import inet.ipaddr.format.util.BinaryTreeNode;
import inet.ipaddr.format.util.BinaryTreeNode.CachingIterator;

/**
 * An IPv4 address trie in which each node can be associated with a value.
 * 
 * See {@link AssociativeAddressTrie} for more details.
 * 
 * @author scfoley
 * 
 * @param <V> the type of the associated values
 *
 */
public class IPv4AddressAssociativeTrie<V> extends AssociativeAddressTrie<IPv4Address, V> {

	private static final long serialVersionUID = 1L;

	private static final IPv4Address INIT_ROOT = IPv4AddressTrie.INIT_ROOT;

	public IPv4AddressAssociativeTrie() {
		super(new IPv4AssociativeTrieNode<V>());
	}

	protected IPv4AddressAssociativeTrie(AddressBounds<IPv4Address> bounds) {
		super(new IPv4AssociativeTrieNode<V>(), bounds);
	}

	protected IPv4AddressAssociativeTrie(IPv4AssociativeTrieNode<V> root, AddressBounds<IPv4Address> bounds) {
		super(root, bounds);
	}

	@Override
	public IPv4AssociativeTrieNode<V> getRoot() {
		return (IPv4AssociativeTrieNode<V>) super.getRoot();
	}

	@Override
	protected IPv4AssociativeTrieNode<V> absoluteRoot() {
		return (IPv4AssociativeTrieNode<V>) super.absoluteRoot();
	}

	@Override
	protected IPv4AddressAssociativeTrie<V> createNew(AddressBounds<IPv4Address> bounds) {
		return new IPv4AddressAssociativeTrie<V>(bounds);
	}

	@Override
	protected IPv4AddressAssociativeTrie<V> createSubTrie(AddressBounds<IPv4Address> bounds) {
		return new IPv4AddressAssociativeTrie<V>(absoluteRoot(), bounds);
	}

	public static class IPv4AssociativeTrieNode<V> extends AssociativeTrieNode<IPv4Address, V> {

		private static final long serialVersionUID = 1L;

		protected IPv4AssociativeTrieNode(IPv4Address addr) {
			super(addr);
		}

		public IPv4AssociativeTrieNode() { // root node
			super(INIT_ROOT);
		}

		@Override
		protected void replaceThisRoot(BinaryTreeNode<IPv4Address> replacement) {
			super.replaceThisRoot(replacement);
			if(!FREEZE_ROOT && replacement == null) {
				setKey(INIT_ROOT);
			}
		}

		@Override
		public IPv4AssociativeTrieNode<V> getUpperSubNode() {
			return (IPv4AssociativeTrieNode<V>) super.getUpperSubNode();
		}

		@Override
		public IPv4AssociativeTrieNode<V> getLowerSubNode() {
			return (IPv4AssociativeTrieNode<V>) super.getLowerSubNode();
		}

		@Override
		public IPv4AssociativeTrieNode<V> getParent() {
			return (IPv4AssociativeTrieNode<V>) super.getParent();
		}

		@Override
		protected IPv4AssociativeTrieNode<V> createNewImpl(IPv4Address addr) {
			return new IPv4AssociativeTrieNode<V>(addr);
		}

		@Override
		public IPv4AssociativeTrieNode<V> removeElementsContainedBy(IPv4Address addr) {
			return (IPv4AssociativeTrieNode<V>) super.removeElementsContainedBy(addr);
		}

		@Override
		public IPv4AssociativeTrieNode<V> elementsContainedBy(IPv4Address addr) {
			return (IPv4AssociativeTrieNode<V>) super.elementsContainedBy(addr);
		}

		@Override
		public IPv4AssociativeTrieNode<V> elementsContaining(IPv4Address addr) {
			return (IPv4AssociativeTrieNode<V>) super.elementsContaining(addr);
		}
		
		@Override
		public IPv4AssociativeTrieNode<V> longestPrefixMatchNode(IPv4Address addr) {
			return (IPv4AssociativeTrieNode<V>) super.longestPrefixMatchNode(addr);
		}

		@Override
		public IPv4AssociativeTrieNode<V> getAddedNode(IPv4Address addr) {
			return (IPv4AssociativeTrieNode<V>) super.getAddedNode(addr);
		}

		@Override
		public IPv4AssociativeTrieNode<V> getNode(IPv4Address addr) {
			return (IPv4AssociativeTrieNode<V>) super.getNode(addr);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPv4AssociativeTrieNode<V>> nodeIterator(boolean forward) {
			return (Iterator<IPv4AssociativeTrieNode<V>>) super.nodeIterator(forward);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPv4AssociativeTrieNode<V>> allNodeIterator(boolean forward) {
			return (Iterator<IPv4AssociativeTrieNode<V>>) super.allNodeIterator(forward);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPv4AssociativeTrieNode<V>> blockSizeNodeIterator(boolean lowerSubNodeFirst) {
			return (Iterator<IPv4AssociativeTrieNode<V>>) super.blockSizeNodeIterator(lowerSubNodeFirst);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPv4AssociativeTrieNode<V>> blockSizeAllNodeIterator(boolean lowerSubNodeFirst) {
			return (Iterator<IPv4AssociativeTrieNode<V>>) super.blockSizeAllNodeIterator(lowerSubNodeFirst);
		}

		@SuppressWarnings("unchecked")
		@Override
		public <C> CachingIterator<IPv4AssociativeTrieNode<V>, IPv4Address, C> blockSizeCachingAllNodeIterator() {
			return (CachingIterator<IPv4AssociativeTrieNode<V>, IPv4Address, C>) super.blockSizeCachingAllNodeIterator();
		}

		@SuppressWarnings("unchecked")
		@Override
		public <C> CachingIterator<IPv4AssociativeTrieNode<V>, IPv4Address, C> containingFirstIterator(boolean forwardSubNodeOrder) {
			return (CachingIterator<IPv4AssociativeTrieNode<V>, IPv4Address, C>) super.containingFirstIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public <C> CachingIterator<IPv4AssociativeTrieNode<V>, IPv4Address, C> containingFirstAllNodeIterator(boolean forwardSubNodeOrder) {
			return (CachingIterator<IPv4AssociativeTrieNode<V>, IPv4Address, C>) super.containingFirstAllNodeIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPv4AssociativeTrieNode<V>> containedFirstIterator(boolean forwardSubNodeOrder) {
			return (Iterator<IPv4AssociativeTrieNode<V>>) super.containedFirstIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPv4AssociativeTrieNode<V>> containedFirstAllNodeIterator(boolean forwardSubNodeOrder) {
			return (Iterator<IPv4AssociativeTrieNode<V>>) super.containedFirstAllNodeIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Spliterator<IPv4AssociativeTrieNode<V>> nodeSpliterator(boolean forward) {
			return (Spliterator<IPv4AssociativeTrieNode<V>>) super.nodeSpliterator(forward);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Spliterator<IPv4AssociativeTrieNode<V>> allNodeSpliterator(boolean forward) {
			return (Spliterator<IPv4AssociativeTrieNode<V>>) super.allNodeSpliterator(forward);
		}

		@Override
		public IPv4AssociativeTrieNode<V> previousAddedNode() {
			return (IPv4AssociativeTrieNode<V>) super.previousAddedNode();
		}

		@Override
		public IPv4AssociativeTrieNode<V> nextAddedNode() {
			return (IPv4AssociativeTrieNode<V>) super.nextAddedNode();
		}

		@Override
		public IPv4AssociativeTrieNode<V> nextNode() {
			return (IPv4AssociativeTrieNode<V>) super.nextNode();
		}

		@Override
		public IPv4AssociativeTrieNode<V> previousNode() {
			return (IPv4AssociativeTrieNode<V>) super.previousNode();
		}

		@Override
		public IPv4AssociativeTrieNode<V> lowerAddedNode(IPv4Address addr) {
			return (IPv4AssociativeTrieNode<V>) super.lowerAddedNode(addr);
		}

		@Override
		public IPv4AssociativeTrieNode<V> floorAddedNode(IPv4Address addr) {
			return (IPv4AssociativeTrieNode<V>) super.floorAddedNode(addr);
		}

		@Override
		public IPv4AssociativeTrieNode<V> higherAddedNode(IPv4Address addr) {
			return (IPv4AssociativeTrieNode<V>) super.higherAddedNode(addr);
		}

		@Override
		public IPv4AssociativeTrieNode<V> ceilingAddedNode(IPv4Address addr) {
			return (IPv4AssociativeTrieNode<V>) super.ceilingAddedNode(addr);
		}

		@Override
		public IPv4AssociativeTrieNode<V> firstNode() {
			return (IPv4AssociativeTrieNode<V>) super.firstNode();
		}

		@Override
		public IPv4AssociativeTrieNode<V> lastNode() {
			return (IPv4AssociativeTrieNode<V>) super.lastNode();
		}

		@Override
		public IPv4AssociativeTrieNode<V> firstAddedNode() {
			return (IPv4AssociativeTrieNode<V>) super.firstAddedNode();
		}

		@Override
		public IPv4AssociativeTrieNode<V> lastAddedNode() {
			return (IPv4AssociativeTrieNode<V>) super.lastAddedNode();
		}
		
		@Override
		protected IPv4AddressAssociativeTrie<V> createNewTree() {
			return new IPv4AddressAssociativeTrie<V>();
		}
		
		@Override
		public IPv4AddressAssociativeTrie<V> asNewTrie() {
			return (IPv4AddressAssociativeTrie<V>) super.asNewTrie();
		}

		@Override
		public IPv4AssociativeTrieNode<V> cloneTree() {
			return (IPv4AssociativeTrieNode<V>) super.cloneTree();
		}

		@Override
		public IPv4AssociativeTrieNode<V> clone() {
			return (IPv4AssociativeTrieNode<V>) super.clone();
		}

		@Override
		public boolean equals(Object o) {
			return o instanceof IPv4AddressAssociativeTrie.IPv4AssociativeTrieNode && super.equals(o);
		}

		@Override
		protected TrieKeyData getTrieKeyCache(IPv4Address addr) {
			return addr.getTrieKeyCache();
		}
	}

	@Override
	public IPv4AssociativeTrieNode<V> removeElementsContainedBy(IPv4Address addr) {
		return (IPv4AssociativeTrieNode<V>) super.removeElementsContainedBy(addr);
	}

	@Override
	public IPv4AssociativeTrieNode<V> elementsContainedBy(IPv4Address addr) {
		return (IPv4AssociativeTrieNode<V>) super.elementsContainedBy(addr);
	}

	@Override
	public IPv4AssociativeTrieNode<V> elementsContaining(IPv4Address addr) {
		return (IPv4AssociativeTrieNode<V>) super.elementsContaining(addr);
	}

	@Override
	public IPv4AssociativeTrieNode<V> longestPrefixMatchNode(IPv4Address addr) {
		return (IPv4AssociativeTrieNode<V>) super.longestPrefixMatchNode(addr);
	}

	@Override
	public IPv4AssociativeTrieNode<V> getAddedNode(IPv4Address addr) {
		return (IPv4AssociativeTrieNode<V>) super.getAddedNode(addr);
	}

	@Override
	public IPv4AssociativeTrieNode<V> getNode(IPv4Address addr) {
		return (IPv4AssociativeTrieNode<V>) super.getNode(addr);
	}

	@Override
	public IPv4AssociativeTrieNode<V> addNode(IPv4Address addr) {
		return (IPv4AssociativeTrieNode<V>) super.addNode(addr);
	}

	@SuppressWarnings("unchecked")
	@Override
	public IPv4AssociativeTrieNode<V> addTrie(TrieNode<IPv4Address> trie) {
		return (IPv4AssociativeTrieNode<V>) super.addTrie(trie);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv4AssociativeTrieNode<V>> nodeIterator(boolean forward) {
		return (Iterator<IPv4AssociativeTrieNode<V>>) super.nodeIterator(forward);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv4AssociativeTrieNode<V>> allNodeIterator(boolean forward) {
		return (Iterator<IPv4AssociativeTrieNode<V>>) super.allNodeIterator(forward);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv4AssociativeTrieNode<V>> blockSizeNodeIterator(boolean lowerSubNodeFirst) {
		return (Iterator<IPv4AssociativeTrieNode<V>>) super.blockSizeNodeIterator(lowerSubNodeFirst);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv4AssociativeTrieNode<V>> blockSizeAllNodeIterator(boolean lowerSubNodeFirst) {
		return (Iterator<IPv4AssociativeTrieNode<V>>) super.blockSizeAllNodeIterator(lowerSubNodeFirst);
	}

	@SuppressWarnings("unchecked")
	@Override
	public <C> CachingIterator<IPv4AssociativeTrieNode<V>, IPv4Address, C> blockSizeCachingAllNodeIterator() {
		return (CachingIterator<IPv4AssociativeTrieNode<V>, IPv4Address, C>) super.blockSizeCachingAllNodeIterator();
	}

	@SuppressWarnings("unchecked")
	@Override
	public <C> CachingIterator<IPv4AssociativeTrieNode<V>, IPv4Address, C> containingFirstIterator(boolean forwardSubNodeOrder) {
		return (CachingIterator<IPv4AssociativeTrieNode<V>, IPv4Address, C>) super.containingFirstIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public <C> CachingIterator<IPv4AssociativeTrieNode<V>, IPv4Address, C> containingFirstAllNodeIterator(boolean forwardSubNodeOrder) {
		return (CachingIterator<IPv4AssociativeTrieNode<V>, IPv4Address, C>) super.containingFirstAllNodeIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv4AssociativeTrieNode<V>> containedFirstIterator(boolean forwardSubNodeOrder) {
		return (Iterator<IPv4AssociativeTrieNode<V>>) super.containedFirstIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv4AssociativeTrieNode<V>> containedFirstAllNodeIterator(boolean forwardSubNodeOrder) {
		return (Iterator<IPv4AssociativeTrieNode<V>>) super.containedFirstAllNodeIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Spliterator<IPv4AssociativeTrieNode<V>> nodeSpliterator(boolean forward) {
		return (Spliterator<IPv4AssociativeTrieNode<V>>) super.nodeSpliterator(forward);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Spliterator<IPv4AssociativeTrieNode<V>> allNodeSpliterator(boolean forward) {
		return (Spliterator<IPv4AssociativeTrieNode<V>>) super.allNodeSpliterator(forward);
	}

	@Override
	public IPv4AssociativeTrieNode<V> lowerAddedNode(IPv4Address addr) {
		return (IPv4AssociativeTrieNode<V>) super.lowerAddedNode(addr);
	}

	@Override
	public IPv4AssociativeTrieNode<V> floorAddedNode(IPv4Address addr) {
		return (IPv4AssociativeTrieNode<V>) super.floorAddedNode(addr);
	}

	@Override
	public IPv4AssociativeTrieNode<V> higherAddedNode(IPv4Address addr) {
		return (IPv4AssociativeTrieNode<V>) super.higherAddedNode(addr);
	}

	@Override
	public IPv4AssociativeTrieNode<V> ceilingAddedNode(IPv4Address addr) {
		return (IPv4AssociativeTrieNode<V>) super.ceilingAddedNode(addr);
	}

	@Override
	public IPv4AssociativeTrieNode<V> firstNode() {
		return (IPv4AssociativeTrieNode<V>) super.firstNode();
	}

	@Override
	public IPv4AssociativeTrieNode<V> lastNode() {
		return (IPv4AssociativeTrieNode<V>) super.lastNode();
	}

	@Override
	public IPv4AssociativeTrieNode<V> firstAddedNode() {
		return (IPv4AssociativeTrieNode<V>) super.firstAddedNode();
	}

	@Override
	public IPv4AssociativeTrieNode<V> lastAddedNode() {
		return (IPv4AssociativeTrieNode<V>) super.lastAddedNode();
	}

	@Override
	public IPv4AssociativeTrieNode<V> putNode(IPv4Address addr, V value) {
		return (IPv4AssociativeTrieNode<V>) super.putNode(addr, value);
	}

	@Override
	public IPv4AssociativeTrieNode<V> putTrie(AssociativeTrieNode<IPv4Address, V> trie) {
		return (IPv4AssociativeTrieNode<V>) super.putTrie(trie);
	}

	@Override
	public IPv4AssociativeTrieNode<V> remap(IPv4Address addr, Function<? super V, ? extends V> remapper) {
		return (IPv4AssociativeTrieNode<V>) super.remap(addr, remapper);
	}

	@Override
	public IPv4AssociativeTrieNode<V> remapIfAbsent(IPv4Address addr, Supplier<? extends V> remapper, boolean insertNull) {
		return (IPv4AssociativeTrieNode<V>) super.remapIfAbsent(addr, remapper, insertNull);
	}

	@Override
	public boolean equals(Object o) {
		return o instanceof IPv4AddressAssociativeTrie && super.equals(o);
	}

	@Override
	public IPv4AddressAssociativeTrie<V> clone() {
		return (IPv4AddressAssociativeTrie<V>) super.clone();
	}

	@Override
	public AssociativeAddedTree<IPv4Address, V> constructAddedNodesTree() {
		IPv4AddressAssociativeTrie<SubNodesMappingAssociative<IPv4Address, V>> trie = new IPv4AddressAssociativeTrie<SubNodesMappingAssociative<IPv4Address, V>>();
		contructAssociativeAddedTree(trie);
		return new AssociativeAddedTree<IPv4Address, V>(trie);
	}

	@Override
	public String toAddedNodesTreeString() {
		IPv4AddressAssociativeTrie<SubNodesMappingAssociative<IPv4Address, V>> trie = new IPv4AddressAssociativeTrie<SubNodesMappingAssociative<IPv4Address, V>>();
		contructAssociativeAddedTree(trie);
		return toAddedNodesTreeString(trie);
	}
}
