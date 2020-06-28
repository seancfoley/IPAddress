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
package inet.ipaddr.ipv6;

import java.util.Iterator;
import java.util.List;
import java.util.Spliterator;
import java.util.function.Function;
import java.util.function.Supplier;

import inet.ipaddr.format.util.AssociativeAddressTrie;
import inet.ipaddr.format.util.BinaryTreeNode;
import inet.ipaddr.format.util.BinaryTreeNode.CachingIterator;

/**
 * An IPv6 address trie in which each node can be associated with a value.
 * 
 * See {@link AssociativeAddressTrie} for more details.
 * 
 * @author scfoley
 *
 * @param <V> the type of the associated values
 */
public class IPv6AddressAssociativeTrie<V> extends AssociativeAddressTrie<IPv6Address, V> {

	private static final long serialVersionUID = 1L;

	private static final IPv6Address INIT_ROOT = IPv6AddressTrie.INIT_ROOT;

	public IPv6AddressAssociativeTrie() {
		super(new IPv6AssociativeTrieNode<V>());
	}

	protected IPv6AddressAssociativeTrie(AddressBounds<IPv6Address> bounds) {
		super(new IPv6AssociativeTrieNode<V>(), bounds);
	}

	protected IPv6AddressAssociativeTrie(IPv6AssociativeTrieNode<V> root, AddressBounds<IPv6Address> bounds) {
		super(root, bounds);
	}

	@Override
	public IPv6AssociativeTrieNode<V> getRoot() {
		return (IPv6AssociativeTrieNode<V>) super.getRoot();
	}

	@Override
	protected IPv6AssociativeTrieNode<V> absoluteRoot() {
		return (IPv6AssociativeTrieNode<V>) super.absoluteRoot();
	}

	@Override
	protected IPv6AddressAssociativeTrie<V> createNew(AddressBounds<IPv6Address> bounds) {
		return new IPv6AddressAssociativeTrie<V>(bounds);
	}

	@Override
	protected IPv6AddressAssociativeTrie<V> createSubTrie(AddressBounds<IPv6Address> bounds) {
		return new IPv6AddressAssociativeTrie<V>(absoluteRoot(), bounds);
	}

	public static class IPv6AssociativeTrieNode<V> extends AssociativeTrieNode<IPv6Address, V> {

		private static final long serialVersionUID = 1L;

		protected IPv6AssociativeTrieNode(IPv6Address addr) {
			super(addr);
		}

		public IPv6AssociativeTrieNode() { // root node
			super(INIT_ROOT);
		}

		@Override
		protected void replaceThisRoot(BinaryTreeNode<IPv6Address> replacement) {
			super.replaceThisRoot(replacement);
			if(!FREEZE_ROOT && replacement == null) {
				setKey(INIT_ROOT);
			}
		}

		@Override
		public IPv6AssociativeTrieNode<V> getUpperSubNode() {
			return (IPv6AssociativeTrieNode<V>) super.getUpperSubNode();
		}

		@Override
		public IPv6AssociativeTrieNode<V> getLowerSubNode() {
			return (IPv6AssociativeTrieNode<V>) super.getLowerSubNode();
		}

		@Override
		public IPv6AssociativeTrieNode<V> getParent() {
			return (IPv6AssociativeTrieNode<V>) super.getParent();
		}

		@Override
		protected IPv6AssociativeTrieNode<V> createNewImpl(IPv6Address addr) {
			return new IPv6AssociativeTrieNode<V>(addr);
		}
		
		@Override
		public IPv6AssociativeTrieNode<V> removeElementsContainedBy(IPv6Address addr) {
			return (IPv6AssociativeTrieNode<V>) super.removeElementsContainedBy(addr);
		}

		@Override
		public IPv6AssociativeTrieNode<V> elementsContainedBy(IPv6Address addr) {
			return (IPv6AssociativeTrieNode<V>) super.elementsContainedBy(addr);
		}

		@Override
		public IPv6AssociativeTrieNode<V> elementsContaining(IPv6Address addr) {
			return (IPv6AssociativeTrieNode<V>) super.elementsContaining(addr);
		}
		
		@Override
		public IPv6AssociativeTrieNode<V> longestPrefixMatchNode(IPv6Address addr) {
			return (IPv6AssociativeTrieNode<V>) super.longestPrefixMatchNode(addr);
		}

		@Override
		public IPv6AssociativeTrieNode<V> getAddedNode(IPv6Address addr) {
			return (IPv6AssociativeTrieNode<V>) super.getAddedNode(addr);
		}

		@Override
		public IPv6AssociativeTrieNode<V> getNode(IPv6Address addr) {
			return (IPv6AssociativeTrieNode<V>) super.getNode(addr);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPv6AssociativeTrieNode<V>> nodeIterator(boolean forward) {
			return (Iterator<IPv6AssociativeTrieNode<V>>) super.nodeIterator(forward);
		}
		
		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPv6AssociativeTrieNode<V>> allNodeIterator(boolean forward) {
			return (Iterator<IPv6AssociativeTrieNode<V>>) super.allNodeIterator(forward);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPv6AssociativeTrieNode<V>> blockSizeNodeIterator(boolean lowerSubNodeFirst) {
			return (Iterator<IPv6AssociativeTrieNode<V>>) super.blockSizeNodeIterator(lowerSubNodeFirst);
		}
		
		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPv6AssociativeTrieNode<V>> blockSizeAllNodeIterator(boolean lowerSubNodeFirst) {
			return (Iterator<IPv6AssociativeTrieNode<V>>) super.blockSizeAllNodeIterator(lowerSubNodeFirst);
		}

		@SuppressWarnings("unchecked")
		@Override
		public <C> CachingIterator<IPv6AssociativeTrieNode<V>, IPv6Address, C> blockSizeCachingAllNodeIterator() {
			return (CachingIterator<IPv6AssociativeTrieNode<V>, IPv6Address, C>) super.blockSizeCachingAllNodeIterator();
		}

		@SuppressWarnings("unchecked")
		@Override
		public <C> CachingIterator<IPv6AssociativeTrieNode<V>, IPv6Address, C> containingFirstIterator(boolean forwardSubNodeOrder) {
			return (CachingIterator<IPv6AssociativeTrieNode<V>, IPv6Address, C>) super.containingFirstIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public <C> CachingIterator<IPv6AssociativeTrieNode<V>, IPv6Address, C> containingFirstAllNodeIterator(boolean forwardSubNodeOrder) {
			return (CachingIterator<IPv6AssociativeTrieNode<V>, IPv6Address, C>) super.containingFirstAllNodeIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPv6AssociativeTrieNode<V>> containedFirstIterator(boolean forwardSubNodeOrder) {
			return (Iterator<IPv6AssociativeTrieNode<V>>) super.containedFirstIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPv6AssociativeTrieNode<V>> containedFirstAllNodeIterator(boolean forwardSubNodeOrder) {
			return (Iterator<IPv6AssociativeTrieNode<V>>) super.containedFirstAllNodeIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Spliterator<IPv6AssociativeTrieNode<V>> nodeSpliterator(boolean forward) {
			return (Spliterator<IPv6AssociativeTrieNode<V>>) super.nodeSpliterator(forward);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Spliterator<IPv6AssociativeTrieNode<V>> allNodeSpliterator(boolean forward) {
			return (Spliterator<IPv6AssociativeTrieNode<V>>) super.allNodeSpliterator(forward);
		}

		@Override
		public IPv6AssociativeTrieNode<V> previousAddedNode() {
			return (IPv6AssociativeTrieNode<V>) super.previousAddedNode();
		}
		
		@Override
		public IPv6AssociativeTrieNode<V> nextAddedNode() {
			return (IPv6AssociativeTrieNode<V>) super.nextAddedNode();
		}
		
		@Override
		public IPv6AssociativeTrieNode<V> nextNode() {
			return (IPv6AssociativeTrieNode<V>) super.nextNode();
		}
		
		@Override
		public IPv6AssociativeTrieNode<V> previousNode() {
			return (IPv6AssociativeTrieNode<V>) super.previousNode();
		}

		@Override
		public IPv6AssociativeTrieNode<V> lowerAddedNode(IPv6Address addr) {
			return (IPv6AssociativeTrieNode<V>) super.lowerAddedNode(addr);
		}

		@Override
		public IPv6AssociativeTrieNode<V> floorAddedNode(IPv6Address addr) {
			return (IPv6AssociativeTrieNode<V>) super.floorAddedNode(addr);
		}

		@Override
		public IPv6AssociativeTrieNode<V> higherAddedNode(IPv6Address addr) {
			return (IPv6AssociativeTrieNode<V>) super.higherAddedNode(addr);
		}

		@Override
		public IPv6AssociativeTrieNode<V> ceilingAddedNode(IPv6Address addr) {
			return (IPv6AssociativeTrieNode<V>) super.ceilingAddedNode(addr);
		}
		
		@Override
		public IPv6AssociativeTrieNode<V> firstNode() {
			return (IPv6AssociativeTrieNode<V>) super.firstNode();
		}

		@Override
		public IPv6AssociativeTrieNode<V> lastNode() {
			return (IPv6AssociativeTrieNode<V>) super.lastNode();
		}
		
		@Override
		public IPv6AssociativeTrieNode<V> firstAddedNode() {
			return (IPv6AssociativeTrieNode<V>) super.firstAddedNode();
		}

		@Override
		public IPv6AssociativeTrieNode<V> lastAddedNode() {
			return (IPv6AssociativeTrieNode<V>) super.lastAddedNode();
		}
		
		@Override
		protected IPv6AddressAssociativeTrie<V> createNewTree() {
			return new IPv6AddressAssociativeTrie<V>();
		}
		
		@Override
		public IPv6AddressAssociativeTrie<V> asNewTrie() {
			return (IPv6AddressAssociativeTrie<V>) super.asNewTrie();
		}
		
		@Override
		public IPv6AssociativeTrieNode<V> cloneTree() {
			return (IPv6AssociativeTrieNode<V>) super.cloneTree();
		}

		@Override
		public IPv6AssociativeTrieNode<V> clone() {
			return (IPv6AssociativeTrieNode<V>) super.clone();
		}

		@Override
		public boolean equals(Object o) {
			return o instanceof IPv6AddressAssociativeTrie.IPv6AssociativeTrieNode && super.equals(o);
		}
	}

	@Override
	public IPv6AssociativeTrieNode<V> removeElementsContainedBy(IPv6Address addr) {
		return (IPv6AssociativeTrieNode<V>) super.removeElementsContainedBy(addr);
	}

	@Override
	public IPv6AssociativeTrieNode<V> elementsContainedBy(IPv6Address addr) {
		return (IPv6AssociativeTrieNode<V>) super.elementsContainedBy(addr);
	}

	@Override
	public IPv6AssociativeTrieNode<V> elementsContaining(IPv6Address addr) {
		return (IPv6AssociativeTrieNode<V>) super.elementsContaining(addr);
	}
	
	@Override
	public IPv6AssociativeTrieNode<V> longestPrefixMatchNode(IPv6Address addr) {
		return (IPv6AssociativeTrieNode<V>) super.longestPrefixMatchNode(addr);
	}

	@Override
	public IPv6AssociativeTrieNode<V> getAddedNode(IPv6Address addr) {
		return (IPv6AssociativeTrieNode<V>) super.getAddedNode(addr);
	}

	@Override
	public IPv6AssociativeTrieNode<V> getNode(IPv6Address addr) {
		return (IPv6AssociativeTrieNode<V>) super.getNode(addr);
	}

	@Override
	public IPv6AssociativeTrieNode<V> addNode(IPv6Address addr) {
		return (IPv6AssociativeTrieNode<V>) super.addNode(addr);
	}

	@SuppressWarnings("unchecked")
	@Override
	public IPv6AssociativeTrieNode<V> addTrie(TrieNode<IPv6Address> trie) {
		return (IPv6AssociativeTrieNode<V>) super.addTrie(trie);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv6AssociativeTrieNode<V>> nodeIterator(boolean forward) {
		return (Iterator<IPv6AssociativeTrieNode<V>>) super.nodeIterator(forward);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv6AssociativeTrieNode<V>> allNodeIterator(boolean forward) {
		return (Iterator<IPv6AssociativeTrieNode<V>>) super.allNodeIterator(forward);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv6AssociativeTrieNode<V>> blockSizeNodeIterator(boolean lowerSubNodeFirst) {
		return (Iterator<IPv6AssociativeTrieNode<V>>) super.blockSizeNodeIterator(lowerSubNodeFirst);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv6AssociativeTrieNode<V>> blockSizeAllNodeIterator(boolean lowerSubNodeFirst) {
		return (Iterator<IPv6AssociativeTrieNode<V>>) super.blockSizeAllNodeIterator(lowerSubNodeFirst);
	}

	@SuppressWarnings("unchecked")
	@Override
	public <C> CachingIterator<IPv6AssociativeTrieNode<V>, IPv6Address, C> blockSizeCachingAllNodeIterator() {
		return (CachingIterator<IPv6AssociativeTrieNode<V>, IPv6Address, C>) super.blockSizeCachingAllNodeIterator();
	}

	@SuppressWarnings("unchecked")
	@Override
	public <C> CachingIterator<IPv6AssociativeTrieNode<V>, IPv6Address, C> containingFirstIterator(boolean forwardSubNodeOrder) {
		return (CachingIterator<IPv6AssociativeTrieNode<V>, IPv6Address, C>) super.containingFirstIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public <C> CachingIterator<IPv6AssociativeTrieNode<V>, IPv6Address, C> containingFirstAllNodeIterator(boolean forwardSubNodeOrder) {
		return (CachingIterator<IPv6AssociativeTrieNode<V>, IPv6Address, C>) super.containingFirstAllNodeIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv6AssociativeTrieNode<V>> containedFirstIterator(boolean forwardSubNodeOrder) {
		return (Iterator<IPv6AssociativeTrieNode<V>>) super.containedFirstIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv6AssociativeTrieNode<V>> containedFirstAllNodeIterator(boolean forwardSubNodeOrder) {
		return (Iterator<IPv6AssociativeTrieNode<V>>) super.containedFirstAllNodeIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Spliterator<IPv6AssociativeTrieNode<V>> nodeSpliterator(boolean forward) {
		return (Spliterator<IPv6AssociativeTrieNode<V>>) super.nodeSpliterator(forward);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Spliterator<IPv6AssociativeTrieNode<V>> allNodeSpliterator(boolean forward) {
		return (Spliterator<IPv6AssociativeTrieNode<V>>) super.allNodeSpliterator(forward);
	}

	@Override
	public IPv6AssociativeTrieNode<V> lowerAddedNode(IPv6Address addr) {
		return (IPv6AssociativeTrieNode<V>) super.lowerAddedNode(addr);
	}

	@Override
	public IPv6AssociativeTrieNode<V> floorAddedNode(IPv6Address addr) {
		return (IPv6AssociativeTrieNode<V>) super.floorAddedNode(addr);
	}

	@Override
	public IPv6AssociativeTrieNode<V> higherAddedNode(IPv6Address addr) {
		return (IPv6AssociativeTrieNode<V>) super.higherAddedNode(addr);
	}

	@Override
	public IPv6AssociativeTrieNode<V> ceilingAddedNode(IPv6Address addr) {
		return (IPv6AssociativeTrieNode<V>) super.ceilingAddedNode(addr);
	}
	
	@Override
	public IPv6AssociativeTrieNode<V> firstNode() {
		return (IPv6AssociativeTrieNode<V>) super.firstNode();
	}

	@Override
	public IPv6AssociativeTrieNode<V> lastNode() {
		return (IPv6AssociativeTrieNode<V>) super.lastNode();
	}
	
	@Override
	public IPv6AssociativeTrieNode<V> firstAddedNode() {
		return (IPv6AssociativeTrieNode<V>) super.firstAddedNode();
	}

	@Override
	public IPv6AssociativeTrieNode<V> lastAddedNode() {
		return (IPv6AssociativeTrieNode<V>) super.lastAddedNode();
	}
	
	@Override
	public IPv6AssociativeTrieNode<V> putNode(IPv6Address addr, V value) {
		return (IPv6AssociativeTrieNode<V>) super.putNode(addr, value);
	}
	
	@Override
	public IPv6AssociativeTrieNode<V> putTrie(AssociativeTrieNode<IPv6Address, V> trie) {
		return (IPv6AssociativeTrieNode<V>) super.putTrie(trie);
	}

	@Override
	public IPv6AssociativeTrieNode<V> remap(IPv6Address addr, Function<? super V, ? extends V> remapper) {
		return (IPv6AssociativeTrieNode<V>) super.remap(addr, remapper);
	}

	@Override
	public IPv6AssociativeTrieNode<V> remapIfAbsent(IPv6Address addr, Supplier<? extends V> remapper, boolean insertNull) {
		return (IPv6AssociativeTrieNode<V>) super.remapIfAbsent(addr, remapper, insertNull);
	}

	@Override
	public boolean equals(Object o) {
		return o instanceof IPv6AddressAssociativeTrie && super.equals(o);
	}
	
	@Override
	public IPv6AddressAssociativeTrie<V> clone() {
		return (IPv6AddressAssociativeTrie<V>) super.clone();
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public AssociativeAddressTrie<IPv6Address, List<IPv6AssociativeTrieNode<?>>> constructAddedNodesTree() {
		IPv6AddressAssociativeTrie<List<AssociativeTrieNode<IPv6Address, ?>>> trie = new IPv6AddressAssociativeTrie<>();
		contructAddedTree(trie);
		IPv6AddressAssociativeTrie<? extends List<? extends AssociativeTrieNode<IPv6Address, ?>>> ret = trie;
		return (AssociativeAddressTrie<IPv6Address, List<IPv6AssociativeTrieNode<?>>>) ret;
	}
}
