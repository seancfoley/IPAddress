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
package inet.ipaddr.mac;

import java.util.Iterator;
import java.util.List;
import java.util.Spliterator;
import java.util.function.Function;
import java.util.function.Supplier;

import inet.ipaddr.format.util.AssociativeAddressTrie;
import inet.ipaddr.format.util.BinaryTreeNode;
import inet.ipaddr.format.util.BinaryTreeNode.CachingIterator;

public class MACAddressAssociativeTrie<V> extends AssociativeAddressTrie<MACAddress, V> {

	private static final long serialVersionUID = 1L;

	private static final MACAddress INIT_ROOT = MACAddressTrie.INIT_ROOT;
	private static final MACAddress INIT_ROOT_EXTENDED = MACAddressTrie.INIT_ROOT_EXTENDED;

	public MACAddressAssociativeTrie() {
		super(new MACAssociativeTrieNode<V>());
	}

	protected MACAddressAssociativeTrie(AddressBounds<MACAddress> bounds) {
		super(new MACAssociativeTrieNode<V>(), bounds);
	}

	protected MACAddressAssociativeTrie(MACAssociativeTrieNode<V> root, AddressBounds<MACAddress> bounds) {
		super(root, bounds);
	}

	// if the very first address inserted into the trie is 64-bit, the trie is 64 bit
	@Override
	protected void adjustRoot(MACAddress addr) {
		if(isEmpty() && addr.getSegmentCount() == MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT) {
			absoluteRoot().setExtendedRootKey();
		}
	}

	@Override
	public MACAssociativeTrieNode<V> getRoot() {
		return (MACAssociativeTrieNode<V>) super.getRoot();
	}

	@Override
	protected MACAssociativeTrieNode<V> absoluteRoot() {
		return (MACAssociativeTrieNode<V>) super.absoluteRoot();
	}

	@Override
	protected MACAddressAssociativeTrie<V> createNew(AddressBounds<MACAddress> bounds) {
		return new MACAddressAssociativeTrie<V>(bounds);
	}

	@Override
	protected MACAddressAssociativeTrie<V> createSubTrie(AddressBounds<MACAddress> bounds) {
		return new MACAddressAssociativeTrie<V>(absoluteRoot(), bounds);
	}

	public static class MACAssociativeTrieNode<V> extends AssociativeTrieNode<MACAddress, V> {

		private static final long serialVersionUID = 1L;

		protected MACAssociativeTrieNode(MACAddress addr) {
			super(addr);
		}

		public MACAssociativeTrieNode() { // root node
			super(INIT_ROOT);
		}

		@Override
		protected void replaceThisRoot(BinaryTreeNode<MACAddress> replacement) {
			super.replaceThisRoot(replacement);
			if(!FREEZE_ROOT && replacement == null) {
				setKey(INIT_ROOT);
			}
		}

		void setExtendedRootKey() {
			setKey(INIT_ROOT_EXTENDED);
		}

		@Override
		public MACAssociativeTrieNode<V> getUpperSubNode() {
			return (MACAssociativeTrieNode<V>) super.getUpperSubNode();
		}

		@Override
		public MACAssociativeTrieNode<V> getLowerSubNode() {
			return (MACAssociativeTrieNode<V>) super.getLowerSubNode();
		}

		@Override
		public MACAssociativeTrieNode<V> getParent() {
			return (MACAssociativeTrieNode<V>) super.getParent();
		}

		@Override
		protected MACAssociativeTrieNode<V> createNewImpl(MACAddress addr) {
			return new MACAssociativeTrieNode<V>(addr);
		}

		@Override
		public MACAssociativeTrieNode<V> removeElementsContainedBy(MACAddress addr) {
			return (MACAssociativeTrieNode<V>) super.removeElementsContainedBy(addr);
		}

		@Override
		public MACAssociativeTrieNode<V> elementsContainedBy(MACAddress addr) {
			return (MACAssociativeTrieNode<V>) super.elementsContainedBy(addr);
		}

		@Override
		public MACAssociativeTrieNode<V> elementsContaining(MACAddress addr) {
			return (MACAssociativeTrieNode<V>) super.elementsContaining(addr);
		}

		@Override
		public MACAssociativeTrieNode<V> getAddedNode(MACAddress addr) {
			return (MACAssociativeTrieNode<V>) super.getAddedNode(addr);
		}

		@Override
		public MACAssociativeTrieNode<V> getNode(MACAddress addr) {
			return (MACAssociativeTrieNode<V>) super.getNode(addr);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<MACAssociativeTrieNode<V>> nodeIterator(boolean forward) {
			return (Iterator<MACAssociativeTrieNode<V>>) super.nodeIterator(forward);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<MACAssociativeTrieNode<V>> allNodeIterator(boolean forward) {
			return (Iterator<MACAssociativeTrieNode<V>>) super.allNodeIterator(forward);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<MACAssociativeTrieNode<V>> blockSizeNodeIterator(boolean lowerSubNodeFirst) {
			return (Iterator<MACAssociativeTrieNode<V>>) super.blockSizeNodeIterator(lowerSubNodeFirst);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<MACAssociativeTrieNode<V>> blockSizeAllNodeIterator(boolean lowerSubNodeFirst) {
			return (Iterator<MACAssociativeTrieNode<V>>) super.blockSizeAllNodeIterator(lowerSubNodeFirst);
		}

		@SuppressWarnings("unchecked")
		@Override
		public <C> CachingIterator<MACAssociativeTrieNode<V>, MACAddress, C> blockSizeCachingAllNodeIterator() {
			return (CachingIterator<MACAssociativeTrieNode<V>, MACAddress, C>) super.blockSizeCachingAllNodeIterator();
		}

		@SuppressWarnings("unchecked")
		@Override
		public <C> CachingIterator<MACAssociativeTrieNode<V>, MACAddress, C> containingFirstIterator(boolean forwardSubNodeOrder) {
			return (CachingIterator<MACAssociativeTrieNode<V>, MACAddress, C>) super.containingFirstIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public <C> CachingIterator<MACAssociativeTrieNode<V>, MACAddress, C> containingFirstAllNodeIterator(boolean forwardSubNodeOrder) {
			return (CachingIterator<MACAssociativeTrieNode<V>, MACAddress, C>) super.containingFirstAllNodeIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<MACAssociativeTrieNode<V>> containedFirstIterator(boolean forwardSubNodeOrder) {
			return (Iterator<MACAssociativeTrieNode<V>>) super.containedFirstIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<MACAssociativeTrieNode<V>> containedFirstAllNodeIterator(boolean forwardSubNodeOrder) {
			return (Iterator<MACAssociativeTrieNode<V>>) super.containedFirstAllNodeIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Spliterator<MACAssociativeTrieNode<V>> nodeSpliterator(boolean forward) {
			return (Spliterator<MACAssociativeTrieNode<V>>) super.nodeSpliterator(forward);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Spliterator<MACAssociativeTrieNode<V>> allNodeSpliterator(boolean forward) {
			return (Spliterator<MACAssociativeTrieNode<V>>) super.allNodeSpliterator(forward);
		}

		@Override
		public MACAssociativeTrieNode<V> previousAddedNode() {
			return (MACAssociativeTrieNode<V>) super.previousAddedNode();
		}

		@Override
		public MACAssociativeTrieNode<V> nextAddedNode() {
			return (MACAssociativeTrieNode<V>) super.nextAddedNode();
		}

		@Override
		public MACAssociativeTrieNode<V> nextNode() {
			return (MACAssociativeTrieNode<V>) super.nextNode();
		}

		@Override
		public MACAssociativeTrieNode<V> previousNode() {
			return (MACAssociativeTrieNode<V>) super.previousNode();
		}

		@Override
		public MACAssociativeTrieNode<V> lowerAddedNode(MACAddress addr) {
			return (MACAssociativeTrieNode<V>) super.lowerAddedNode(addr);
		}

		@Override
		public MACAssociativeTrieNode<V> floorAddedNode(MACAddress addr) {
			return (MACAssociativeTrieNode<V>) super.floorAddedNode(addr);
		}

		@Override
		public MACAssociativeTrieNode<V> higherAddedNode(MACAddress addr) {
			return (MACAssociativeTrieNode<V>) super.higherAddedNode(addr);
		}

		@Override
		public MACAssociativeTrieNode<V> ceilingAddedNode(MACAddress addr) {
			return (MACAssociativeTrieNode<V>) super.ceilingAddedNode(addr);
		}

		@Override
		public MACAssociativeTrieNode<V> firstNode() {
			return (MACAssociativeTrieNode<V>) super.firstNode();
		}

		@Override
		public MACAssociativeTrieNode<V> lastNode() {
			return (MACAssociativeTrieNode<V>) super.lastNode();
		}

		@Override
		public MACAssociativeTrieNode<V> firstAddedNode() {
			return (MACAssociativeTrieNode<V>) super.firstAddedNode();
		}

		@Override
		public MACAssociativeTrieNode<V> lastAddedNode() {
			return (MACAssociativeTrieNode<V>) super.lastAddedNode();
		}

		@Override
		public MACAssociativeTrieNode<V> cloneTree() {
			return (MACAssociativeTrieNode<V>) super.cloneTree();
		}

		@Override
		public MACAssociativeTrieNode<V> clone() {
			return (MACAssociativeTrieNode<V>) super.clone();
		}

		@Override
		public boolean equals(Object o) {
			return o instanceof MACAddressAssociativeTrie.MACAssociativeTrieNode && super.equals(o);
		}
	}

	@Override
	public MACAssociativeTrieNode<V> removeElementsContainedBy(MACAddress addr) {
		return (MACAssociativeTrieNode<V>) super.removeElementsContainedBy(addr);
	}

	@Override
	public MACAssociativeTrieNode<V> elementsContainedBy(MACAddress addr) {
		return (MACAssociativeTrieNode<V>) super.elementsContainedBy(addr);
	}

	@Override
	public MACAssociativeTrieNode<V> elementsContaining(MACAddress addr) {
		return (MACAssociativeTrieNode<V>) super.elementsContaining(addr);
	}

	@Override
	public MACAssociativeTrieNode<V> getAddedNode(MACAddress addr) {
		return (MACAssociativeTrieNode<V>) super.getAddedNode(addr);
	}

	@Override
	public MACAssociativeTrieNode<V> getNode(MACAddress addr) {
		return (MACAssociativeTrieNode<V>) super.getNode(addr);
	}

	@Override
	public MACAssociativeTrieNode<V> addNode(MACAddress addr) {
		return (MACAssociativeTrieNode<V>) super.addNode(addr);
	}

	@SuppressWarnings("unchecked")
	@Override
	public MACAssociativeTrieNode<V> addTrie(TrieNode<MACAddress> trie) {
		return (MACAssociativeTrieNode<V>) super.addTrie(trie);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<MACAssociativeTrieNode<V>> nodeIterator(boolean forward) {
		return (Iterator<MACAssociativeTrieNode<V>>) super.nodeIterator(forward);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<MACAssociativeTrieNode<V>> allNodeIterator(boolean forward) {
		return (Iterator<MACAssociativeTrieNode<V>>) super.allNodeIterator(forward);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<MACAssociativeTrieNode<V>> blockSizeNodeIterator(boolean lowerSubNodeFirst) {
		return (Iterator<MACAssociativeTrieNode<V>>) super.blockSizeNodeIterator(lowerSubNodeFirst);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<MACAssociativeTrieNode<V>> blockSizeAllNodeIterator(boolean lowerSubNodeFirst) {
		return (Iterator<MACAssociativeTrieNode<V>>) super.blockSizeAllNodeIterator(lowerSubNodeFirst);
	}

	@SuppressWarnings("unchecked")
	@Override
	public <C> CachingIterator<MACAssociativeTrieNode<V>, MACAddress, C> blockSizeCachingAllNodeIterator() {
		return (CachingIterator<MACAssociativeTrieNode<V>, MACAddress, C>) super.blockSizeCachingAllNodeIterator();
	}

	@SuppressWarnings("unchecked")
	@Override
	public <C> CachingIterator<MACAssociativeTrieNode<V>, MACAddress, C> containingFirstIterator(boolean forwardSubNodeOrder) {
		return (CachingIterator<MACAssociativeTrieNode<V>, MACAddress, C>) super.containingFirstIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public <C> CachingIterator<MACAssociativeTrieNode<V>, MACAddress, C> containingFirstAllNodeIterator(boolean forwardSubNodeOrder) {
		return (CachingIterator<MACAssociativeTrieNode<V>, MACAddress, C>) super.containingFirstAllNodeIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<MACAssociativeTrieNode<V>> containedFirstIterator(boolean forwardSubNodeOrder) {
		return (Iterator<MACAssociativeTrieNode<V>>) super.containedFirstIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<MACAssociativeTrieNode<V>> containedFirstAllNodeIterator(boolean forwardSubNodeOrder) {
		return (Iterator<MACAssociativeTrieNode<V>>) super.containedFirstAllNodeIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Spliterator<MACAssociativeTrieNode<V>> nodeSpliterator(boolean forward) {
		return (Spliterator<MACAssociativeTrieNode<V>>) super.nodeSpliterator(forward);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Spliterator<MACAssociativeTrieNode<V>> allNodeSpliterator(boolean forward) {
		return (Spliterator<MACAssociativeTrieNode<V>>) super.allNodeSpliterator(forward);
	}

	@Override
	public MACAssociativeTrieNode<V> lowerAddedNode(MACAddress addr) {
		return (MACAssociativeTrieNode<V>) super.lowerAddedNode(addr);
	}

	@Override
	public MACAssociativeTrieNode<V> floorAddedNode(MACAddress addr) {
		return (MACAssociativeTrieNode<V>) super.floorAddedNode(addr);
	}

	@Override
	public MACAssociativeTrieNode<V> higherAddedNode(MACAddress addr) {
		return (MACAssociativeTrieNode<V>) super.higherAddedNode(addr);
	}

	@Override
	public MACAssociativeTrieNode<V> ceilingAddedNode(MACAddress addr) {
		return (MACAssociativeTrieNode<V>) super.ceilingAddedNode(addr);
	}

	@Override
	public MACAssociativeTrieNode<V> firstNode() {
		return (MACAssociativeTrieNode<V>) super.firstNode();
	}

	@Override
	public MACAssociativeTrieNode<V> lastNode() {
		return (MACAssociativeTrieNode<V>) super.lastNode();
	}

	@Override
	public MACAssociativeTrieNode<V> firstAddedNode() {
		return (MACAssociativeTrieNode<V>) super.firstAddedNode();
	}

	@Override
	public MACAssociativeTrieNode<V> lastAddedNode() {
		return (MACAssociativeTrieNode<V>) super.lastAddedNode();
	}

	@Override
	public MACAssociativeTrieNode<V> putNode(MACAddress addr, V value) {
		return (MACAssociativeTrieNode<V>) super.putNode(addr, value);
	}

	@Override
	public MACAssociativeTrieNode<V> putTrie(AssociativeTrieNode<MACAddress, V> trie) {
		return (MACAssociativeTrieNode<V>) super.putTrie(trie);
	}

	@Override
	public MACAssociativeTrieNode<V> remap(MACAddress addr, Function<? super V, ? extends V> remapper) {
		return (MACAssociativeTrieNode<V>) super.remap(addr, remapper);
	}

	@Override
	public MACAssociativeTrieNode<V> remapIfAbsent(MACAddress addr, Supplier<? extends V> remapper, boolean insertNull) {
		return (MACAssociativeTrieNode<V>) super.remapIfAbsent(addr, remapper, insertNull);
	}

	@Override
	public boolean equals(Object o) {
		return o instanceof MACAddressAssociativeTrie && super.equals(o);
	}

	@Override
	public MACAddressAssociativeTrie<V> clone() {
		return (MACAddressAssociativeTrie<V>) super.clone();
	}

	@SuppressWarnings("unchecked")
	@Override
	public AssociativeAddressTrie<MACAddress, List<MACAssociativeTrieNode<?>>> constructAddedNodesTree() {
		MACAddressAssociativeTrie<List<AssociativeTrieNode<MACAddress, ?>>> trie = new MACAddressAssociativeTrie<>();
		contructAddedTree(trie);
		MACAddressAssociativeTrie<? extends List<? extends AssociativeTrieNode<MACAddress, ?>>> ret = trie;
		return (AssociativeAddressTrie<MACAddress, List<MACAssociativeTrieNode<?>>>) ret;
	}
}
