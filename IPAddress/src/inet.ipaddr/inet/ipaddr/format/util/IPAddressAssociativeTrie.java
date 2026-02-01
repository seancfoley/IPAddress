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
package inet.ipaddr.format.util;

import java.util.Iterator;
import java.util.Spliterator;

import inet.ipaddr.IPAddress;
import inet.ipaddr.format.util.BinaryTreeNode.CachingIterator;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv6.IPv6Address;


/**
 * IPAddressAssociativeTrie is a polymorphic address trie that can use either IPv4 or IPv6 addresses as keys, but not both at the same time.
 * Each node can be associated with a value.
 * <p>
 * This trie will accept IPv4 keys if the first added node has an IPv4 address key, and then afterwards additional nodes added must have IPv4 address keys.
 * Similarly, this trie will accept IPv6 keys if the first added node has an IPv6 address key, and then afterwards additional nodes added must have IPv6 address keys.
 * If a trie is emptied of all added nodes, then it can accept a new node with a key that is either IPv4 or IPv6 again.
 * <p>
 * If you attempt to add a node with an IPv4 key to a trie with IPv6 keys, or vice versa, then IllegalArgumentException will be thrown.
 * <p>
 * See {@link AssociativeAddressTrie} for more details.
 * 
 * @author scfoley
 * 
 * @param <V> the type of the associated values
 *
 */
public class IPAddressAssociativeTrie<V> extends AssociativeAddressTrie<IPAddress, V> {

	private static final long serialVersionUID = 1L;
	
	static final IPv6Address IPV6_ROOT = IPAddressTrie.IPV6_ROOT;
	static final IPv4Address IPV4_ROOT = IPAddressTrie.IPV4_ROOT;

	public IPAddressAssociativeTrie() {
		super(new IPAddressAssociativeTrieNode<V>());
	}
	
	protected IPAddressAssociativeTrie(IPAddressAssociativeTrieNode<V> root, AddressBounds<IPAddress> bounds) {
		super(root, bounds);
	}
	
	protected IPAddressAssociativeTrie(AddressBounds<IPAddress> bounds) {
		super(new IPAddressAssociativeTrieNode<V>(), bounds);
	}
	
	// if the very first address inserted into the trie is IPv4, the trie is IPv4.  Same goes for IPv6.
	@Override
	protected void adjustRoot(IPAddress addr) {
		if(isInitialRoot()) {
			if(addr.isIPv6()) {
				absoluteRoot().setIPv6Key();
			} else {
				absoluteRoot().setIPv4Key();
			}
		}
	}

	@Override
	protected IPAddressAssociativeTrie<V> createNew(AddressBounds<IPAddress> bounds) {
		return new IPAddressAssociativeTrie<V>(bounds);
	}

	@Override
	protected IPAddressAssociativeTrie<V> createSubTrie(AddressBounds<IPAddress> bounds) {
		return new IPAddressAssociativeTrie<V>(absoluteRoot(), bounds);
	}

	@Override
	protected IPAddressAssociativeTrieNode<V> absoluteRoot() {
		return (IPAddressAssociativeTrieNode<V>) super.absoluteRoot();
	}

	@Override
	public IPAddressAssociativeTrieNode<V> getRoot() {
		return (IPAddressAssociativeTrieNode<V>) super.getRoot();
	}

	@Override
	public AssociativeAddedTree<IPAddress, V> constructAddedNodesTree() {
		IPAddressAssociativeTrie<SubNodesMappingAssociative<IPAddress, V>> trie = new IPAddressAssociativeTrie<SubNodesMappingAssociative<IPAddress, V>>();
		contructAssociativeAddedTree(trie);
		return new AssociativeAddedTree<IPAddress, V>(trie);
	}

	@Override
	public String toAddedNodesTreeString() {
		IPAddressAssociativeTrie<SubNodesMappingAssociative<IPAddress, V>> trie = new IPAddressAssociativeTrie<SubNodesMappingAssociative<IPAddress, V>>();
		contructAssociativeAddedTree(trie);
		return toAddedNodesTreeString(trie);
	}

	public static class IPAddressAssociativeTrieNode<V> extends AssociativeTrieNode<IPAddress, V> {

		private static final long serialVersionUID = 1L;

		protected IPAddressAssociativeTrieNode(IPAddress addr) {
			super(addr);
		}

		public IPAddressAssociativeTrieNode() {
			super(null);
		} // root node
		
		@Override
		protected void replaceThisRoot(BinaryTreeNode<IPAddress> replacement) {
			super.replaceThisRoot(replacement);
			if(replacement == null) {
				setKey(null);
			}
		}
		
		void setIPv6Key() {
			setKey(IPV6_ROOT);
		}
		
		void setIPv4Key() {
			setKey(IPV4_ROOT);
		}
		
		@Override
		protected IPAddressAssociativeTrieNode<V> createNewImpl(IPAddress newAddr) {
			return new IPAddressAssociativeTrieNode<V>(newAddr);
		}

		@Override
		protected IPAddressAssociativeTrie<V> createNewTree() {
			return new IPAddressAssociativeTrie<V>();
		}
		
		@Override
		public IPAddressAssociativeTrieNode<V> getUpperSubNode() {
			return (IPAddressAssociativeTrieNode<V>) super.getUpperSubNode();
		}

		@Override
		public IPAddressAssociativeTrieNode<V> getLowerSubNode() {
			return (IPAddressAssociativeTrieNode<V>) super.getLowerSubNode();
		}

		@Override
		public IPAddressAssociativeTrieNode<V> getParent() {
			return (IPAddressAssociativeTrieNode<V>) super.getParent();
		}

		@Override
		public IPAddressAssociativeTrieNode<V> removeElementsContainedBy(IPAddress addr) {
			return (IPAddressAssociativeTrieNode<V>) super.removeElementsContainedBy(addr);
		}

		@Override
		public IPAddressAssociativeTrieNode<V> elementsContainedBy(IPAddress addr) {
			return (IPAddressAssociativeTrieNode<V>) super.elementsContainedBy(addr);
		}

		@Override
		public IPAddressAssociativeTrieNode<V> elementsContaining(IPAddress addr) {
			return (IPAddressAssociativeTrieNode<V>) super.elementsContaining(addr);
		}

		@Override
		public IPAddressAssociativeTrieNode<V> longestPrefixMatchNode(IPAddress addr) {
			return (IPAddressAssociativeTrieNode<V>) super.longestPrefixMatchNode(addr);
		}

		@Override
		public IPAddressAssociativeTrieNode<V> getAddedNode(IPAddress addr) {
			return (IPAddressAssociativeTrieNode<V>) super.getAddedNode(addr);
		}

		@Override
		public IPAddressAssociativeTrieNode<V> getNode(IPAddress addr) {
			return (IPAddressAssociativeTrieNode<V>) super.getNode(addr);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPAddressAssociativeTrieNode<V>> nodeIterator(boolean forward) {
			return (Iterator<IPAddressAssociativeTrieNode<V>>) super.nodeIterator(forward);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPAddressAssociativeTrieNode<V>> allNodeIterator(boolean forward) {
			return (Iterator<IPAddressAssociativeTrieNode<V>>) super.allNodeIterator(forward);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPAddressAssociativeTrieNode<V>> blockSizeNodeIterator(boolean lowerSubNodeFirst) {
			return (Iterator<IPAddressAssociativeTrieNode<V>>) super.blockSizeNodeIterator(lowerSubNodeFirst);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPAddressAssociativeTrieNode<V>> blockSizeAllNodeIterator(boolean lowerSubNodeFirst) {
			return (Iterator<IPAddressAssociativeTrieNode<V>>) super.blockSizeAllNodeIterator(lowerSubNodeFirst);
		}

		@SuppressWarnings("unchecked")
		@Override
		public <C> CachingIterator<IPAddressAssociativeTrieNode<V>, IPAddress, C> blockSizeCachingAllNodeIterator() {
			return (CachingIterator<IPAddressAssociativeTrieNode<V>, IPAddress, C>) super.blockSizeCachingAllNodeIterator();
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPAddressAssociativeTrieNode<V>> containingFirstIterator(boolean forwardSubNodeOrder) {
			return (Iterator<IPAddressAssociativeTrieNode<V>>) super.containingFirstIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public <C> CachingIterator<IPAddressAssociativeTrieNode<V>, IPAddress, C> containingFirstAllNodeIterator(boolean forwardSubNodeOrder) {
			return (CachingIterator<IPAddressAssociativeTrieNode<V>, IPAddress, C>) super.containingFirstAllNodeIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPAddressAssociativeTrieNode<V>> containedFirstIterator(boolean forwardSubNodeOrder) {
			return (Iterator<IPAddressAssociativeTrieNode<V>>) super.containedFirstIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPAddressAssociativeTrieNode<V>> containedFirstAllNodeIterator(boolean forwardSubNodeOrder) {
			return (Iterator<IPAddressAssociativeTrieNode<V>>) super.containedFirstAllNodeIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Spliterator<IPAddressAssociativeTrieNode<V>> nodeSpliterator(boolean forward) {
			return (Spliterator<IPAddressAssociativeTrieNode<V>>) super.nodeSpliterator(forward);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Spliterator<IPAddressAssociativeTrieNode<V>> allNodeSpliterator(boolean forward) {
			return (Spliterator<IPAddressAssociativeTrieNode<V>>) super.allNodeSpliterator(forward);
		}

		@Override
		public IPAddressAssociativeTrieNode<V> previousAddedNode() {
			return (IPAddressAssociativeTrieNode<V>) super.previousAddedNode();
		}

		@Override
		public IPAddressAssociativeTrieNode<V> nextAddedNode() {
			return (IPAddressAssociativeTrieNode<V>) super.nextAddedNode();
		}

		@Override
		public IPAddressAssociativeTrieNode<V> nextNode() {
			return (IPAddressAssociativeTrieNode<V>) super.nextNode();
		}

		@Override
		public IPAddressAssociativeTrieNode<V> previousNode() {
			return (IPAddressAssociativeTrieNode<V>) super.previousNode();
		}

		@Override
		public IPAddressAssociativeTrieNode<V> removeElementsIntersectedBy(IPAddress addr) { 
			return (IPAddressAssociativeTrieNode<V>) super.removeElementsIntersectedBy(addr);
		}

		@Override
		public IPAddressAssociativeTrieNode<V> containingFloorAddedNode(IPAddress addr) {
			return (IPAddressAssociativeTrieNode<V>) super.containingFloorAddedNode(addr);
		}
		
		@Override
		public IPAddressAssociativeTrieNode<V> containingLowerAddedNode(IPAddress addr) {
			return (IPAddressAssociativeTrieNode<V>) super.containingLowerAddedNode(addr);
		}

		@Override
		public IPAddressAssociativeTrieNode<V> containingCeilingAddedNode(IPAddress addr) {
			return (IPAddressAssociativeTrieNode<V>) super.containingCeilingAddedNode(addr);
		}

		@Override
		public IPAddressAssociativeTrieNode<V> containingHigherAddedNode(IPAddress addr) {
			return (IPAddressAssociativeTrieNode<V>) super.containingHigherAddedNode(addr);
		}

		@Override
		public IPAddressAssociativeTrieNode<V> lowerAddedNode(IPAddress addr) {
			return (IPAddressAssociativeTrieNode<V>) super.lowerAddedNode(addr);
		}

		@Override
		public IPAddressAssociativeTrieNode<V> floorAddedNode(IPAddress addr) {
			return (IPAddressAssociativeTrieNode<V>) super.floorAddedNode(addr);
		}

		@Override
		public IPAddressAssociativeTrieNode<V> higherAddedNode(IPAddress addr) {
			return (IPAddressAssociativeTrieNode<V>) super.higherAddedNode(addr);
		}

		@Override
		public IPAddressAssociativeTrieNode<V> ceilingAddedNode(IPAddress addr) {
			return (IPAddressAssociativeTrieNode<V>) super.ceilingAddedNode(addr);
		}

		@Override
		public IPAddressAssociativeTrieNode<V> firstNode() {
			return (IPAddressAssociativeTrieNode<V>) super.firstNode();
		}

		@Override
		public IPAddressAssociativeTrieNode<V> lastNode() {
			return (IPAddressAssociativeTrieNode<V>) super.lastNode();
		}

		@Override
		public IPAddressAssociativeTrieNode<V> firstAddedNode() {
			return (IPAddressAssociativeTrieNode<V>) super.firstAddedNode();
		}

		@Override
		public IPAddressAssociativeTrieNode<V> lastAddedNode() {
			return (IPAddressAssociativeTrieNode<V>) super.lastAddedNode();
		}
		
		@Override
		public IPAddressAssociativeTrie<V> asNewTrie() {
			return (IPAddressAssociativeTrie<V>) super.asNewTrie();
		}

		@Override
		public IPAddressAssociativeTrieNode<V> cloneTree() {
			return (IPAddressAssociativeTrieNode<V>) super.cloneTree();
		}

		@Override
		public IPAddressAssociativeTrieNode<V> clone() {
			return (IPAddressAssociativeTrieNode<V>) super.clone();
		}

		@Override
		public boolean equals(Object o) {
			return o instanceof IPAddressAssociativeTrieNode && super.equals(o);
		}
	}
	
	@Override
	public IPAddressAssociativeTrieNode<V> removeElementsContainedBy(IPAddress addr) {
		return (IPAddressAssociativeTrieNode<V>) super.removeElementsContainedBy(addr);
	}

	@Override
	public IPAddressAssociativeTrieNode<V> elementsContainedBy(IPAddress addr) {
		return (IPAddressAssociativeTrieNode<V>) super.elementsContainedBy(addr);
	}

	@Override
	public IPAddressAssociativeTrieNode<V> elementsContaining(IPAddress addr) {
		return (IPAddressAssociativeTrieNode<V>) super.elementsContaining(addr);
	}

	@Override
	public IPAddressAssociativeTrieNode<V> longestPrefixMatchNode(IPAddress addr) {
		return (IPAddressAssociativeTrieNode<V>) super.longestPrefixMatchNode(addr);
	}

	@Override
	public IPAddressAssociativeTrieNode<V> getAddedNode(IPAddress addr) {
		return (IPAddressAssociativeTrieNode<V>) super.getAddedNode(addr);
	}

	@Override
	public IPAddressAssociativeTrieNode<V> getNode(IPAddress addr) {
		return (IPAddressAssociativeTrieNode<V>) super.getNode(addr);
	}

	@Override
	public IPAddressAssociativeTrieNode<V> addNode(IPAddress addr) {
		return (IPAddressAssociativeTrieNode<V>) super.addNode(addr);
	}

	@SuppressWarnings("unchecked")
	@Override
	public IPAddressAssociativeTrieNode<V> addTrie(TrieNode<IPAddress> trie) {
		return (IPAddressAssociativeTrieNode<V>) super.addTrie(trie);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPAddressAssociativeTrieNode<V>> nodeIterator(boolean forward) {
		return (Iterator<IPAddressAssociativeTrieNode<V>>) super.nodeIterator(forward);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPAddressAssociativeTrieNode<V>> allNodeIterator(boolean forward) {
		return (Iterator<IPAddressAssociativeTrieNode<V>>) super.allNodeIterator(forward);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPAddressAssociativeTrieNode<V>> blockSizeNodeIterator(boolean lowerSubNodeFirst) {
		return (Iterator<IPAddressAssociativeTrieNode<V>>) super.blockSizeNodeIterator(lowerSubNodeFirst);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPAddressAssociativeTrieNode<V>> blockSizeAllNodeIterator(boolean lowerSubNodeFirst) {
		return (Iterator<IPAddressAssociativeTrieNode<V>>) super.blockSizeAllNodeIterator(lowerSubNodeFirst);
	}

	@SuppressWarnings("unchecked")
	@Override
	public <C> CachingIterator<IPAddressAssociativeTrieNode<V>, IPAddress, C> blockSizeCachingAllNodeIterator() {
		return (CachingIterator<IPAddressAssociativeTrieNode<V>, IPAddress, C>) super.blockSizeCachingAllNodeIterator();
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPAddressAssociativeTrieNode<V>> containingFirstIterator(boolean forwardSubNodeOrder) {
		return (Iterator<IPAddressAssociativeTrieNode<V>>) super.containingFirstIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public <C> CachingIterator<IPAddressAssociativeTrieNode<V>, IPAddress, C> containingFirstAllNodeIterator(boolean forwardSubNodeOrder) {
		return (CachingIterator<IPAddressAssociativeTrieNode<V>, IPAddress, C>) super.containingFirstAllNodeIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPAddressAssociativeTrieNode<V>> containedFirstIterator(boolean forwardSubNodeOrder) {
		return (Iterator<IPAddressAssociativeTrieNode<V>>) super.containedFirstIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPAddressAssociativeTrieNode<V>> containedFirstAllNodeIterator(boolean forwardSubNodeOrder) {
		return (Iterator<IPAddressAssociativeTrieNode<V>>) super.containedFirstAllNodeIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Spliterator<IPAddressAssociativeTrieNode<V>> nodeSpliterator(boolean forward) {
		return (Spliterator<IPAddressAssociativeTrieNode<V>>) super.nodeSpliterator(forward);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Spliterator<IPAddressAssociativeTrieNode<V>> allNodeSpliterator(boolean forward) {
		return (Spliterator<IPAddressAssociativeTrieNode<V>>) super.allNodeSpliterator(forward);
	}

	@Override
	public IPAddressAssociativeTrieNode<V> removeElementsIntersectedBy(IPAddress addr) { 
		return (IPAddressAssociativeTrieNode<V>) super.removeElementsIntersectedBy(addr);
	}

	@Override
	public IPAddressAssociativeTrieNode<V> addIfNoElementsContaining(IPAddress addr) { 
		return (IPAddressAssociativeTrieNode<V>) super.addIfNoElementsContaining(addr);
	}

	@Override
	public IPAddressAssociativeTrieNode<V> containingFloorAddedNode(IPAddress addr) {
		return (IPAddressAssociativeTrieNode<V>) super.containingFloorAddedNode(addr);
	}
	
	@Override
	public IPAddressAssociativeTrieNode<V> containingLowerAddedNode(IPAddress addr) {
		return (IPAddressAssociativeTrieNode<V>) super.containingLowerAddedNode(addr);
	}

	@Override
	public IPAddressAssociativeTrieNode<V> containingCeilingAddedNode(IPAddress addr) {
		return (IPAddressAssociativeTrieNode<V>) super.containingCeilingAddedNode(addr);
	}

	@Override
	public IPAddressAssociativeTrieNode<V> containingHigherAddedNode(IPAddress addr) {
		return (IPAddressAssociativeTrieNode<V>) super.containingHigherAddedNode(addr);
	}

	@Override
	public IPAddressAssociativeTrieNode<V> lowerAddedNode(IPAddress addr) {
		return (IPAddressAssociativeTrieNode<V>) super.lowerAddedNode(addr);
	}

	@Override
	public IPAddressAssociativeTrieNode<V> floorAddedNode(IPAddress addr) {
		return (IPAddressAssociativeTrieNode<V>) super.floorAddedNode(addr);
	}

	@Override
	public IPAddressAssociativeTrieNode<V> higherAddedNode(IPAddress addr) {
		return (IPAddressAssociativeTrieNode<V>) super.higherAddedNode(addr);
	}

	@Override
	public IPAddressAssociativeTrieNode<V> ceilingAddedNode(IPAddress addr) {
		return (IPAddressAssociativeTrieNode<V>) super.ceilingAddedNode(addr);
	}

	@Override
	public IPAddressAssociativeTrieNode<V> firstNode() {
		return (IPAddressAssociativeTrieNode<V>) super.firstNode();
	}

	@Override
	public IPAddressAssociativeTrieNode<V> lastNode() {
		return (IPAddressAssociativeTrieNode<V>) super.lastNode();
	}

	@Override
	public IPAddressAssociativeTrieNode<V> firstAddedNode() {
		return (IPAddressAssociativeTrieNode<V>) super.firstAddedNode();
	}

	@Override
	public IPAddressAssociativeTrieNode<V> lastAddedNode() {
		return (IPAddressAssociativeTrieNode<V>) super.lastAddedNode();
	}

	@Override
	public boolean equals(Object o) {
		return o instanceof IPAddressAssociativeTrie && super.equals(o);
	}

	@Override
	public IPAddressAssociativeTrie<V> clone() {
		return (IPAddressAssociativeTrie<V>) super.clone();
	}
}
