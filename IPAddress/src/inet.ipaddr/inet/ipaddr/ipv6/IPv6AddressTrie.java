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

import inet.ipaddr.IPAddressString;
import inet.ipaddr.format.util.AddressTrie;
import inet.ipaddr.format.util.AssociativeAddressTrie;
import inet.ipaddr.format.util.BinaryTreeNode;
import inet.ipaddr.format.util.AssociativeAddressTrie.AssociativeTrieNode;
import inet.ipaddr.format.util.BinaryTreeNode.CachingIterator;
import inet.ipaddr.ipv6.IPv6AddressAssociativeTrie.IPv6AssociativeTrieNode;


public class IPv6AddressTrie extends AddressTrie<IPv6Address> {

	private static final long serialVersionUID = 1L;

	static final IPv6Address INIT_ROOT = new IPAddressString("::/0").getAddress().toIPv6();

	public IPv6AddressTrie() {
		super(new IPv6TrieNode());
	}

	protected IPv6AddressTrie(AddressBounds<IPv6Address> bounds) {
		super(new IPv6TrieNode(), bounds);
	}

	protected IPv6AddressTrie(IPv6TrieNode root, AddressBounds<IPv6Address> bounds) {
		super(root, bounds);
	}

	@Override
	protected IPv6TrieNode absoluteRoot() {
		return (IPv6TrieNode) super.absoluteRoot();
	}

	@Override
	protected IPv6AddressTrie createNew(AddressBounds<IPv6Address> bounds) {
		return new IPv6AddressTrie(bounds);
	}

	@Override
	protected IPv6AddressTrie createSubTrie(AddressBounds<IPv6Address> bounds) {
		return new IPv6AddressTrie(absoluteRoot(), bounds);
	}

	@Override
	public IPv6TrieNode getRoot() {
		return (IPv6TrieNode) super.getRoot();
	}

	public static class IPv6TrieNode extends TrieNode<IPv6Address> {

		private static final long serialVersionUID = 1L;

		protected IPv6TrieNode(IPv6Address addr) {
			super(addr);
		}

		public IPv6TrieNode() {
			super(INIT_ROOT);
		} // root node

		@Override
		protected void replaceThisRoot(BinaryTreeNode<IPv6Address> replacement) {
			super.replaceThisRoot(replacement);
			if(!FREEZE_ROOT && replacement == null) {
				setKey(INIT_ROOT);
			}
		}

		@Override
		public IPv6TrieNode getUpperSubNode() {
			return (IPv6TrieNode) super.getUpperSubNode();
		}

		@Override
		public IPv6TrieNode getLowerSubNode() {
			return (IPv6TrieNode) super.getLowerSubNode();
		}

		@Override
		public IPv6TrieNode getParent() {
			return (IPv6TrieNode) super.getParent();
		}

		@Override
		protected IPv6TrieNode createNewImpl(IPv6Address addr) {
			return new IPv6TrieNode(addr);
		}

		@Override
		public IPv6TrieNode removeElementsContainedBy(IPv6Address addr) {
			return (IPv6TrieNode) super.removeElementsContainedBy(addr);
		}

		@Override
		public IPv6TrieNode elementsContainedBy(IPv6Address addr) {
			return (IPv6TrieNode) super.elementsContainedBy(addr);
		}

		@Override
		public IPv6TrieNode elementsContaining(IPv6Address addr) {
			return (IPv6TrieNode) super.elementsContaining(addr);
		}

		@Override
		public IPv6TrieNode getAddedNode(IPv6Address addr) {
			return (IPv6TrieNode) super.getAddedNode(addr);
		}

		@Override
		public IPv6TrieNode getNode(IPv6Address addr) {
			return (IPv6TrieNode) super.getNode(addr);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPv6TrieNode> nodeIterator(boolean forward) {
			return (Iterator<IPv6TrieNode>) super.nodeIterator(forward);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPv6TrieNode> allNodeIterator(boolean forward) {
			return (Iterator<IPv6TrieNode>) super.allNodeIterator(forward);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPv6TrieNode> blockSizeNodeIterator(boolean lowerSubNodeFirst) {
			return (Iterator<IPv6TrieNode>) super.blockSizeNodeIterator(lowerSubNodeFirst);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPv6TrieNode> blockSizeAllNodeIterator(boolean lowerSubNodeFirst) {
			return (Iterator<IPv6TrieNode>) super.blockSizeAllNodeIterator(lowerSubNodeFirst);
		}

		@SuppressWarnings("unchecked")
		@Override
		public <C> CachingIterator<IPv6TrieNode, IPv6Address, C> blockSizeCachingAllNodeIterator() {
			return (CachingIterator<IPv6TrieNode, IPv6Address, C>) super.blockSizeCachingAllNodeIterator();
		}

		@SuppressWarnings("unchecked")
		@Override
		public <C> CachingIterator<IPv6TrieNode, IPv6Address, C> containingFirstIterator(boolean forwardSubNodeOrder) {
			return (CachingIterator<IPv6TrieNode, IPv6Address, C>) super.containingFirstIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public <C> CachingIterator<IPv6TrieNode, IPv6Address, C> containingFirstAllNodeIterator(boolean forwardSubNodeOrder) {
			return (CachingIterator<IPv6TrieNode, IPv6Address, C>) super.containingFirstAllNodeIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPv6TrieNode> containedFirstIterator(boolean forwardSubNodeOrder) {
			return (Iterator<IPv6TrieNode>) super.containedFirstIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPv6TrieNode> containedFirstAllNodeIterator(boolean forwardSubNodeOrder) {
			return (Iterator<IPv6TrieNode>) super.containedFirstAllNodeIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Spliterator<IPv6TrieNode> nodeSpliterator(boolean forward) {
			return (Spliterator<IPv6TrieNode>) super.nodeSpliterator(forward);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Spliterator<IPv6TrieNode> allNodeSpliterator(boolean forward) {
			return (Spliterator<IPv6TrieNode>) super.allNodeSpliterator(forward);
		}

		@Override
		public IPv6TrieNode previousAddedNode() {
			return (IPv6TrieNode) super.previousAddedNode();
		}

		@Override
		public IPv6TrieNode nextAddedNode() {
			return (IPv6TrieNode) super.nextAddedNode();
		}

		@Override
		public IPv6TrieNode nextNode() {
			return (IPv6TrieNode) super.nextNode();
		}

		@Override
		public IPv6TrieNode previousNode() {
			return (IPv6TrieNode) super.previousNode();
		}

		@Override
		public IPv6TrieNode lowerAddedNode(IPv6Address addr) {
			return (IPv6TrieNode) super.lowerAddedNode(addr);
		}

		@Override
		public IPv6TrieNode floorAddedNode(IPv6Address addr) {
			return (IPv6TrieNode) super.floorAddedNode(addr);
		}

		@Override
		public IPv6TrieNode higherAddedNode(IPv6Address addr) {
			return (IPv6TrieNode) super.higherAddedNode(addr);
		}

		@Override
		public IPv6TrieNode ceilingAddedNode(IPv6Address addr) {
			return (IPv6TrieNode) super.ceilingAddedNode(addr);
		}

		@Override
		public IPv6TrieNode firstNode() {
			return (IPv6TrieNode) super.firstNode();
		}

		@Override
		public IPv6TrieNode lastNode() {
			return (IPv6TrieNode) super.lastNode();
		}

		@Override
		public IPv6TrieNode firstAddedNode() {
			return (IPv6TrieNode) super.firstAddedNode();
		}

		@Override
		public IPv6TrieNode lastAddedNode() {
			return (IPv6TrieNode) super.lastAddedNode();
		}

		@Override
		public IPv6TrieNode cloneTree() {
			return (IPv6TrieNode) super.cloneTree();
		}

		@Override
		public IPv6TrieNode clone() {
			return (IPv6TrieNode) super.clone();
		}

		@Override
		public boolean equals(Object o) {
			return o instanceof IPv6TrieNode && super.equals(o);
		}
	}

	@Override
	public IPv6TrieNode removeElementsContainedBy(IPv6Address addr) {
		return (IPv6TrieNode) super.removeElementsContainedBy(addr);
	}

	@Override
	public IPv6TrieNode elementsContainedBy(IPv6Address addr) {
		return (IPv6TrieNode) super.elementsContainedBy(addr);
	}

	@Override
	public IPv6TrieNode elementsContaining(IPv6Address addr) {
		return (IPv6TrieNode) super.elementsContaining(addr);
	}

	@Override
	public IPv6TrieNode getAddedNode(IPv6Address addr) {
		return (IPv6TrieNode) super.getAddedNode(addr);
	}

	@Override
	public IPv6TrieNode getNode(IPv6Address addr) {
		return (IPv6TrieNode) super.getNode(addr);
	}

	@Override
	public IPv6TrieNode addNode(IPv6Address addr) {
		return (IPv6TrieNode) super.addNode(addr);
	}

	@Override
	public IPv6TrieNode addTrie(TrieNode<IPv6Address> trie) {
		return (IPv6TrieNode) super.addTrie(trie);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv6TrieNode> nodeIterator(boolean forward) {
		return (Iterator<IPv6TrieNode>) super.nodeIterator(forward);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv6TrieNode> allNodeIterator(boolean forward) {
		return (Iterator<IPv6TrieNode>) super.allNodeIterator(forward);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv6TrieNode> blockSizeNodeIterator(boolean lowerSubNodeFirst) {
		return (Iterator<IPv6TrieNode>) super.blockSizeNodeIterator(lowerSubNodeFirst);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv6TrieNode> blockSizeAllNodeIterator(boolean lowerSubNodeFirst) {
		return (Iterator<IPv6TrieNode>) super.blockSizeAllNodeIterator(lowerSubNodeFirst);
	}

	@SuppressWarnings("unchecked")
	@Override
	public <C> CachingIterator<IPv6TrieNode, IPv6Address, C> blockSizeCachingAllNodeIterator() {
		return (CachingIterator<IPv6TrieNode, IPv6Address, C>) super.blockSizeCachingAllNodeIterator();
	}

	@SuppressWarnings("unchecked")
	@Override
	public <C> CachingIterator<IPv6TrieNode, IPv6Address, C> containingFirstIterator(boolean forwardSubNodeOrder) {
		return (CachingIterator<IPv6TrieNode, IPv6Address, C>) super.containingFirstIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public <C> CachingIterator<IPv6TrieNode, IPv6Address, C> containingFirstAllNodeIterator(boolean forwardSubNodeOrder) {
		return (CachingIterator<IPv6TrieNode, IPv6Address, C>) super.containingFirstAllNodeIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv6TrieNode> containedFirstIterator(boolean forwardSubNodeOrder) {
		return (Iterator<IPv6TrieNode>) super.containedFirstIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv6TrieNode> containedFirstAllNodeIterator(boolean forwardSubNodeOrder) {
		return (Iterator<IPv6TrieNode>) super.containedFirstAllNodeIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Spliterator<IPv6TrieNode> nodeSpliterator(boolean forward) {
		return (Spliterator<IPv6TrieNode>) super.nodeSpliterator(forward);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Spliterator<IPv6TrieNode> allNodeSpliterator(boolean forward) {
		return (Spliterator<IPv6TrieNode>) super.allNodeSpliterator(forward);
	}

	@Override
	public IPv6TrieNode lowerAddedNode(IPv6Address addr) {
		return (IPv6TrieNode) super.lowerAddedNode(addr);
	}

	@Override
	public IPv6TrieNode floorAddedNode(IPv6Address addr) {
		return (IPv6TrieNode) super.floorAddedNode(addr);
	}

	@Override
	public IPv6TrieNode higherAddedNode(IPv6Address addr) {
		return (IPv6TrieNode) super.higherAddedNode(addr);
	}

	@Override
	public IPv6TrieNode ceilingAddedNode(IPv6Address addr) {
		return (IPv6TrieNode) super.ceilingAddedNode(addr);
	}

	@Override
	public IPv6TrieNode firstNode() {
		return (IPv6TrieNode) super.firstNode();
	}

	@Override
	public IPv6TrieNode lastNode() {
		return (IPv6TrieNode) super.lastNode();
	}

	@Override
	public IPv6TrieNode firstAddedNode() {
		return (IPv6TrieNode) super.firstAddedNode();
	}

	@Override
	public IPv6TrieNode lastAddedNode() {
		return (IPv6TrieNode) super.lastAddedNode();
	}

	@Override
	public boolean equals(Object o) {
		return o instanceof IPv6AddressTrie && super.equals(o);
	}

	@Override
	public IPv6AddressTrie clone() {
		return (IPv6AddressTrie) super.clone();
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
