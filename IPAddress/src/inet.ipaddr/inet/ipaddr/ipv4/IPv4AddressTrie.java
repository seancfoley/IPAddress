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
package inet.ipaddr.ipv4;

import java.util.Iterator;
import java.util.List;
import java.util.Spliterator;

import inet.ipaddr.IPAddressString;
import inet.ipaddr.format.util.AddressTrie;
import inet.ipaddr.format.util.AssociativeAddressTrie;
import inet.ipaddr.format.util.BinaryTreeNode;
import inet.ipaddr.format.util.AssociativeAddressTrie.AssociativeTrieNode;
import inet.ipaddr.format.util.BinaryTreeNode.CachingIterator;
import inet.ipaddr.ipv4.IPv4AddressAssociativeTrie.IPv4AssociativeTrieNode;

public class IPv4AddressTrie extends AddressTrie<IPv4Address> {

	private static final long serialVersionUID = 1L;
	
	static final IPv4Address INIT_ROOT = new IPAddressString("0.0.0.0/0").getAddress().toIPv4();
	
//	public IPv4AddressTrie() {
//		super(trie -> new IPv4TrieNode());
//	}
	public IPv4AddressTrie() {
		super(new IPv4TrieNode());
	}
	
//	protected IPv4AddressTrie(IPv4TrieNode root) {
//		super(root);
//	}
	
	protected IPv4AddressTrie(AddressBounds<IPv4Address> bounds) {
		super(new IPv4TrieNode(), bounds);
	}
	
	protected IPv4AddressTrie(IPv4TrieNode root, AddressBounds<IPv4Address> bounds) {
		super(root, bounds);
	}
	
	@Override
	protected IPv4TrieNode absoluteRoot() {
		return (IPv4TrieNode) super.absoluteRoot();
	}
	
	@Override
	protected IPv4AddressTrie createNew(AddressBounds<IPv4Address> bounds) {
		return new IPv4AddressTrie(bounds);
	}
	
	@Override
	protected IPv4AddressTrie createSubTrie(AddressBounds<IPv4Address> bounds) {
		return new IPv4AddressTrie(absoluteRoot(), bounds);
	}
	
	@Override
	public IPv4TrieNode getRoot() {
		return (IPv4TrieNode) super.getRoot();
	}
	
	public static class IPv4TrieNode extends TrieNode<IPv4Address> {

		private static final long serialVersionUID = 1L;

		protected IPv4TrieNode(IPv4Address addr) {
			super(addr);
		}

		public IPv4TrieNode() {
			super(INIT_ROOT);
		} // root node

		@Override
		protected void replaceThisRoot(BinaryTreeNode<IPv4Address> replacement) {
			super.replaceThisRoot(replacement);
			if(!FREEZE_ROOT && replacement == null) {
				setKey(INIT_ROOT);
			}
		}
	
		@Override
		public IPv4TrieNode getUpperSubNode() {
			return (IPv4TrieNode) super.getUpperSubNode();
		}
	
		@Override
		public IPv4TrieNode getLowerSubNode() {
			return (IPv4TrieNode) super.getLowerSubNode();
		}
		
		@Override
		public IPv4TrieNode getParent() {
			return (IPv4TrieNode) super.getParent();
		}
		
		@Override
		protected IPv4TrieNode createNewImpl(IPv4Address addr) {
			return new IPv4TrieNode(addr);
		}
		
		@Override
		public IPv4TrieNode removeElementsContainedBy(IPv4Address addr) {
			return (IPv4TrieNode) super.removeElementsContainedBy(addr);
		}

		@Override
		public IPv4TrieNode elementsContainedBy(IPv4Address addr) {
			return (IPv4TrieNode) super.elementsContainedBy(addr);
		}

		@Override
		public IPv4TrieNode elementsContaining(IPv4Address addr) {
			return (IPv4TrieNode) super.elementsContaining(addr);
		}
		
		@Override
		public IPv4TrieNode getAddedNode(IPv4Address addr) {
			return (IPv4TrieNode) super.getAddedNode(addr);
		}

		@Override
		public IPv4TrieNode getNode(IPv4Address addr) {
			return (IPv4TrieNode) super.getNode(addr);
		}
		
//		@SuppressWarnings("unchecked")
//		@Override
//		public Iterator<IPv4TrieNode> nodeIterator(boolean forward, boolean addedNodesOnly) {
//			return (Iterator<IPv4TrieNode>) super.nodeIterator(forward, addedNodesOnly);
//		}
		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPv4TrieNode> nodeIterator(boolean forward) {
			return (Iterator<IPv4TrieNode>) super.nodeIterator(forward);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPv4TrieNode> allNodeIterator(boolean forward) {
			return (Iterator<IPv4TrieNode>) super.allNodeIterator(forward);
		}
		
//		@SuppressWarnings("unchecked")
//		@Override
//		public Iterator<IPv4TrieNode> blockSizeNodeIterator(boolean lowerSubNodeFirst, boolean addedNodesOnly) {
//			return (Iterator<IPv4TrieNode>) super.blockSizeNodeIterator(lowerSubNodeFirst, addedNodesOnly);
//		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPv4TrieNode> blockSizeNodeIterator(boolean lowerSubNodeFirst) {
			return (Iterator<IPv4TrieNode>) super.blockSizeNodeIterator(lowerSubNodeFirst);
		}
		
		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPv4TrieNode> blockSizeAllNodeIterator(boolean lowerSubNodeFirst) {
			return (Iterator<IPv4TrieNode>) super.blockSizeAllNodeIterator(lowerSubNodeFirst);
		}
		
		@SuppressWarnings("unchecked")
		@Override
		public <C> CachingIterator<IPv4TrieNode, IPv4Address, C> blockSizeCachingAllNodeIterator() {
			return (CachingIterator<IPv4TrieNode, IPv4Address, C>) super.blockSizeCachingAllNodeIterator();
		}

//		@SuppressWarnings("unchecked")
//		@Override
//		public <C> CachingIterator<IPv4TrieNode, IPv4Address, C> containingFirstIterator(boolean forwardSubNodeOrder, boolean addedNodesOnly) {
//			return (CachingIterator<IPv4TrieNode, IPv4Address, C>) super.containingFirstIterator(forwardSubNodeOrder, addedNodesOnly);
//		}
		@SuppressWarnings("unchecked")
		@Override
		public <C> CachingIterator<IPv4TrieNode, IPv4Address, C> containingFirstIterator(boolean forwardSubNodeOrder) {
			return (CachingIterator<IPv4TrieNode, IPv4Address, C>) super.containingFirstIterator(forwardSubNodeOrder);
		}
		
		@SuppressWarnings("unchecked")
		@Override
		public <C> CachingIterator<IPv4TrieNode, IPv4Address, C> containingFirstAllNodeIterator(boolean forwardSubNodeOrder) {
			return (CachingIterator<IPv4TrieNode, IPv4Address, C>) super.containingFirstAllNodeIterator(forwardSubNodeOrder);
		}
		
//		@SuppressWarnings("unchecked")
//		@Override
//		public Iterator<IPv4TrieNode> containedFirstIterator(boolean forwardSubNodeOrder, boolean addedNodesOnly) {
//			return (Iterator<IPv4TrieNode>) super.containedFirstIterator(forwardSubNodeOrder, addedNodesOnly);
//		}
		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPv4TrieNode> containedFirstIterator(boolean forwardSubNodeOrder) {
			return (Iterator<IPv4TrieNode>) super.containedFirstIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPv4TrieNode> containedFirstAllNodeIterator(boolean forwardSubNodeOrder) {
			return (Iterator<IPv4TrieNode>) super.containedFirstAllNodeIterator(forwardSubNodeOrder);
		}
		
		@SuppressWarnings("unchecked")
		@Override
		public Spliterator<IPv4TrieNode> nodeSpliterator(boolean forward) {
			return (Spliterator<IPv4TrieNode>) super.nodeSpliterator(forward);
		}
		
		@SuppressWarnings("unchecked")
		@Override
		public Spliterator<IPv4TrieNode> allNodeSpliterator(boolean forward) {
			return (Spliterator<IPv4TrieNode>) super.allNodeSpliterator(forward);
		}
		
		@Override
		public IPv4TrieNode previousAddedNode() {
			return (IPv4TrieNode) super.previousAddedNode();
		}
		
		@Override
		public IPv4TrieNode nextAddedNode() {
			return (IPv4TrieNode) super.nextAddedNode();
		}
		
		@Override
		public IPv4TrieNode nextNode() {
			return (IPv4TrieNode) super.nextNode();
		}
		
		@Override
		public IPv4TrieNode previousNode() {
			return (IPv4TrieNode) super.previousNode();
		}
		
		@Override
		public IPv4TrieNode lowerAddedNode(IPv4Address addr) {
			return (IPv4TrieNode) super.lowerAddedNode(addr);
		}

		@Override
		public IPv4TrieNode floorAddedNode(IPv4Address addr) {
			return (IPv4TrieNode) super.floorAddedNode(addr);
		}

		@Override
		public IPv4TrieNode higherAddedNode(IPv4Address addr) {
			return (IPv4TrieNode) super.higherAddedNode(addr);
		}

		@Override
		public IPv4TrieNode ceilingAddedNode(IPv4Address addr) {
			return (IPv4TrieNode) super.ceilingAddedNode(addr);
		}
		
		@Override
		public IPv4TrieNode firstNode() {
			return (IPv4TrieNode) super.firstNode();
		}

		@Override
		public IPv4TrieNode lastNode() {
			return (IPv4TrieNode) super.lastNode();
		}

		@Override
		public IPv4TrieNode cloneTree() {
			return (IPv4TrieNode) super.cloneTree();
		}

		@Override
		public IPv4TrieNode clone() {
			return (IPv4TrieNode) super.clone();
		}

		@Override
		public boolean equals(Object o) {
			return o instanceof IPv4TrieNode && super.equals(o);
		}
	}
	
	@Override
	public IPv4TrieNode removeElementsContainedBy(IPv4Address addr) {
		return (IPv4TrieNode) super.removeElementsContainedBy(addr);
	}

	@Override
	public IPv4TrieNode elementsContainedBy(IPv4Address addr) {
		return (IPv4TrieNode) super.elementsContainedBy(addr);
	}

	@Override
	public IPv4TrieNode elementsContaining(IPv4Address addr) {
		return (IPv4TrieNode) super.elementsContaining(addr);
	}
	
	@Override
	public IPv4TrieNode getAddedNode(IPv4Address addr) {
		return (IPv4TrieNode) super.getAddedNode(addr);
	}

	@Override
	public IPv4TrieNode getNode(IPv4Address addr) {
		return (IPv4TrieNode) super.getNode(addr);
	}
	
	@Override
	public IPv4TrieNode addNode(IPv4Address addr) {
		return (IPv4TrieNode) super.addNode(addr);
	}
	
	@Override
	public IPv4TrieNode addTrie(TrieNode<IPv4Address> trie) {
		return (IPv4TrieNode) super.addTrie(trie);
	}
	
//	@SuppressWarnings("unchecked")
//	@Override
//	public Iterator<IPv4TrieNode> nodeIterator(boolean forward, boolean addedNodesOnly) {
//		return (Iterator<IPv4TrieNode>) super.nodeIterator(forward, addedNodesOnly);
//	}
	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv4TrieNode> nodeIterator(boolean forward) {
		return (Iterator<IPv4TrieNode>) super.nodeIterator(forward);
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv4TrieNode> allNodeIterator(boolean forward) {
		return (Iterator<IPv4TrieNode>) super.allNodeIterator(forward);
	}

//	@SuppressWarnings("unchecked")
//	@Override
//	public Iterator<IPv4TrieNode> blockSizeNodeIterator(boolean lowerSubNodeFirst, boolean addedNodesOnly) {
//		return (Iterator<IPv4TrieNode>) super.blockSizeNodeIterator(lowerSubNodeFirst, addedNodesOnly);
//	}
	
	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv4TrieNode> blockSizeNodeIterator(boolean lowerSubNodeFirst) {
		return (Iterator<IPv4TrieNode>) super.blockSizeNodeIterator(lowerSubNodeFirst);
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv4TrieNode> blockSizeAllNodeIterator(boolean lowerSubNodeFirst) {
		return (Iterator<IPv4TrieNode>) super.blockSizeAllNodeIterator(lowerSubNodeFirst);
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public <C> CachingIterator<IPv4TrieNode, IPv4Address, C> blockSizeCachingAllNodeIterator() {
		return (CachingIterator<IPv4TrieNode, IPv4Address, C>) super.blockSizeCachingAllNodeIterator();
	}

//	@SuppressWarnings("unchecked")
//	@Override
//	public <C> CachingIterator<IPv4TrieNode, IPv4Address, C> containingFirstIterator(boolean forwardSubNodeOrder, boolean addedNodesOnly) {
//		return (CachingIterator<IPv4TrieNode, IPv4Address, C>) super.containingFirstIterator(forwardSubNodeOrder, addedNodesOnly);
//	}
	@SuppressWarnings("unchecked")
	@Override
	public <C> CachingIterator<IPv4TrieNode, IPv4Address, C> containingFirstIterator(boolean forwardSubNodeOrder) {
		return (CachingIterator<IPv4TrieNode, IPv4Address, C>) super.containingFirstIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public <C> CachingIterator<IPv4TrieNode, IPv4Address, C> containingFirstAllNodeIterator(boolean forwardSubNodeOrder) {
		return (CachingIterator<IPv4TrieNode, IPv4Address, C>) super.containingFirstAllNodeIterator(forwardSubNodeOrder);
	}
	
//	@SuppressWarnings("unchecked")
//	@Override
//	public Iterator<IPv4TrieNode> containedFirstIterator(boolean forwardSubNodeOrder, boolean addedNodesOnly) {
//		return (Iterator<IPv4TrieNode>) super.containedFirstIterator(forwardSubNodeOrder, addedNodesOnly);
//	}
	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv4TrieNode> containedFirstIterator(boolean forwardSubNodeOrder) {
		return (Iterator<IPv4TrieNode>) super.containedFirstIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv4TrieNode> containedFirstAllNodeIterator(boolean forwardSubNodeOrder) {
		return (Iterator<IPv4TrieNode>) super.containedFirstAllNodeIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Spliterator<IPv4TrieNode> nodeSpliterator(boolean forward) {
		return (Spliterator<IPv4TrieNode>) super.nodeSpliterator(forward);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Spliterator<IPv4TrieNode> allNodeSpliterator(boolean forward) {
		return (Spliterator<IPv4TrieNode>) super.allNodeSpliterator(forward);
	}

	@Override
	public IPv4TrieNode lowerAddedNode(IPv4Address addr) {
		return (IPv4TrieNode) super.lowerAddedNode(addr);
	}

	@Override
	public IPv4TrieNode floorAddedNode(IPv4Address addr) {
		return (IPv4TrieNode) super.floorAddedNode(addr);
	}

	@Override
	public IPv4TrieNode higherAddedNode(IPv4Address addr) {
		return (IPv4TrieNode) super.higherAddedNode(addr);
	}

	@Override
	public IPv4TrieNode ceilingAddedNode(IPv4Address addr) {
		return (IPv4TrieNode) super.ceilingAddedNode(addr);
	}
	
	@Override
	public IPv4TrieNode firstNode() {
		return (IPv4TrieNode) super.firstNode();
	}

	@Override
	public IPv4TrieNode lastNode() {
		return (IPv4TrieNode) super.lastNode();
	}

	@Override
	public IPv4AddressTrie clone() {
		return (IPv4AddressTrie) super.clone();
	}
	
	@Override
	public boolean equals(Object o) {
		return o instanceof IPv4AddressTrie && super.equals(o);
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public AssociativeAddressTrie<IPv4Address, List<IPv4AssociativeTrieNode<?>>> constructAddedNodesTree() {
		IPv4AddressAssociativeTrie<List<AssociativeTrieNode<IPv4Address, ?>>> trie = new IPv4AddressAssociativeTrie<>();
		contructAddedTree(trie);
		IPv4AddressAssociativeTrie<? extends List<AssociativeTrieNode<IPv4Address, ?>>> ret = trie;
		return (AssociativeAddressTrie<IPv4Address, List<IPv4AssociativeTrieNode<?>>>) ret;
	}
}
