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
import inet.ipaddr.IPAddressString;
import inet.ipaddr.format.util.BinaryTreeNode.CachingIterator;
import inet.ipaddr.format.validate.ChangeTracker;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv6.IPv6Address;


/**
 * IPAddressTrie is a polymorphic address trie that can use have IPv4 or IPv6 addresses as keys, but not both at the same time.
 * <p>
 * This trie will accept IPv4 keys if the first added node has an IPv4 address key, and then afterwards additional added nodes must have IPv4 address keys.
 * Similarly, this trie will accept IPv6 keys if the first added node has an IPv6 address key, and then afterwards additional added nodes must have IPv6 address keys.
 * If a trie is emptied of all added nodes, then it can accept a new node with a key that is either IPv4 or IPv6 again.
 * <p>
 * If you attempt to add a node with an IPv4 key to a trie with IPv6 keys, or vice versa, then IllegalArgumentException will be thrown.
 * <p>
 * See {@link AddressTrie} for more details on tries.
 * 
 * @author scfoley
 *
 */
public class IPAddressTrie extends AddressTrie<IPAddress> {

	private static final long serialVersionUID = 1L;
	
	static final IPv6Address IPV6_ROOT = new IPAddressString("::/0").getAddress().toIPv6();
	static final IPv4Address IPV4_ROOT = new IPAddressString("0.0.0.0/0").getAddress().toIPv4();

	public IPAddressTrie() {
		super(new IPAddressTrieNode());
	}
	
	protected IPAddressTrie(ChangeTracker changeTracker) {
		super(new IPAddressTrieNode(), changeTracker);
	}
	
	protected IPAddressTrie(IPAddressTrieNode root, AddressBounds<IPAddress> bounds) {
		super(root, bounds);
	}
	
	protected IPAddressTrie(AddressBounds<IPAddress> bounds) {
		super(new IPAddressTrieNode(), bounds);
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
	protected IPAddressTrie createNew(AddressBounds<IPAddress> bounds) {
		return new IPAddressTrie(bounds);
	}

	@Override
	protected IPAddressTrie createSubTrie(AddressBounds<IPAddress> bounds) {
		return new IPAddressTrie(absoluteRoot(), bounds);
	}

	@Override
	protected IPAddressTrieNode absoluteRoot() {
		return (IPAddressTrieNode) super.absoluteRoot();
	}

	@Override
	public AddedTreeBase<IPAddress, ? extends SubNodesMapping<IPAddress, ? extends SubNodesMapping<IPAddress, ?>>> constructAddedNodesTree() {
		IPAddressAssociativeTrie<SubNodesMappingBasic<IPAddress>> trie = new IPAddressAssociativeTrie<SubNodesMappingBasic<IPAddress>>();
		contructAddedTree(trie);
		return new AddedTree<IPAddress>(trie);
	}

	@Override
	public String toAddedNodesTreeString() {
		IPAddressAssociativeTrie<SubNodesMappingBasic<IPAddress>> trie = new IPAddressAssociativeTrie<SubNodesMappingBasic<IPAddress>>();
		contructAddedTree(trie);
		return toAddedNodesTreeString(trie);
	}

	public static class IPAddressTrieNode extends TrieNode<IPAddress> {

		private static final long serialVersionUID = 1L;

		protected IPAddressTrieNode(IPAddress addr) {
			super(addr);
		}

		public IPAddressTrieNode() {
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
		protected IPAddressTrieNode createNewImpl(IPAddress newAddr) {
			return new IPAddressTrieNode(newAddr);
		}

		@Override
		protected IPAddressTrie createNewTree() {
			return new IPAddressTrie();
		}
		
		@Override
		public IPAddressTrieNode getUpperSubNode() {
			return (IPAddressTrieNode) super.getUpperSubNode();
		}

		@Override
		public IPAddressTrieNode getLowerSubNode() {
			return (IPAddressTrieNode) super.getLowerSubNode();
		}

		@Override
		public IPAddressTrieNode getParent() {
			return (IPAddressTrieNode) super.getParent();
		}

		@Override
		public IPAddressTrieNode removeElementsContainedBy(IPAddress addr) {
			return (IPAddressTrieNode) super.removeElementsContainedBy(addr);
		}

		@Override
		public IPAddressTrieNode elementsContainedBy(IPAddress addr) {
			return (IPAddressTrieNode) super.elementsContainedBy(addr);
		}

		@Override
		public IPAddressTrieNode elementsContaining(IPAddress addr) {
			return (IPAddressTrieNode) super.elementsContaining(addr);
		}

		@Override
		public IPAddressTrieNode longestPrefixMatchNode(IPAddress addr) {
			return (IPAddressTrieNode) super.longestPrefixMatchNode(addr);
		}

		@Override
		public IPAddressTrieNode getAddedNode(IPAddress addr) {
			return (IPAddressTrieNode) super.getAddedNode(addr);
		}

		@Override
		public IPAddressTrieNode getNode(IPAddress addr) {
			return (IPAddressTrieNode) super.getNode(addr);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPAddressTrieNode> nodeIterator(boolean forward) {
			return (Iterator<IPAddressTrieNode>) super.nodeIterator(forward);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPAddressTrieNode> allNodeIterator(boolean forward) {
			return (Iterator<IPAddressTrieNode>) super.allNodeIterator(forward);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPAddressTrieNode> blockSizeNodeIterator(boolean lowerSubNodeFirst) {
			return (Iterator<IPAddressTrieNode>) super.blockSizeNodeIterator(lowerSubNodeFirst);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPAddressTrieNode> blockSizeAllNodeIterator(boolean lowerSubNodeFirst) {
			return (Iterator<IPAddressTrieNode>) super.blockSizeAllNodeIterator(lowerSubNodeFirst);
		}

		@SuppressWarnings("unchecked")
		@Override
		public <C> CachingIterator<IPAddressTrieNode, IPAddress, C> blockSizeCachingAllNodeIterator() {
			return (CachingIterator<IPAddressTrieNode, IPAddress, C>) super.blockSizeCachingAllNodeIterator();
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPAddressTrieNode> containingFirstIterator(boolean forwardSubNodeOrder) {
			return (Iterator<IPAddressTrieNode>) super.containingFirstIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public <C> CachingIterator<IPAddressTrieNode, IPAddress, C> containingFirstAllNodeIterator(boolean forwardSubNodeOrder) {
			return (CachingIterator<IPAddressTrieNode, IPAddress, C>) super.containingFirstAllNodeIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPAddressTrieNode> containedFirstIterator(boolean forwardSubNodeOrder) {
			return (Iterator<IPAddressTrieNode>) super.containedFirstIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<IPAddressTrieNode> containedFirstAllNodeIterator(boolean forwardSubNodeOrder) {
			return (Iterator<IPAddressTrieNode>) super.containedFirstAllNodeIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Spliterator<IPAddressTrieNode> nodeSpliterator(boolean forward) {
			return (Spliterator<IPAddressTrieNode>) super.nodeSpliterator(forward);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Spliterator<IPAddressTrieNode> allNodeSpliterator(boolean forward) {
			return (Spliterator<IPAddressTrieNode>) super.allNodeSpliterator(forward);
		}

		@Override
		public IPAddressTrieNode previousAddedNode() {
			return (IPAddressTrieNode) super.previousAddedNode();
		}

		@Override
		public IPAddressTrieNode nextAddedNode() {
			return (IPAddressTrieNode) super.nextAddedNode();
		}

		@Override
		public IPAddressTrieNode nextNode() {
			return (IPAddressTrieNode) super.nextNode();
		}

		@Override
		public IPAddressTrieNode previousNode() {
			return (IPAddressTrieNode) super.previousNode();
		}

		@Override
		public IPAddressTrieNode lowerAddedNode(IPAddress addr) {
			return (IPAddressTrieNode) super.lowerAddedNode(addr);
		}

		@Override
		public IPAddressTrieNode floorAddedNode(IPAddress addr) {
			return (IPAddressTrieNode) super.floorAddedNode(addr);
		}

		@Override
		public IPAddressTrieNode higherAddedNode(IPAddress addr) {
			return (IPAddressTrieNode) super.higherAddedNode(addr);
		}

		@Override
		public IPAddressTrieNode ceilingAddedNode(IPAddress addr) {
			return (IPAddressTrieNode) super.ceilingAddedNode(addr);
		}

		@Override
		public IPAddressTrieNode firstNode() {
			return (IPAddressTrieNode) super.firstNode();
		}

		@Override
		public IPAddressTrieNode lastNode() {
			return (IPAddressTrieNode) super.lastNode();
		}

		@Override
		public IPAddressTrieNode firstAddedNode() {
			return (IPAddressTrieNode) super.firstAddedNode();
		}

		@Override
		public IPAddressTrieNode lastAddedNode() {
			return (IPAddressTrieNode) super.lastAddedNode();
		}

		@Override
		public IPAddressTrie asNewTrie() {
			return (IPAddressTrie) super.asNewTrie();
		}

		@Override
		public IPAddressTrieNode cloneTree() {
			return (IPAddressTrieNode) super.cloneTree();
		}

		@Override
		public IPAddressTrieNode clone() {
			return (IPAddressTrieNode) super.clone();
		}

		@Override
		public boolean equals(Object o) {
			return o instanceof IPAddressTrieNode && super.equals(o);
		}
	}
	
	@Override
	public IPAddressTrieNode removeElementsContainedBy(IPAddress addr) {
		return (IPAddressTrieNode) super.removeElementsContainedBy(addr);
	}

	@Override
	public IPAddressTrieNode elementsContainedBy(IPAddress addr) {
		return (IPAddressTrieNode) super.elementsContainedBy(addr);
	}
	
	@Override
	public IPAddressTrieNode removeElementsIntersectedBy(IPAddress addr) { 
		return (IPAddressTrieNode) super.removeElementsIntersectedBy(addr);
	}

	@Override
	public IPAddressTrieNode addIfNoElementsContaining(IPAddress addr) { 
		return (IPAddressTrieNode) super.addIfNoElementsContaining(addr);
	}
	
	@Override
	protected IPAddressTrieNode addIfNoElementsContaining(IPAddress addr, boolean checkBlockOrAddress) {
		return (IPAddressTrieNode) super.addIfNoElementsContaining(addr, checkBlockOrAddress);
	}

	@Override
	public IPAddressTrieNode elementsContaining(IPAddress addr) {
		return (IPAddressTrieNode) super.elementsContaining(addr);
	}

	@Override
	public IPAddressTrieNode longestPrefixMatchNode(IPAddress addr) {
		return (IPAddressTrieNode) super.longestPrefixMatchNode(addr);
	}

	@Override
	public IPAddressTrieNode getAddedNode(IPAddress addr) {
		return (IPAddressTrieNode) super.getAddedNode(addr);
	}

	@Override
	public IPAddressTrieNode getNode(IPAddress addr) {
		return (IPAddressTrieNode) super.getNode(addr);
	}

	@Override
	public IPAddressTrieNode addNode(IPAddress addr) {
		return (IPAddressTrieNode) super.addNode(addr);
	}

	@Override
	public IPAddressTrieNode addTrie(TrieNode<IPAddress> trie) {
		return (IPAddressTrieNode) super.addTrie(trie);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPAddressTrieNode> nodeIterator(boolean forward) {
		return (Iterator<IPAddressTrieNode>) super.nodeIterator(forward);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPAddressTrieNode> allNodeIterator(boolean forward) {
		return (Iterator<IPAddressTrieNode>) super.allNodeIterator(forward);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPAddressTrieNode> blockSizeNodeIterator(boolean lowerSubNodeFirst) {
		return (Iterator<IPAddressTrieNode>) super.blockSizeNodeIterator(lowerSubNodeFirst);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPAddressTrieNode> blockSizeAllNodeIterator(boolean lowerSubNodeFirst) {
		return (Iterator<IPAddressTrieNode>) super.blockSizeAllNodeIterator(lowerSubNodeFirst);
	}

	@SuppressWarnings("unchecked")
	@Override
	public <C> CachingIterator<IPAddressTrieNode, IPAddress, C> blockSizeCachingAllNodeIterator() {
		return (CachingIterator<IPAddressTrieNode, IPAddress, C>) super.blockSizeCachingAllNodeIterator();
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPAddressTrieNode> containingFirstIterator(boolean forwardSubNodeOrder) {
		return (Iterator<IPAddressTrieNode>) super.containingFirstIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public <C> CachingIterator<IPAddressTrieNode, IPAddress, C> containingFirstAllNodeIterator(boolean forwardSubNodeOrder) {
		return (CachingIterator<IPAddressTrieNode, IPAddress, C>) super.containingFirstAllNodeIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPAddressTrieNode> containedFirstIterator(boolean forwardSubNodeOrder) {
		return (Iterator<IPAddressTrieNode>) super.containedFirstIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPAddressTrieNode> containedFirstAllNodeIterator(boolean forwardSubNodeOrder) {
		return (Iterator<IPAddressTrieNode>) super.containedFirstAllNodeIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Spliterator<IPAddressTrieNode> nodeSpliterator(boolean forward) {
		return (Spliterator<IPAddressTrieNode>) super.nodeSpliterator(forward);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Spliterator<IPAddressTrieNode> allNodeSpliterator(boolean forward) {
		return (Spliterator<IPAddressTrieNode>) super.allNodeSpliterator(forward);
	}

	@Override
	public IPAddressTrieNode lowerAddedNode(IPAddress addr) {
		return (IPAddressTrieNode) super.lowerAddedNode(addr);
	}

	@Override
	public IPAddressTrieNode floorAddedNode(IPAddress addr) {
		return (IPAddressTrieNode) super.floorAddedNode(addr);
	}

	@Override
	public IPAddressTrieNode higherAddedNode(IPAddress addr) {
		return (IPAddressTrieNode) super.higherAddedNode(addr);
	}

	@Override
	public IPAddressTrieNode ceilingAddedNode(IPAddress addr) {
		return (IPAddressTrieNode) super.ceilingAddedNode(addr);
	}

	@Override
	public IPAddressTrieNode containingFloorAddedNode(IPAddress addr) {
		return (IPAddressTrieNode) super.containingFloorAddedNode(addr);
	}
	
	@Override
	protected IPAddressTrieNode containingFloorAddedNodeNoCheck(IPAddress addr) {
		return (IPAddressTrieNode) super.containingFloorAddedNodeNoCheck(addr);
	}
	
	@Override
	public IPAddressTrieNode containingLowerAddedNode(IPAddress addr) {
		return (IPAddressTrieNode) super.containingLowerAddedNode(addr);
	}
	
	@Override
	protected IPAddressTrieNode containingLowerAddedNodeNoCheck(IPAddress addr) {
		return (IPAddressTrieNode) super.containingLowerAddedNodeNoCheck(addr);
	}

	@Override
	public IPAddressTrieNode containingCeilingAddedNode(IPAddress addr) {
		return (IPAddressTrieNode) super.containingCeilingAddedNode(addr);
	}

	@Override
	protected IPAddressTrieNode containingCeilingAddedNodeNoCheck(IPAddress addr) {
		return (IPAddressTrieNode) super.containingCeilingAddedNodeNoCheck(addr);
	}
	
	@Override
	public IPAddressTrieNode containingHigherAddedNode(IPAddress addr) {
		return (IPAddressTrieNode) super.containingHigherAddedNode(addr);
	}
	
	@Override
	protected IPAddressTrieNode containingHigherAddedNodeNoCheck(IPAddress addr) {
		return (IPAddressTrieNode) super.containingHigherAddedNodeNoCheck(addr);
	}

	@Override
	public IPAddressTrieNode firstNode() {
		return (IPAddressTrieNode) super.firstNode();
	}

	@Override
	public IPAddressTrieNode lastNode() {
		return (IPAddressTrieNode) super.lastNode();
	}

	@Override
	public IPAddressTrieNode firstAddedNode() {
		return (IPAddressTrieNode) super.firstAddedNode();
	}

	@Override
	public IPAddressTrieNode lastAddedNode() {
		return (IPAddressTrieNode) super.lastAddedNode();
	}

	@Override
	public boolean equals(Object o) {
		return o instanceof IPAddressTrie && super.equals(o);
	}

	@Override
	protected IPAddressTrie clone(ChangeTracker tracker) {
		return (IPAddressTrie) super.clone(tracker);
	}
	
	@Override
	public IPAddressTrie clone() {
		return (IPAddressTrie) super.clone();
	}
}
