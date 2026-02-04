/*
 * Copyright 2020-2022 Sean C Foley
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
import java.util.Spliterator;

import inet.ipaddr.MACAddressString;
import inet.ipaddr.format.util.AddedTree;
import inet.ipaddr.format.util.AddressTrie;
import inet.ipaddr.format.util.BinaryTreeNode;
import inet.ipaddr.format.util.BinaryTreeNode.CachingIterator;

/**
 * A MAC address trie.
 * 
 * See {@link AddressTrie}  for more details.
 * 
 * @author scfoley
 *
 */
public class MACAddressTrie extends AddressTrie<MACAddress> {

	private static final long serialVersionUID = 1L;

	static final MACAddress INIT_ROOT = new MACAddressString("*:*:*:*:*:*").getAddress();
	static final MACAddress INIT_ROOT_EXTENDED = new MACAddressString("*:*:*:*:*:*:*:*").getAddress();

	public MACAddressTrie() {
		super(new MACTrieNode());
	}

	protected MACAddressTrie(AddressBounds<MACAddress> bounds) {
		super(new MACTrieNode(), bounds);
	}

	protected MACAddressTrie(MACTrieNode root, AddressBounds<MACAddress> bounds) {
		super(root, bounds);
	}

	// if the very first address inserted into the trie is 64-bit, the trie is 64 bit
	@Override
	protected void adjustRoot(MACAddress addr) {
		if(isInitialRoot()) {
			if(addr.getSegmentCount() == MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT) {
			absoluteRoot().setExtendedRootKey();
			} else {
				absoluteRoot().setRootKey();
			}
		}
	}

	@Override
	protected MACTrieNode absoluteRoot() {
		return (MACTrieNode) super.absoluteRoot();
	}

	@Override
	protected MACAddressTrie createNew(AddressBounds<MACAddress> bounds) {
		return new MACAddressTrie(bounds);
	}

	@Override
	protected MACAddressTrie createSubTrie(AddressBounds<MACAddress> bounds) {
		return new MACAddressTrie(absoluteRoot(), bounds);
	}

	@Override
	public MACTrieNode getRoot() {
		return (MACTrieNode) super.getRoot();
	}

	public static class MACTrieNode extends TrieNode<MACAddress> {

		private static final long serialVersionUID = 1L;

		protected MACTrieNode(MACAddress addr) {
			super(addr);
		}

		public MACTrieNode() { // root node
			super(null);
		}

		@Override
		protected void replaceThisRoot(BinaryTreeNode<MACAddress> replacement) {
			super.replaceThisRoot(replacement);
			if(replacement == null) {
				setKey(null);
			}
		}

		void setExtendedRootKey() {
			setKey(INIT_ROOT_EXTENDED);
		}

		void setRootKey() {
			setKey(INIT_ROOT);
		}

		@Override
		public MACTrieNode getUpperSubNode() {
			return (MACTrieNode) super.getUpperSubNode();
		}

		@Override
		public MACTrieNode getLowerSubNode() {
			return (MACTrieNode) super.getLowerSubNode();
		}

		@Override
		public MACTrieNode getParent() {
			return (MACTrieNode) super.getParent();
		}

		@Override
		protected MACTrieNode createNewImpl(MACAddress addr) {
			return new MACTrieNode(addr);
		}

		@Override
		public MACTrieNode removeElementsContainedBy(MACAddress addr) {
			return (MACTrieNode) super.removeElementsContainedBy(addr);
		}

		@Override
		public MACTrieNode elementsContainedBy(MACAddress addr) {
			return (MACTrieNode) super.elementsContainedBy(addr);
		}

		@Override
		public MACTrieNode elementsContaining(MACAddress addr) {
			return (MACTrieNode) super.elementsContaining(addr);
		}

		@Override
		public MACTrieNode longestPrefixMatchNode(MACAddress addr) {
			return (MACTrieNode) super.longestPrefixMatchNode(addr);
		}

		@Override
		public MACTrieNode getAddedNode(MACAddress addr) {
			return (MACTrieNode) super.getAddedNode(addr);
		}

		@Override
		public MACTrieNode getNode(MACAddress addr) {
			return (MACTrieNode) super.getNode(addr);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<MACTrieNode> nodeIterator(boolean forward) {
			return (Iterator<MACTrieNode>) super.nodeIterator(forward);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<MACTrieNode> allNodeIterator(boolean forward) {
			return (Iterator<MACTrieNode>) super.allNodeIterator(forward);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<MACTrieNode> blockSizeNodeIterator(boolean lowerSubNodeFirst) {
			return (Iterator<MACTrieNode>) super.blockSizeNodeIterator(lowerSubNodeFirst);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<MACTrieNode> blockSizeAllNodeIterator(boolean lowerSubNodeFirst) {
			return (Iterator<MACTrieNode>) super.blockSizeAllNodeIterator(lowerSubNodeFirst);
		}

		@SuppressWarnings("unchecked")
		@Override
		public <C> CachingIterator<MACTrieNode, MACAddress, C> blockSizeCachingAllNodeIterator() {
			return (CachingIterator<MACTrieNode, MACAddress, C>) super.blockSizeCachingAllNodeIterator();
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<MACTrieNode> containingFirstIterator(boolean forwardSubNodeOrder) {
			return (Iterator<MACTrieNode>) super.containingFirstIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public <C> CachingIterator<MACTrieNode, MACAddress, C> containingFirstAllNodeIterator(boolean forwardSubNodeOrder) {
			return (CachingIterator<MACTrieNode, MACAddress, C>) super.containingFirstAllNodeIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<MACTrieNode> containedFirstIterator(boolean forwardSubNodeOrder) {
			return (Iterator<MACTrieNode>) super.containedFirstIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<MACTrieNode> containedFirstAllNodeIterator(boolean forwardSubNodeOrder) {
			return (Iterator<MACTrieNode>) super.containedFirstAllNodeIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Spliterator<MACTrieNode> nodeSpliterator(boolean forward) {
			return (Spliterator<MACTrieNode>) super.nodeSpliterator(forward);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Spliterator<MACTrieNode> allNodeSpliterator(boolean forward) {
			return (Spliterator<MACTrieNode>) super.allNodeSpliterator(forward);
		}

		@Override
		public MACTrieNode previousAddedNode() {
			return (MACTrieNode) super.previousAddedNode();
		}

		@Override
		public MACTrieNode nextAddedNode() {
			return (MACTrieNode) super.nextAddedNode();
		}

		@Override
		public MACTrieNode nextNode() {
			return (MACTrieNode) super.nextNode();
		}

		@Override
		public MACTrieNode previousNode() {
			return (MACTrieNode) super.previousNode();
		}

		@Override
		public MACTrieNode removeElementsIntersectedBy(MACAddress addr) { 
			return (MACTrieNode) super.removeElementsIntersectedBy(addr);
		}

		@Override
		public MACTrieNode containingFloorAddedNode(MACAddress addr) {
			return (MACTrieNode) super.containingFloorAddedNode(addr);
		}
		
		@Override
		public MACTrieNode containingLowerAddedNode(MACAddress addr) {
			return (MACTrieNode) super.containingLowerAddedNode(addr);
		}

		@Override
		public MACTrieNode containingCeilingAddedNode(MACAddress addr) {
			return (MACTrieNode) super.containingCeilingAddedNode(addr);
		}

		@Override
		public MACTrieNode containingHigherAddedNode(MACAddress addr) {
			return (MACTrieNode) super.containingHigherAddedNode(addr);
		}

		@Override
		public MACTrieNode lowerAddedNode(MACAddress addr) {
			return (MACTrieNode) super.lowerAddedNode(addr);
		}

		@Override
		public MACTrieNode floorAddedNode(MACAddress addr) {
			return (MACTrieNode) super.floorAddedNode(addr);
		}

		@Override
		public MACTrieNode higherAddedNode(MACAddress addr) {
			return (MACTrieNode) super.higherAddedNode(addr);
		}

		@Override
		public MACTrieNode ceilingAddedNode(MACAddress addr) {
			return (MACTrieNode) super.ceilingAddedNode(addr);
		}

		@Override
		public MACTrieNode firstNode() {
			return (MACTrieNode) super.firstNode();
		}

		@Override
		public MACTrieNode lastNode() {
			return (MACTrieNode) super.lastNode();
		}

		@Override
		public MACTrieNode firstAddedNode() {
			return (MACTrieNode) super.firstAddedNode();
		}

		@Override
		public MACTrieNode lastAddedNode() {
			return (MACTrieNode) super.lastAddedNode();
		}
		
		@Override
		protected MACAddressTrie createNewTree() {
			return new MACAddressTrie();
		}
		
		@Override
		public MACAddressTrie asNewTrie() {
			return (MACAddressTrie) super.asNewTrie();
		}

		@Override
		public MACTrieNode cloneTree() {
			return (MACTrieNode) super.cloneTree();
		}

		@Override
		public MACTrieNode clone() {
			return (MACTrieNode) super.clone();
		}

		@Override
		public boolean equals(Object o) {
			return o instanceof MACTrieNode && super.equals(o);
		}
	}

	@Override
	public MACTrieNode removeElementsContainedBy(MACAddress addr) {
		return (MACTrieNode) super.removeElementsContainedBy(addr);
	}

	@Override
	public MACTrieNode elementsContainedBy(MACAddress addr) {
		return (MACTrieNode) super.elementsContainedBy(addr);
	}

	@Override
	public MACTrieNode elementsContaining(MACAddress addr) {
		return (MACTrieNode) super.elementsContaining(addr);
	}

	@Override
	public MACTrieNode longestPrefixMatchNode(MACAddress addr) {
		return (MACTrieNode) super.longestPrefixMatchNode(addr);
	}

	@Override
	public MACTrieNode getAddedNode(MACAddress addr) {
		return (MACTrieNode) super.getAddedNode(addr);
	}

	@Override
	public MACTrieNode getNode(MACAddress addr) {
		return (MACTrieNode) super.getNode(addr);
	}

	@Override
	public MACTrieNode addNode(MACAddress addr) {
		return (MACTrieNode) super.addNode(addr);
	}

	@Override
	public MACTrieNode addTrie(TrieNode<MACAddress> trie) {
		return (MACTrieNode) super.addTrie(trie);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<MACTrieNode> nodeIterator(boolean forward) {
		return (Iterator<MACTrieNode>) super.nodeIterator(forward);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<MACTrieNode> allNodeIterator(boolean forward) {
		return (Iterator<MACTrieNode>) super.allNodeIterator(forward);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<MACTrieNode> blockSizeNodeIterator(boolean lowerSubNodeFirst) {
		return (Iterator<MACTrieNode>) super.blockSizeNodeIterator(lowerSubNodeFirst);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<MACTrieNode> blockSizeAllNodeIterator(boolean lowerSubNodeFirst) {
		return (Iterator<MACTrieNode>) super.blockSizeAllNodeIterator(lowerSubNodeFirst);
	}

	@SuppressWarnings("unchecked")
	@Override
	public <C> CachingIterator<MACTrieNode, MACAddress, C> blockSizeCachingAllNodeIterator() {
		return (CachingIterator<MACTrieNode, MACAddress, C>) super.blockSizeCachingAllNodeIterator();
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<MACTrieNode> containingFirstIterator(boolean forwardSubNodeOrder) {
		return (Iterator<MACTrieNode>) super.containingFirstIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public <C> CachingIterator<MACTrieNode, MACAddress, C> containingFirstAllNodeIterator(boolean forwardSubNodeOrder) {
		return (CachingIterator<MACTrieNode, MACAddress, C>) super.containingFirstAllNodeIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<MACTrieNode> containedFirstIterator(boolean forwardSubNodeOrder) {
		return (Iterator<MACTrieNode>) super.containedFirstIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<MACTrieNode> containedFirstAllNodeIterator(boolean forwardSubNodeOrder) {
		return (Iterator<MACTrieNode>) super.containedFirstAllNodeIterator(forwardSubNodeOrder);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Spliterator<MACTrieNode> nodeSpliterator(boolean forward) {
		return (Spliterator<MACTrieNode>) super.nodeSpliterator(forward);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Spliterator<MACTrieNode> allNodeSpliterator(boolean forward) {
		return (Spliterator<MACTrieNode>) super.allNodeSpliterator(forward);
	}

	@Override
	public MACTrieNode removeElementsIntersectedBy(MACAddress addr) { 
		return (MACTrieNode) super.removeElementsIntersectedBy(addr);
	}

	@Override
	public MACTrieNode addIfNoElementsContaining(MACAddress addr) { 
		return (MACTrieNode) super.addIfNoElementsContaining(addr);
	}

	@Override
	public MACTrieNode containingFloorAddedNode(MACAddress addr) {
		return (MACTrieNode) super.containingFloorAddedNode(addr);
	}
	
	@Override
	public MACTrieNode containingLowerAddedNode(MACAddress addr) {
		return (MACTrieNode) super.containingLowerAddedNode(addr);
	}

	@Override
	public MACTrieNode containingCeilingAddedNode(MACAddress addr) {
		return (MACTrieNode) super.containingCeilingAddedNode(addr);
	}

	@Override
	public MACTrieNode containingHigherAddedNode(MACAddress addr) {
		return (MACTrieNode) super.containingHigherAddedNode(addr);
	}

	@Override
	public MACTrieNode lowerAddedNode(MACAddress addr) {
		return (MACTrieNode) super.lowerAddedNode(addr);
	}

	@Override
	public MACTrieNode floorAddedNode(MACAddress addr) {
		return (MACTrieNode) super.floorAddedNode(addr);
	}

	@Override
	public MACTrieNode higherAddedNode(MACAddress addr) {
		return (MACTrieNode) super.higherAddedNode(addr);
	}

	@Override
	public MACTrieNode ceilingAddedNode(MACAddress addr) {
		return (MACTrieNode) super.ceilingAddedNode(addr);
	}

	@Override
	public MACTrieNode firstNode() {
		return (MACTrieNode) super.firstNode();
	}

	@Override
	public MACTrieNode lastNode() {
		return (MACTrieNode) super.lastNode();
	}

	@Override
	public MACTrieNode firstAddedNode() {
		return (MACTrieNode) super.firstAddedNode();
	}

	@Override
	public MACTrieNode lastAddedNode() {
		return (MACTrieNode) super.lastAddedNode();
	}

	@Override
	public boolean equals(Object o) {
		return o instanceof MACAddressTrie && super.equals(o);
	}

	@Override
	public MACAddressTrie clone() {
		return (MACAddressTrie) super.clone();
	}

	@Override
	public AddedTree<MACAddress> constructAddedNodesTree() {
		MACAddressAssociativeTrie<SubNodesMappingBasic<MACAddress>> trie = new MACAddressAssociativeTrie<SubNodesMappingBasic<MACAddress>>();
		contructAddedTree(trie);
		return new AddedTree<MACAddress>(trie);
	}

	@Override
	public String toAddedNodesTreeString() {
		MACAddressAssociativeTrie<SubNodesMappingBasic<MACAddress>> trie = new MACAddressAssociativeTrie<SubNodesMappingBasic<MACAddress>>();
		contructAddedTree(trie);
		return toAddedNodesTreeString(trie);
	}
}
