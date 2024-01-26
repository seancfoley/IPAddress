/*
 * Copyright 2022 Sean C Foley
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

import inet.ipaddr.Address;
import inet.ipaddr.format.util.AddressTrie.SubNodesMapping;
import inet.ipaddr.format.util.AddressTrie.TrieNode;
import inet.ipaddr.format.util.AssociativeAddressTrie.AssociativeTrieNode;

abstract class AddedTreeBase<E extends Address, N extends SubNodesMapping<E, N>> {

	AssociativeAddressTrie<E, N> wrapped;
	
	AddedTreeBase(AssociativeAddressTrie<E, N> wrapped) {
		this.wrapped = wrapped;
	}
	
	static abstract class AddedTreeNodeBase<E extends Address, N extends SubNodesMapping<E, N>> {
		
		AssociativeTrieNode<E, N> node;

		public AddedTreeNodeBase(AssociativeTrieNode<E, N> node) {
			this.node = node;
		}
		
		/**
		 * Returns the sub-nodes of this node, which are not the same as the 0, 1 or 2 direct sub-nodes of the originating binary trie.
		 * Instead, these are all the direct or indirect added sub-nodes of the node in the originating trie.
		 * If you can traverse from this node to another node in the originating trie, using a sequence of sub-nodes, 
		 * without any intervening sub-node being an added node, then that other node will appear as a sub-node here.
		 * If there are no sub-nodes, then this method returns null.
		 */
		abstract AddedTreeNodeBase<E,N>[] getSubNodes();
		
		/**
		 * getKey returns the key of this node, which is the same as the key of the corresponding node in the originating trie.
		 * @return
		 */
		public E getKey() {
			return node.getKey();
		}
		
		/**
		 * Returns whether the node was an added node in the original trie.  
		 * This returns true for all nodes except possibly the root, since only added nodes are added to this tree, apart from the root.
		 */
		public boolean isAdded() {
			return node.isAdded();
		}
		
		/**
		 * Returns a visual representation of this node including the key.
		 * If this is the root, it will have an open circle if the root is not an added node.
		 * Otherwise, the node will have a closed circle.
		 */
		@Override
		public String toString() {
			return TrieNode.toNodeString(new StringBuilder(50), node.isAdded(), getKey(), null).toString();
		}
		
		/**
		 * toTreeString returns a visual representation of the sub-tree originating from this node, with one node per line.
		 * @return
		 */
		public String toTreeString() {
			return AddressTrie.toAddedNodesTreeString(node);
		}
	}
	
	/**
	 * Returns the root of this tree, which corresponds to the root of the originating trie.
	 */
	public abstract AddedTreeNodeBase<E,N> getRoot();

	/**
	 * Returns a string representation of the tree, which is the same as the string obtained from
	 * the AddedNodesTreeString method of the originating trie.
	 */
	@Override
	public String toString() {
		return AddressTrie.toAddedNodesTreeString(wrapped.getRoot());
	}
}
