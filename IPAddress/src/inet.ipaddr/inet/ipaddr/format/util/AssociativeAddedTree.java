/*
 * Copyright 2022-2024 Sean C Foley
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

import java.util.List;

import inet.ipaddr.Address;
import inet.ipaddr.format.util.AssociativeAddressTrie.AssociativeTrieNode;
import inet.ipaddr.format.util.AssociativeAddressTrie.SubNodesMappingAssociative;

/** 
 * AssociativeAddedTree is similar to AddedTree but originates from an AssociativeTrie.
 * The nodes of this tree have the same values as the corresponding nodes in the original trie.
 */
public class AssociativeAddedTree<E extends Address, V> extends AddedTreeBase<E, SubNodesMappingAssociative<E,V>> {

	public AssociativeAddedTree(AssociativeAddressTrie<E, SubNodesMappingAssociative<E,V>> wrapped) {
		super(wrapped);
	}

	/** 
	 * AssociativeAddedTreeNode represents a node in an AssociativeAddedTree.
	 */
	public static class AssociativeAddedTreeNode<E extends Address, V> extends AddedTreeNodeBase<E,SubNodesMappingAssociative<E,V>> {

		public AssociativeAddedTreeNode(AssociativeTrieNode<E, SubNodesMappingAssociative<E, V>> node) {
			super(node);
		}

		@Override
		public AssociativeAddedTreeNode<E,V>[] getSubNodes() {
			SubNodesMappingAssociative<E, V> value = node.getValue();
			if(value == null) {
				return null;
			}
			List<AssociativeTrieNode<E, SubNodesMappingAssociative<E, V>>> subNodes = value.subNodes;  
			if(subNodes == null || subNodes.size() == 0) {
				return null;
			}
			@SuppressWarnings("unchecked")
			AssociativeAddedTreeNode<E,V>[] nodes = (AssociativeAddedTreeNode<E,V>[]) new AssociativeAddedTreeNode[subNodes.size()];
			for(int i = 0; i < nodes.length; i++) {
				nodes[i] = new AssociativeAddedTreeNode<E,V>(subNodes.get(i));
			}
			return nodes;
		}
	}
	
	/**
	 * Returns the root of this tree, which corresponds to the root of the originating trie.
	 */
	@Override
	public AssociativeAddedTreeNode<E,V> getRoot()  {
		return new AssociativeAddedTreeNode<E, V>(wrapped.getRoot());
	}
}
