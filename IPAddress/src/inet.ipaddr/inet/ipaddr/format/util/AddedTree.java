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

import java.util.List;

import inet.ipaddr.Address;
import inet.ipaddr.format.util.AddressTrie.SubNodesMappingBasic;
import inet.ipaddr.format.util.AssociativeAddressTrie.AssociativeTrieNode;

/** 
 * AddedTree is an alternative non-binary tree data structure originating from a binary trie
 * with the possible exception of the root, which matches the root node of the original.
 * The root may or may not be an added node from the original trie.
 * This tree is also read-only and is generated from the originating trie,
 * but does not change in concert with changes to the original trie.
 */
public class AddedTree<E extends Address> extends AddedTreeBase<E, SubNodesMappingBasic<E>> {

	public AddedTree(AssociativeAddressTrie<E, SubNodesMappingBasic<E>> wrapped) {
		super(wrapped);
	}

	/** 
	 * AddedTreeNode represents a node in an AddedTree.
	 */
	public static class AddedTreeNode<E extends Address> extends AddedTreeNodeBase<E,SubNodesMappingBasic<E>> {

		public AddedTreeNode(AssociativeTrieNode<E, SubNodesMappingBasic<E>> node) {
			super(node);
		}
		
		@Override
		public AddedTreeNode<E>[] getSubNodes() {
			SubNodesMappingBasic<E> value = node.getValue();
			if(value == null) {
				return null;
			}
			List<AssociativeTrieNode<E, SubNodesMappingBasic<E>>> subNodes = value.subNodes;  
			if(subNodes == null || subNodes.size() == 0) {
				return null;
			}
			@SuppressWarnings("unchecked")
			AddedTreeNode<E>[] nodes = (AddedTreeNode<E>[]) new AddedTreeNode[subNodes.size()];
			for(int i = 0; i < nodes.length; i++) {
				nodes[i] = new AddedTreeNode<E>(subNodes.get(i));
			}
			return nodes;
		}
	}
	
	/**
	 * Returns the root of this tree, which corresponds to the root of the originating trie.
	 */
	@Override
	public AddedTreeNode<E> getRoot()  {
		return new AddedTreeNode<E>(wrapped.getRoot());
	}
}
