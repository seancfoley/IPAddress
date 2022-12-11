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
