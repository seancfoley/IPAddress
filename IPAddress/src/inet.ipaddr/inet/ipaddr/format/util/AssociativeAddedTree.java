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
