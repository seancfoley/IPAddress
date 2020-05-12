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
package inet.ipaddr.format.util;

import java.io.Serializable;
import java.util.Iterator;
import java.util.Spliterator;
import java.util.Spliterators;

import inet.ipaddr.format.util.BinaryTreeNode.CachingIterator;

/**
 * TreeOps is an interface to the operations supported by both trees and tree nodes: traversals, cloning, and serialization.
 * <p>
 * The traversal orders are demonstrated by the following code:
 * <pre><code>
static class Node extends BinaryTreeNode&lt;Integer&gt; {

	private static final long serialVersionUID = 1L;

	Node(int i) {
		super(i);
		setAdded(true);
	}
	
	protected void setUpper(int upper) {
		super.setUpper(new Node(upper));
	}

	protected void setLower(int lower) {
		super.setLower(new Node(lower));
	}
	
	&#64;Override
	public Node getUpperSubNode() {
		return (Node) super.getUpperSubNode();
	}

	&#64;Override
	public Node getLowerSubNode() {
		return (Node) super.getLowerSubNode();
	}
}

static void trieOrders() {
	Node root = new Node(1);
	root.setLower(2);
	root.setUpper(3);
	root.getLowerSubNode().setLower(4);
	root.getLowerSubNode().setUpper(5);
	root.getUpperSubNode().setLower(6);
	root.getUpperSubNode().setUpper(7);
	root.getLowerSubNode().getLowerSubNode().setLower(8);
	root.getLowerSubNode().getLowerSubNode().setUpper(9);
	root.getLowerSubNode().getUpperSubNode().setLower(10);
	root.getLowerSubNode().getUpperSubNode().setUpper(11);
	root.getUpperSubNode().getLowerSubNode().setLower(12);
	root.getUpperSubNode().getLowerSubNode().setUpper(13);
	root.getUpperSubNode().getUpperSubNode().setLower(14);
	root.getUpperSubNode().getUpperSubNode().setUpper(15);
	
	PrintStream out = System.out;
	out.println(root.toTreeString(true, false));
	
	out.println("natural tree order:");
	print(root.nodeIterator(true));
	out.println("reverse natural tree order:");
	print(root.nodeIterator(false));
	out.println("pre-order traversal, lower node first:");
	print(root.containingFirstIterator(true));
	out.println("pre-order traversal, upper node first:");
	print(root.containingFirstIterator(false));
	out.println("post-order traversal, lower node first:");
	print(root.containedFirstIterator(true));
	out.println("post-order traversal, upper node first:");
	print(root.containedFirstIterator(false));
}

static void print(Iterator&lt;? extends BinaryTreeNode&lt;Integer&gt;&gt; iterator) {
	PrintStream out = System.out;
	while(iterator.hasNext()) {
		Integer i = iterator.next().getKey();
		out.print(i);
		out.print(' ');
	}
	out.println();
	out.println();
}
</code></pre>
The code gives the following output (the tree is printed with lower nodes before upper nodes):
<pre>
● 1
├─● 2
│ ├─● 4
│ │ ├─● 8
│ │ └─● 9
│ └─● 5
│   ├─● 10
│   └─● 11
└─● 3
  ├─● 6
  │ ├─● 12
  │ └─● 13
  └─● 7
    ├─● 14
    └─● 15

natural tree order:
8 4 9 2 10 5 11 1 12 6 13 3 14 7 15 

reverse natural tree order:
15 7 14 3 13 6 12 1 11 5 10 2 9 4 8 

pre-order traversal, lower node first:
1 2 4 8 9 5 10 11 3 6 12 13 7 14 15 

pre-order traversal, upper node first:
1 3 7 15 14 6 13 12 2 5 11 10 4 9 8 

post-order traversal, lower node first:
8 9 4 10 11 5 2 12 13 6 14 15 7 3 1 

post-order traversal, upper node first:
15 14 7 13 12 6 3 11 10 5 9 8 4 2 1 
</pre>
 * @author scfoley
 *
 * @param <E>
 */
public interface TreeOps<E> extends Iterable<E>, Serializable, Cloneable {
	/**
	 * Traverses the added node keys in natural tree order.
	 * <p>
	 * See {@link TreeOps} for more details on the ordering.
	 * 
	 * @return
	 */
	@Override
	Iterator<E> iterator();

	/**
	 * Traverses the added node keys in reverse natural tree order.
	 * <p>
	 * See {@link TreeOps} for more details on the ordering.
	 * @return
	 */
	Iterator<E> descendingIterator();

	/**
	 * Creates a {@link java.util.Spliterator} over the keys of the added nodes in natural tree order.
	 * <p>
	 * See {@link TreeOps} for more details on the ordering.
	 * 
	 * @return
	 */
	@Override
	default Spliterator<E> spliterator() {
		return Spliterators.spliteratorUnknownSize(iterator(), 0);
	}

	/**
	 * Creates a {@link java.util.Spliterator} over the keys of the added nodes in descending natural tree order.
	 * <p>
	 * See {@link TreeOps} for more details on the ordering.
	 * 
	 * @return
	 */
	default Spliterator<E> descendingSpliterator() {
		return Spliterators.spliteratorUnknownSize(descendingIterator(), 0);
	}

	/**
	 * Iterates through the added nodes in forward or reverse natural tree order.
	 * <p>
	 * This iterator supports the {@link java.util.Iterator#remove()} operation.
	 * <p>
	 * See {@link TreeOps} for more details on the ordering.
	 * <p>
	 * 
	 * @param forward if true, goes in ascending order, otherwise descending
	 * @return
	 */
	Iterator<? extends BinaryTreeNode<E>> nodeIterator(boolean forward);

	/**
	 * Iterates through the nodes (not just the added nodes) in forward or reverse tree order.
	 * <p>
	 * <p>
	 * See {@link TreeOps} for more details on the ordering.
	 * This iterator supports the {@link java.util.Iterator#remove()} operation.
	 * <p>
	 * 
	 * @param forward if true, goes in ascending order, otherwise descending
	 * @return
	 */
	Iterator<? extends BinaryTreeNode<E>> allNodeIterator(boolean forward);

	/**
	 * Returns an iterator that does a pre-order binary tree traversal of the added nodes.
	 * All added nodes will be visited before their added sub-nodes.
	 * For an address trie this means added containing subnet blocks will be visited before their added contained addresses and subnet blocks.
	 * <p>
	 * This iterator supports the {@link java.util.Iterator#remove()} operation.
	 * <p>
	 * Once a given node is visited, the iterator allows you to cache an object corresponding to the 
	 * lower or upper sub-node that can be retrieved when you later visit that sub-node.
	 * <p>
	 * Objects are cached only with nodes to be visited.  
	 * So for this iterator that means an object will be cached with the first added lower or upper sub-node,
	 * the next lower or upper sub-node to be visited, 
	 * which is not necessarily the direct lower or upper sub-node of a given node. 
	 * <p>
	 * The caching allows you to provide iteration context from a parent to its sub-nodes when iterating.
	 * The caching and retrieval is done in constant-time and linear space (proportional to tree size).	 
	 * <p>
	 * See {@link TreeOps} for more details on the ordering.
	 * 
	 * @param forwardSubNodeOrder if true, a left sub-node will be visited before the right sub-node of the same parent node.
	 * @return
	 */
	<C> CachingIterator<? extends BinaryTreeNode<E>, E, C> containingFirstIterator(boolean forwardSubNodeOrder);	

	/**
	 * Returns an iterator that does a pre-order binary tree traversal.
	 * All nodes will be visited before their sub-nodes.
	 * For an address trie this means containing subnet blocks will be visited before their contained addresses and subnet blocks.
	 * <p>
	 * This iterator supports the {@link java.util.Iterator#remove()} operation.
	 * <p>
	 * Once a given node is visited, the iterator allows you to cache an object corresponding to the 
	 * lower or upper sub-node that can be retrieved when you later visit that sub-node.
	 * That allows you to provide iteration context from a parent to its sub-nodes when iterating.
	 * The caching and retrieval is done in constant-time and linear space (proportional to tree size).	 
	 * <p>
	 * Here is an example showing usage of the caching.  Consider this recursive code doing a pre-order traversal:
	 *<pre><code>
IPv6AddressTrie ipv6Tree = ...;
visitRecursive(ipv6Tree.getRoot(), null);

static &lt;E&gt; void visitRecursive(BinaryTreeNode&lt;E&gt; node, String direction) {
	if(direction == null) {
		direction = "root";
	}
	System.out.println("visited " + direction + " " + node);
	BinaryTreeNode&lt;E&gt; sub = node.getLowerSubNode();
	if(sub != null) {
		visitRecursive(sub, direction + " left");
	}
	sub = node.getUpperSubNode();
	if(sub != null) {
		visitRecursive(sub, direction + " right");
	}
}
</code></pre>
	 * The following iterative code provides the same functionality:
<pre><code>
visitIterative(ipv6Tree.getRoot());

static &lt;E&gt; void visitIterative(BinaryTreeNode&lt;E&gt; node) {	
	CachingIterator&lt;? extends BinaryTreeNode&lt;E&gt;, E, String&gt;iterator = node.containingFirstAllNodeIterator(true);
	while(iterator.hasNext()) {
		BinaryTreeNode&lt;E&gt; next = iterator.next();
		String direction = iterator.getCached();
		if(direction == null) {
			direction = "root";
		}
		System.out.println("visited " + direction + " " + next);
		iterator.cacheWithLowerSubNode(direction + " left");
		iterator.cacheWithUpperSubNode(direction + " right");
	}
}
	 * </code></pre>
	 * <p>
	 * See {@link TreeOps} for more details on the ordering.
	 * 
	 * @param forwardSubNodeOrder if true, a left sub-node will be visited before the right sub-node of the same parent node.
	 * @param addedNodesOnly if true, skips nodes not corresponding to added keys, otherwise visits all nodes
	 * @return
	 */
	<C> CachingIterator<? extends BinaryTreeNode<E>, E, C> containingFirstAllNodeIterator(boolean forwardSubNodeOrder);

	/**
	 * Returns an iterator that does a post-order binary tree traversal of the added nodes.
	 * All added sub-nodes will be visited before their parent nodes.
	 * For an address trie this means contained addresses and subnets will be visited before their containing subnet blocks.
	 * <p>
	 * This iterator supports the {@link java.util.Iterator#remove()} operation.
	 * <p>
	 * See {@link TreeOps} for more details on the ordering.
	 * <p>
	 * @param forwardSubNodeOrder if true, a left sub-node will be visited before the right sub-node of the same parent node.
	 * @return
	 */
	Iterator<? extends BinaryTreeNode<E>> containedFirstIterator(boolean forwardSubNodeOrder);

	/**
	 * Returns an iterator that does a post-order binary tree traversal.
	 * All sub-nodes will be visited before their parent nodes.
	 * For an address trie this means contained addresses and subnets will be visited before their containing subnet blocks.
	* <p>
	 * This iterator does not support the {@link java.util.Iterator#remove()} operation.
	 * If {@link java.util.Iterator#remove()} is called it will throw {@link UnsupportedOperationException}.
	 * <p>
	 * See {@link TreeOps} for more details on the ordering.
	 * <p>
	 * @param forwardSubNodeOrder if true, a left sub-node will be visited before the right sub-node of the same parent node.
	 * @return
	 */
	Iterator<? extends BinaryTreeNode<E>> containedFirstAllNodeIterator(boolean forwardSubNodeOrder);

	/**
	 * Creates a {@link java.util.Spliterator} over the added nodes in forward or reverse natural tree order.
	 * <p>
	 * See {@link TreeOps} for more details on the ordering.
	 * 
	 * @param forward if true, goes in ascending order, otherwise descending
	 * @return
	 */
	default Spliterator<? extends BinaryTreeNode<E>> nodeSpliterator(boolean forward) {
        return Spliterators.spliteratorUnknownSize(nodeIterator(forward), 0);
    }

	/**
	 * Creates a {@link java.util.Spliterator} over the nodes in forward or reverse natural tree order.
	 * <p>
	 * See {@link TreeOps} for more details on the ordering.
	 * 
	 * @param forward if true, goes in ascending order, otherwise descending
	 * @return
	 */
	default Spliterator<? extends BinaryTreeNode<E>> allNodeSpliterator(boolean forward) {
        return Spliterators.spliteratorUnknownSize(allNodeIterator(forward), 0);
    }
}
