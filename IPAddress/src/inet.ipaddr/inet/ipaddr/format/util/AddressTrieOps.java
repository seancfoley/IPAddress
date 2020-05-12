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

import java.util.Iterator;
import java.util.Spliterator;
import java.util.function.Function;
import java.util.function.Supplier;

import inet.ipaddr.Address;
import inet.ipaddr.format.util.AddressTrie.TrieNode;
import inet.ipaddr.format.util.AssociativeAddressTrie.AssociativeTrieNode;
import inet.ipaddr.format.util.BinaryTreeNode.CachingIterator;

/**
 * Provides an interface to the trie operations.  
 * Operations which take an address as an argument require that the address is an individual address or prefix block. 
 * 
 * @author scfoley
 *
 * @param <E>
 */
public interface AddressTrieOps<E extends Address> extends TreeOps<E> {
	/**
	 * Gets the node corresponding to the given address, returns null if not such element exists.
	 * <p>
	 * If added is true, returns only nodes representing added elements, otherwise returns any node, 
	 * including a prefix block that was not added.
	 * <p>
	 * If the given address is not a single address nor prefix block, then this method throws IllegalArgumentException.
	 * <p>
	 * If not a single address nor prefix block, the {@link Partition} class can be used to convert the address before calling this method.  
	 * See {@link AddressTrieAddOps#add(Address)} for more details.
	 * <p>
	 * @see #contains(Address)
	 * @param addr
	 * @return
	 */
	TrieNode<E> getNode(E addr);

	/**
	 * Gets trie nodes representing added elements.
	 * <p>
	 * Use {@link #contains(Address)} to check for the existence of a given address in the trie,
	 * as well as {@link #getNode(Address)} to search for all nodes including those not-added but also auto-generated nodes for subnet blocks.
	 * 
	 * @param addr
	 * @return
	 */
	default TrieNode<E> getAddedNode(E addr) {
		TrieNode<E> ret = getNode(addr);
		return (ret == null || ret.isAdded()) ? ret : null;
	}

	/**
	 * Checks if a prefix block subnet or address in the trie contains the given subnet or address.
	 * <p>
	 * If the given address is not a single address nor prefix block, then this method throws IllegalArgumentException.
	 * <p>
	 * If not a single address nor prefix block, the {@link Partition} class can be used to convert the address before calling this method.  
	 * See {@link AddressTrieAddOps#add(Address)} for more details.
	 * <p>
	 * Returns true if the subnet or address is contained by a trie element, false otherwise.
	 * <p>
	 * To get the containing addresses, use {@link #elementsContaining(Address)}.
	 * 
	 * @param addr
	 * @return
	 */
	boolean elementContains(E addr);

	/**
	 * Returns whether the given address or prefix block subnet is in the trie (as an added element).
	 * <p>
	 * If the given address is not a single address nor prefix block, then this method throws IllegalArgumentException.
	 * <p>
	 * If not a single address nor prefix block, the {@link Partition} class can be used to convert the address before calling this method.  
	 * See {@link AddressTrieAddOps#add(Address)} for more details.
	 * <p>
	 * Returns true if the prefix block or address address exists already in the trie, false otherwise.
	 * <p>
	 * Use {@link #getAddedNode(Address)} to get the node for the address rather than just checking for its existence.
	 * 
	 * @param addr
	 * @return
	 */
	boolean contains(E addr);

	/**
	 * Removes the given single address or prefix block subnet from the trie.
	 * <p>
	 * Removing an element will not remove contained elements (nodes for contained blocks and addresses).
	 * <p>
	 * If the given address is not a single address nor prefix block, then this method throws IllegalArgumentException. 
	 * <p>
	 * If not a single address nor prefix block, the {@link Partition} class can be used to convert the address before calling this method.  
	 * See {@link AddressTrieAddOps#add(Address)} for more details.
	 * <p>
	 * Returns true if the prefix block or address was removed, false if not already in the trie.
	 * <p>
	 * You can also remove by calling {@link #getAddedNode(Address)} to get the node and then calling {@link BinaryTreeNode#remove()} on the node.
	 * <p>
	 * When an address is removed, the corresponding node may remain in the trie if it remains a subnet block for two sub-nodes.
	 * If the corresponding node can be removed from the trie, it will be.
	 * 
	 * @see #removeElementsContainedBy(Address)
	 * @param addr
	 * @return
	 */
	boolean remove(E addr);

	/**
	 * Removes any single address or prefix block subnet from the trie that is contained in the given individual address or prefix block subnet.
	 * <p>
	 * Goes further than {@link #remove(Address)}, not requiring a match to an inserted node, and also removing all the sub-nodes of any removed node or sub-node.
	 * <p>
	 * For example, after inserting 1.2.3.0 and 1.2.3.1, passing 1.2.3.0/31 to {@link #removeElementsContainedBy(Address)} will remove them both,
	 * while {@link #remove(Address)} will remove nothing.  
	 * After inserting 1.2.3.0/31, then #remove(Address) will remove 1.2.3.0/31, but will leave 1.2.3.0 and 1.2.3.1 in the trie.
	 * <p>
	 * It cannot partially delete a node, such as deleting a single address from a prefix block represented by a node.  
	 * It can only delete the whole node if the whole address or block represented by that node is contained in the given address or block.
	 * <p>
	 * If the given address is not a single address nor prefix block, then this method throws IllegalArgumentException. 
	 * <p>
	 * If not a single address nor prefix block, the {@link Partition} class can be used to convert the address before calling this method.  
	 * See {@link AddressTrieAddOps#add(Address)} for more details.
	 * <p>
	 * Returns the root node of the subtrie that was removed from the trie, or null if nothing was removed.
	 * 
	 * @see #removeElementsContainedByEach(Address, Function)
	 * @param addr
	 * @return
	 */
	TrieNode<E> removeElementsContainedBy(E addr);

	/**
	 * Checks if a part of this trie is contained by the given prefix block subnet or individual address.
	 * <p>
	 * If the given address is not a single address nor prefix block, then this method throws IllegalArgumentException. 
	 * <p>
	 * If not a single address nor prefix block, the {@link Partition} class can be used to convert the address before calling this method.  
	 * See {@link AddressTrieAddOps#add(Address)} for more details.
	 * <p>
	 * Returns the root node of the contained subtrie, or null if no subtrie is contained.
	 * The node returned need not be an "added" node, see {@link TrieNode#isAdded()} for more details on added nodes.
	 * The returned subtrie is backed by this trie, so changes in this trie are reflected in those nodes and vice-versa.
	 * 
	 * @param addr
	 * @return
	 */
	TrieNode<E> elementsContainedBy(E addr);
				
	/**
	 * Finds the added subnets and/or addresses in the trie that contain the given individual address or prefix block subnet.
	 * <p>
	 * If the given address is not a single address nor prefix block, then this method throws IllegalArgumentException.
	 * <p>
	 * If not a single address nor prefix block, the {@link Partition} class can be used to convert the address before calling this method.  
	 * See {@link AddressTrieAddOps#add(Address)} for more details.
	 * <p>
	 * Returns a list of the nodes for prefix block subnets and addresses from the trie that contain the address or block.
	 * The list consists only of added nodes, see {@link TrieNode#isAdded()} for more details on added nodes.
	 * The list is constructed as a trie in which each parent node has only one sub-node.
	 * <p>
	 * Use {@link #elementContains(Address)} to check for the existence of a containing address.
	 * 
	 * @param addr
	 * @return
	 */
	TrieNode<E> elementsContaining(E addr);

	@Override
	Iterator<? extends TrieNode<E>> nodeIterator(boolean forward);

	@Override
	Iterator<? extends TrieNode<E>> allNodeIterator(boolean forward);

	@Override
	<C> CachingIterator<? extends TrieNode<E>, E, C> containingFirstIterator(boolean forwardSubNodeOrder);

	@Override
	<C> CachingIterator<? extends TrieNode<E>, E, C> containingFirstAllNodeIterator(boolean forwardSubNodeOrder);

	@Override
	Iterator<? extends TrieNode<E>> containedFirstIterator(boolean forwardSubNodeOrder);

	@Override
	Iterator<? extends TrieNode<E>> containedFirstAllNodeIterator(boolean forwardSubNodeOrder);
	
	@Override
	Spliterator<? extends TrieNode<E>> nodeSpliterator(boolean forward);
	
	@Override
	Spliterator<? extends TrieNode<E>> allNodeSpliterator(boolean forward);

	/**
	 * Returns the node with the first (lowest valued) key, whether the node is added or not
	 * 
	 * @return
	 */
	TrieNode<E> firstNode();

	/**
	 * Returns the node with the last (highest valued) key, whether the node is added or not
	 * 
	 * @return
	 */
	TrieNode<E> lastNode();
	
	/**
	 * Returns the added node with the first (lowest valued) key, 
	 * or null if there are no added entries in this trie or subtrie
	 * @return
	 */
	TrieNode<E> firstAddedNode();

	/**
	 * Returns the added node with the last (highest valued) key, 
	 * or null if there are no added elements in this trie or subtrie
	 * @return
	 */
	TrieNode<E> lastAddedNode();

	/**
	 * Returns the added node whose address is the highest address less than or equal to the given address.
	 * @param addr
	 * @return
	 */
	TrieNode<E> floorAddedNode(E addr);

	/**
	 * Returns the added node whose address is the highest address strictly less than the given address.
	 * @param addr
	 * @return
	 */
	TrieNode<E> lowerAddedNode(E addr);

	/**
	 * Returns the added node whose address is the lowest address greater than or equal to the given address.
	 * @param addr
	 * @return
	 */
	TrieNode<E> ceilingAddedNode(E addr);

	/**
	 * Returns the added node whose address is the lowest address strictly greater than the given address.
	 * @param addr
	 * @return
	 */
	TrieNode<E> higherAddedNode(E addr);

	/**
	 * Provides an interface to the trie add operations.<p>
	 * Operations which take an address as an argument require that the address is an individual address or prefix block. 
	 * 
	 * 
	 * @author scfoley
	 *
	 * @param <E>
	 */
	public static interface AddressTrieAddOps<E extends Address> extends AddressTrieOps<E> {
		/**
		 * Adds the given single address or prefix block subnet to the trie.
		 * <p>
		 * If the given address is not a single address nor prefix block, then this method throws IllegalArgumentException. 
		 * <p>
		 * If not a single address nor prefix block, the {@link Partition} class can be used to convert the address before calling this method.  
		 * Given a subnet s of type T and a trie of type AddressTrie<T>, such as {@link inet.ipaddr.ipv4.IPv4Address} and {@link inet.ipaddr.ipv4.IPv4AddressTrie},
		 * you can convert and add the spanning prefix blocks with <code>Partition.partitionWithSpanningBlocks(s).predicateForEach(trie::add)</code>,
		 * or you can convert and add using a single max block size with <code>Partition.partitionWithSingleBlockSize(s).predicateForEach(trie::add)</code>.
		 * <p>
		 * Returns true if the prefix block or address was inserted, false if already in the trie.
		 * 
		 * @param addr
		 * @return
		 */
		boolean add(E addr);
		
		/**
		 * Adds the given single address or prefix block subnet to the trie, if not already there.
		 * <p>
		 * If the given address is not a single address nor prefix block, then this method throws IllegalArgumentException. 
		 * <p>
		 * If not a single address nor prefix block, the {@link Partition} class can be used to convert the address before calling this method.  
		 * See {@link #add(Address)} for more details.
		 * <p>
		 * Returns the node for the added address, whether it was already in the trie or not.
		 * <p>
		 * If you wish to know whether the node was already there when adding, use {@link #add(Address)}, or before adding you can use {@link #getAddedNode(Address)}
		 * 
		 * @param addr
		 * @return
		 */
		TrieNode<E> addNode(E addr);
	
		/**
		 * Adds nodes matching the given sub-root node and all of its sub-nodes to the trie, if not already there.
		 * <p>
		 * For each added in the given node that does not exist in the trie, a copy of each node will be made that matches the trie type (associative or not),
		 * and the copy will be inserted into the trie.
		 * <p>
		 * The node type need not match the node type of the trie, although the address type/version E must match.
		 * You can add associative nodes to tries with this method but associated values will all be null.
		 * If you want to preserve the values, use {@link AssociativeAddressTriePutOps#putTrie(AssociativeTrieNode)} instead.
		 * <p>
		 * When adding one trie to another, this method is more efficient than adding each node of the first trie individually.
		 * When using this method, searching for the location to add sub-nodes starts from the inserted parent node.
		 * <p>
		 * Returns the node corresponding to the given sub-root node, whether it was already in the trie or not.
		 * <p>
		 * 
		 * @param addr
		 * @return
		 */
		TrieNode<E> addTrie(TrieNode<E> trie);
	}

	/**
	 * Provides an interface to the associative trie operations.<p>
	 * Operations which take an address as an argument require that the address is an individual address or prefix block.
	 * 
	 * 
	 * @author scfoley
	 *
	 * @param <K>
	 * @param <V>
	 */
	public static interface AssociativeAddressTrieOps<K extends Address, V> extends AddressTrieOps<K> {
		/**
		 * Gets the specified value for the specified key in this mapped trie or subtrie.
		 * <p>
		 * If the given address is not a single address nor prefix block, then this method throws IllegalArgumentException.
		 * <p>
		 * If not a single address nor prefix block, the {@link Partition} class can be used to convert the address before calling this method.  
		 * See {@link AddressTrieAddOps#add(Address)} for more details.
		 * <p>
		 * Returns the value for the given key.
		 * Returns null if the contains no mapping for that key or if the mapped value is null.
		 * 
		 * @param addr
		 * @return
		 */
		V get(K addr);
	}

	/**
	 * Provides an interface to the associative trie put operations.<p>
	 * Operations which take an address as an argument require that the address is an individual address or prefix block.
	 * 
	 * 
	 * @author scfoley
	 *
	 * @param <K>
	 * @param <V>
	 */
	public static interface AssociativeAddressTriePutOps<K extends Address, V> extends AssociativeAddressTrieOps<K, V> {
		/**
		 * Associates the specified value with the specified key in this map.
		 * <p>
	     * Unlike {@link #putNew(Address, Object)}, {@link #put(Address, Object)} can provide the value to which to key was previously mapped.
		 * <p>
		 * If the given address is not a single address nor prefix block, then this method throws IllegalArgumentException.
		 * <p>
		 * If not a single address nor prefix block, the {@link Partition} class can be used to convert the address before calling this method.  
		 * See {@link AddressTrieAddOps#add(Address)} for more details.
		 * <p>
		 * If this map previously contained a mapping for a key, 
		 * the old value is replaced by the specified value, and the old value is returned.
	     * If this map did not previously contain a mapping for the key, null is returned.
		 * 
		 * @param addr
		 * @return
		 */
		V put(K addr, V value);
		
		/**
		 * Associates the specified value with the specified key in this map.
		 * <p>
	     * Unlike {@link #put(Address, Object)}, {@link #put(Address, Object)} can distinguish between
	     * cases where the call results in a new entry, and cases where the call matched a previous entry that was mapped to null.
		 * <p>
		 * If the given address is not a single address nor prefix block, then this method throws IllegalArgumentException.
		 * <p>
		 * If not a single address nor prefix block, the {@link Partition} class can be used to convert the address before calling this method.  
		 * See {@link AddressTrieAddOps#add(Address)} for more details.
		 * <p>
		 * If this map previously contained a mapping for a key, 
		 * the old value is replaced by the specified value, and false is returned.
	     * If this map did not previously contain a mapping for the key, true is returned.
	     * 
		 * @param addr
		 * @return
		 */
		boolean putNew(K addr, V value);
		
		
		/**
		 * Associates the specified value with the specified key in this map.
		 * <p>
	     * Unlike {@link #put(Address, Object)}, {@link #put(Address, Object)} can distinguish between
	     * cases where the call results in a new entry, and cases where the call matched a previous entry that was mapped to null.
		 * <p>
		 * If the given address is not a single address nor prefix block, then this method throws IllegalArgumentException.
		 * <p>
		 * If not a single address nor prefix block, the {@link Partition} class can be used to convert the address before calling this method.  
		 * See {@link AddressTrieAddOps#add(Address)} for more details.
		 * <p>
		 * Returns the node for the added address, whether it was already in the tree or not.
		 * <p>
		 * If you wish to know whether the node was already there when adding, use {@link #putNew(Address, Object)}, or before adding you can use {@link #getAddedNode(Address)}
	     * 
		 * @param addr
		 * @return
		 */
		AssociativeTrieNode<K,V> putNode(K addr, V value);

		/**
		 * Remaps node values in the trie.
		 * <p>
		 * This will lookup the node corresponding to the given key.
		 * It will call the remapping function with the key as the first argument, regardless of whether the node is found or not.
		 * <p>
		 * If the node is not found, the value argument will be null.  
		 * If the node is found, the value argument will be the node's value, which can also be null.  
		 * <p>
		 * If the remapping function returns null, then the matched node will be removed, if any.
		 * If it returns a non-null value, then it will either set the existing node to have that value,
		 * or if there was no matched node, it will create a new node with that value.
		 * <p>
		 * The method will return the node involved, which is either the matched node, or the newly created node,
		 * or null if there was no matched node nor newly created node.
		 * <p>
		 * If the remapping function modifies the trie during its computation,
		 * and the returned value specifies changes to be made,
		 * then the trie will not be changed and ConcurrentModificationException will be thrown instead.
		 * <p>
		 * If the given address is not a single address nor prefix block, then this method throws IllegalArgumentException.
		 * <p>
		 * If not a single address nor prefix block, the {@link Partition} class can be used to convert the address before calling this method.  
		 * See {@link AddressTrieAddOps#add(Address)} for more details.
		 * 
		 * @param addr
		 * @param remapper
		 * @return
		 */
		AssociativeTrieNode<K, V> remap(K addr, Function<? super V, ? extends V> remapper);

		/**
		 * Remaps node values in the trie, but only for nodes that do not exist or are mapped to null.
		 * <p>
		 * This will look up the node corresponding to the given key.
		 * If the node is not found or mapped to null, this will call the remapping function.
		 * <p>
		 * If the remapping function returns a non-null value, then it will either set the existing node to have that value,
		 * or if there was no matched node, it will create a new node with that value.
		 * If the remapping function returns null, then it will do the same if insertNull is true, otherwise it will do nothing.
		 * <p>
		 * The method will return the node involved, which is either the matched node, or the newly created node,
		 * or null if there was no matched node nor newly created node.
		 * <p>
		 * If the remapping function modifies the trie during its computation,
		 * and the returned value specifies changes to be made,
		 * then the trie will not be changed and ConcurrentModificationException will be thrown instead.
		 * <p>
		 * If the given address is not a single address nor prefix block, then this method throws IllegalArgumentException.
		 * <p>
		 * If not a single address nor prefix block, the {@link Partition} class can be used to convert the address before calling this method.  
		 * See {@link AddressTrieAddOps#add(Address)} for more details.
		 * 
		 * @param addr
		 * @param remapper
		 * @param insertNull whether null values returned from remapper should be inserted into the map, or whether null values indicate no remapping
		 * @return
		 */
		AssociativeTrieNode<K, V> remapIfAbsent(K addr, Supplier<? extends V> remapper, boolean insertNull);

		/**
		 * Adds nodes matching the given sub-root node and all of its sub-nodes to the trie, if not already there.
		 * <p>
		 * For each added in the given node that does not exist in the trie, a copy of each node will be made that matches the trie type (associative or not),
		 * the copy including the associated value, and the copy will be inserted into the trie.
		 * <p>
		 * The node type need not match the node type of the trie, although the address type/version E must match.
		 * So this means you can add non-associative nodes with this method,
		 * in which case, the new nodes will be associative but will be mapped to null.
		 * <p>
		 * When adding one trie to another, this method is more efficient than adding each node of the first trie individually.
		 * When using this method, searching for the location to add sub-nodes starts from the inserted parent node.
		 * <p>
		 * Returns the node corresponding to the given sub-root node, whether it was already in the trie or not.
		 * <p>
		 * 
		 * @param addr
		 * @return
		 */
		AssociativeTrieNode<K, V> putTrie(AssociativeTrieNode<K, V> trie);
	}
}
