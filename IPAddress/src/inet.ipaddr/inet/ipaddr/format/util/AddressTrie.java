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
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.Iterator;
import java.util.Spliterator;
import java.util.function.Function;

import inet.ipaddr.Address;
import inet.ipaddr.AddressSegment;
import inet.ipaddr.AddressSegmentSeries;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressSegment;
import inet.ipaddr.format.util.AddressTrie.TrieNode.FollowingBits;
import inet.ipaddr.format.util.AddressTrie.TrieNode.KeyCompareResult;
import inet.ipaddr.format.util.AssociativeAddressTrie.AssociativeTrieNode;
import inet.ipaddr.format.util.BinaryTreeNode.BlockSizeNodeIterator;
import inet.ipaddr.format.util.BinaryTreeNode.Bounds;
import inet.ipaddr.format.util.BinaryTreeNode.CachingIterator;
import inet.ipaddr.format.util.BinaryTreeNode.ChangeTracker;
import inet.ipaddr.format.util.BinaryTreeNode.ChangeTracker.Change;
import inet.ipaddr.format.util.BinaryTreeNode.Indents;
import inet.ipaddr.format.util.BinaryTreeNode.KeySpliterator;
import inet.ipaddr.format.util.BinaryTreeNode.NodeIterator;
import inet.ipaddr.format.util.BinaryTreeNode.NodeSpliterator;
import inet.ipaddr.format.util.BinaryTreeNode.PostOrderNodeIterator;
import inet.ipaddr.format.util.BinaryTreeNode.PreOrderNodeIterator;
import inet.ipaddr.format.validate.ParsedAddressGrouping;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv6.IPv6Address;

/**
 * A compact binary trie (aka compact binary prefix tree, or binary radix trie), for addresses and/or CIDR prefix block subnets.
 * The prefixes in used by the prefix trie are the CIDR prefixes, or the full address in the case of individual addresses with no prefix length.  
 * The elements of the trie are CIDR prefix blocks or addresses.
 * <p>
 * This trie data structure allows you to check an address for containment in many subnets at once, in constant time.  
 * The trie allows you to check a subnet for containment of many smaller subnets or addresses at once, in constant time.
 * The trie allows you to check for equality of a subnet or address with a large number of subnets or addresses at once.
 *<p>
 * The trie can also be used as the backing structure for a {@link AddressTrieSet} which is a {@link java.util.NavigableSet}.
 * Unlike {@link java.util.TreeSet} this data structure provides access to the nodes and the associated subtrie with each node,
 * which corresponds with their associated CIDR prefix block subnets.
 * <p>
 * There is only a single possible trie for any given set of address and subnets.  For one thing, this means they are automatically balanced.
 * Also, this makes access to subtries and to the nodes themselves more useful, allowing for many of the same operations performed on the original trie.  
 * <p>
 * Each node has either a prefix block or a single address as its key.  
 * Each prefix block node can have two sub-nodes, each sub-node a prefix block or address contained by the node.
 * <p>
 * There are more nodes in the trie than there are elements in the set.  
 * A node is considered "added" if it was explicitly added to the trie and is included as an element when viewed as a set.
 * There are non-added prefix block nodes that are generated in the trie as well.
 * When two or more added addresses share the same prefix up until they differ with the bit at index x, 
 * then a prefix block node is generated (if not already added to the trie) for the common prefix of length x,
 * with the nodes for those addresses to be found following the lower 
 * or upper sub-nodes according to the bit at index x + 1 in each address.
 * If that bit is 1, the node can be found by following the upper sub-node, 
 * and when it is 0, the lower sub-node.  
 * <p>
 * Nodes that were generated as part of the trie structure only 
 * because of other added elements are not elements of the represented set.
 * The set elements are the elements that were explicitly added.
 * <p>
 * You can work with parts of the trie, starting from any node in the trie,
 * calling methods that start with any given node, such as iterating or spliterating the subtrie,
 * finding the first or last in the subtrie, doing containment checks with the subtrie, and so on.
 * <p>
 * The binary trie structure defines a natural ordering of the trie elements.  
 * Addresses of equal prefix length are sorted by prefix value.  Addresses with no prefix length are sorted by address value.
 * Addresses of differing prefix length are sorted according to the bit that follows the shorter prefix length in the address with the longer prefix length,
 * whether that bit is 0 or 1 determines if that address is ordered before or after the address of shorter prefix length.
 * <p>
 * The unique and pre-defined structure for a trie means that different means of traversing the trie can be more meaningful.
 * This trie implementation provides 8 different ways of iterating through the trie:
 * <ul><li>1, 2: the natural sorted trie order, forward and reverse (spliterating is also an option for these two orders).  Use {@link #nodeIterator(boolean)}, {@link #iterator()} or {@link #descendingIterator()}.  A comparator is also provided for this order.
 * </li><li>3, 4: pre-order tree traversal, in which parent node is visited before sub-nodes, with sub-nodes visited in forward or reverse order
 * </li><li>5, 6: post-order tree traversal, in which sub-nodes are visited before parent nodes, with sub-nodes visited in forward or reverse order
 * </li><li>7, 8: prefix-block order, in which larger prefix blocks are visited before smaller, and blocks of equal size are visited in forward or reverse sorted order
 * </li></ul>
 * <p>
 * 
 * All of these orderings are useful in specific contexts.
 * <p>
 * You can do lookup and containment checks on all the subnets and addresses in the trie at once, in constant time.
 * A generic trie data structure lookup is O(m) where m is the entry length. 
 * For this trie, which operates on address bits, entry length is capped at 128 bits for IPv6 and 32 bits for IPv4.
 * That makes lookup a constant time operation.  
 * Subnet containment or equality checks are also constant time since they work the same way as lookup, by comparing prefix bits.
 * <p>
 * For a generic trie data structure, construction is O(m * n) where m is entry length and n is the number of addresses,
 * but for this trie, since entry length is capped at 128 bits for IPv6 and 32 bits for IPv4, construction is O(n),
 * in linear proportion to the number of added elements.
 *<p>
 * This trie also allows for constant time size queries (count of added elements, not node count), by storing sub-trie size in each node. 
 * It works by updating the size of every node in the path to any added or removed node.
 * This does not change insertion or deletion operations from being constant time (because tree-depth is limited to address bit count). 
 * At the same this makes size queries constant time, rather than being O(n) time.
 * <p>
 * This class is abstract and has a subclass for each address version or type. 
 * A single trie can use just a single address type or version, since it works with bits alone,
 * and this cannot distinguish between different versions and types in the trie structure. 
 * More specifically, using different address bit lengths would:
 * <ul>
 * <li>break the concept of containment, for example IPv6 address 0::/8 would be considered to contain IPv4 address 0.2.3.4
 * </li><li>break the concept of equality, for example MAC 1:2:3:*:*:* and IPv4 1.2.3.0/24 would be considered the same since they have the same prefix bits and length 
 * </li></ul><p>
 * Instead, you could aggregate multiple subtries to create a collection of multiple address types or versions.
 * You can use the method {@link #toString(boolean, AddressTrie...)} for a String that represents multiple tries as a single tree.
 * <p>
 * Tries are thread-safe when not being modified (elements added or removed), but are not thread-safe when one thread is modifying the trie.
 * For thread safety when modifying, one option is to use {@link Collections#synchronizedNavigableSet(java.util.NavigableSet)} on {@link #asSet()}.
 * <p>
 * 
 * @author scfoley
 *
 * @param <E> the type of the address keys
 */
// Note: We do not allow direct access to tries that have non-null bounds.
// Such tries can only be accessed indirectly through the Set and Map classes.
// Methods like removeElementsContainedBy, elementsContainedBy, elementsContaining, and elementContains (and perhaps a couple others) would be inaccurate,
//	as they do not account for the bounds.
// Those methods used by the Set and Map classes do account for the bounds.
// Also, many methods here give access to the nodes, and the nodes themselves do not account for the bounds.
// That in particular would make things quite confusing for users, in which the trie methods and the node methods produce different results.
//
// So overall, we do not allow direct access to AddressTrie objects that have bounds, mostly because of the potential confusion,
// and because it would force us to alter the API for methods like elementsContainedBy in a way that makes the API inferior.
//
// We do allow the Set and Map classes to produce an AddressTrie even when bounded, 
// but that AddressTrie is a clone of the bounded trie that has only the bounded nodes.
// So, overall, we do provide the same functionality, you just have to generate a new trie from the bounded set or map.
//
// Also, by storing the bounds strictly inside the AddressTrie, we avoid the complications of making the Bounds part of the API,
// which would make all the operations quite tricky and in some cases expensive.
// For instance, here we can cache the bounded root and reuse it.  
// Making the bounds part of the API would also double the API method count and make the API quite cumbersome,
// even if it is not public.
//
// So for all those reasons, the bounds are stored in the tries, but tries with bounds are not directly accessible.
// The API then remains quite full-fledged, with full access to the nodes, while at the same time the Set and Map API
// also remains full-fledged.  Finally, Map and Set users can get a non-bounds trie for any bounded Set or Map,
// should they really want one.
// 
public abstract class AddressTrie<E extends Address> extends AbstractTree<E> {

	private static final long serialVersionUID = 1L;

	protected static class AddressBounds<E extends Address> extends Bounds<E> {

		private static final long serialVersionUID = 1L;
		
		E oneAboveUpperBound, oneBelowUpperBound, oneAboveLowerBound, oneBelowLowerBound;

		
		AddressBounds(E lowerBound, E upperBound, Comparator<? super E> comparator) {
			this(lowerBound, true, upperBound, false, comparator);
		}
		
		AddressBounds(E lowerBound, boolean lowerInclusive, E upperBound, boolean upperInclusive, Comparator<? super E> comparator) {
			super(lowerBound, lowerInclusive, upperBound, upperInclusive, comparator);
			if(lowerBound != null) {
				checkBlockOrAddress(lowerBound, true);
			}
			if(upperBound != null) {
				checkBlockOrAddress(upperBound, true);
			}
		}
		
		static <E extends Address> AddressBounds<E> createNewBounds(E lowerBound, boolean lowerInclusive, E upperBound, boolean upperInclusive, Comparator<? super E> comparator) {
			if(lowerBound != null) {
				if(lowerInclusive && lowerBound.isZero()) {
					lowerBound = null;
				}
			}
			if(upperBound != null) {
				if(upperInclusive && upperBound.isMax()) {
					upperBound = null;
				}
			}
			if(lowerBound == null && upperBound == null) {
				return null;
			}
			return new AddressBounds<E>(lowerBound, lowerInclusive, upperBound, upperInclusive, comparator);
		}
		
		@Override
		AddressBounds<E> createBounds(E lowerBound, boolean lowerInclusive, E upperBound, boolean upperInclusive, Comparator<? super E> comparator) {
			return new AddressBounds<E>(lowerBound, lowerInclusive, upperBound, upperInclusive, comparator);
		}
		
		@Override
		AddressBounds<E> restrict(E lowerBound, boolean lowerInclusive, E upperBound, boolean upperInclusive) {
			return (AddressBounds<E>) super.restrict(lowerBound, lowerInclusive, upperBound, upperInclusive);
		}
		
		@Override
		AddressBounds<E> intersect(E lowerBound, boolean lowerInclusive, E upperBound, boolean upperInclusive) {
			return (AddressBounds<E>) super.intersect(lowerBound, lowerInclusive, upperBound, upperInclusive);
		}
		
		
		// matches the value just above the upper bound (only applies to discrete quantities)
		@Override
		boolean isAdjacentAboveUpperBound(E addr) {
			E res = oneAboveUpperBound;
			if(res == null) {
				res = increment(upperBound);
				oneAboveUpperBound = res;
			}
			return res != null && res.equals(addr);
		}
		
		// matches the value just below the lower bound (only applies to discrete quantities)
		@Override
		boolean isAdjacentBelowLowerBound(E addr) {
			E res = oneBelowLowerBound;
			if(res == null) {
				res = decrement(lowerBound);
				oneBelowLowerBound = res;
			}
			return res != null && res.equals(addr);
		}
		
		// matches the value just below the upper bound (only applies to discrete quantities)
		@Override
		boolean isAdjacentBelowUpperBound(E addr) { 
			E res = oneBelowUpperBound;
			if(res == null) {
				res = decrement(upperBound);
				oneBelowUpperBound = res;
			}
			return res != null && res.equals(addr);
		}
		
		// matches the value just above the lower bound (only applies to discrete quantities)
		@Override
		boolean isAdjacentAboveLowerBound(E addr) {
			E res = oneAboveLowerBound;
			if(res == null) {
				res = increment(lowerBound);
				oneAboveLowerBound = res;
			}
			return res != null && res.equals(addr);
		}
		
		@Override
		boolean isMax(E addr) {
			return addr.isMax();
		}

		@Override
		boolean isMin(E addr) {
			return addr.isZero();
		}
		
		@Override
		public String toCanonicalString(String separator) {
			Function<? super E, String> stringer = Address::toCanonicalString;
			return toString(stringer, separator, stringer);
		}
	}
	
	protected static enum Operation {
		// Given an address/subnet key E
	    INSERT, // add node for E if not already there
	    REMAP, // alters nodes based on the existing nodes and their values
	    LOOKUP, // find node for E, traversing all containing elements along the way
	    NEAR, // closest match, going down trie to get element considered closest.
	    	// Whether one thing is closer than another is determined by the sorted order.
	    	// For example, for subnet 1.2.0.0/16, 1.2.128.0 is closest address on the high side, 1.2.127.255 is closest address on the low side
	    CONTAINING, // find a single node whose key contains E
	    ALL_CONTAINING, // list the nodes whose keys contain E
	    INSERTED_DELETE, // remove node for E
	    SUBTREE_DELETE // remove nodes whose keys are contained by E
	}
	
	// not optimized for size, since only temporary, to be used for a single operation
	protected static class OpResult<E extends Address> implements KeyCompareResult, FollowingBits, Serializable {

		private static final long serialVersionUID = 1L;

		E addr;
		
		// whether near is searching for a floor or ceiling
		// a floor is greatest element below addr
		// a ceiling is lowest element above addr
		boolean nearestFloor; 
		
		// whether near cannot be an exact match
		boolean nearExclusive;
		
		Operation op;
		
		OpResult() {}
		
		OpResult(E addr, Operation op) {
			this(addr, op, false, false);
		}

		OpResult(E addr, boolean floor, boolean exclusive) {
			this(addr, Operation.NEAR, floor, exclusive);
		}

		private OpResult(E addr, Operation op, boolean floor, boolean exclusive) {
			this.addr = addr;
			this.op = op;
			this.nearestFloor = floor;
			this.nearExclusive = exclusive;
		}

		// do not use with Operation.NEAR, INSERT, REMAP, INSERTED_DELETE, SUBTREE_DELETE
		OpResult<E> reset(E addr, Operation op) {
			this.addr = addr;
			this.op = op;
			return this;
		}
		
		OpResult<E> resetNear(E addr, boolean floor, boolean exclusive) {
			this.nearestFloor = floor;
			this.nearExclusive = exclusive;
			return reset(addr, Operation.NEAR);
		}
		
		// Do not use with Operation.NEAR, INSERT, REMAP, INSERTED_DELETE, SUBTREE_DELETE,
		// We'd need to do more cleaning if we did.
		void clean() {
			addr = null;
			op = null;
			
			// contains and lookups
			exists = false;
			existingNode = containing = containingEnd = 
					smallestContaining = largestContaining = 
					containedBy = null;
			
			// near
			nearestFloor = nearExclusive = false;
			nearestNode = backtrackNode = null;
			
			// deletions
			deleted = null;
			
			// adds and puts
			newValue = existingValue = null;
			inserted = added = addedAlready = null;

			// remaps
			remapper = null;
		}

		// lookups:

		// an inserted tree element matches the supplied argument
		// exists is set to true only for "added" nodes
		boolean exists;

		// the matching tree element, when doing a lookup operation, or the pre-existing node for an insert operation
		// existingNode is set for both added and not added nodes
		TrieNode<E> existingNode;

		// the closest tree element, when doing a near operation
		TrieNode<E> nearestNode;


		// if searching for a floor/lower, and the nearest node is above addr, then we must backtrack to get below
		// if searching for a ceiling/higher, and the nearest node is below addr, then we must backtrack to get above
		TrieNode<E> backtrackNode;
		
		// contains:  

		// A linked list of the tree elements, from largest to smallest, 
		// that contain the supplied argument, and the end of the list
		TrieNode<E> containing, containingEnd;
		
		// Of the tree nodes with elements containing the subnet or address,
		// those with the smallest or largest subnet or address
		TrieNode<E> smallestContaining, largestContaining;

		// contained by: 

		// this tree is contained by the supplied argument
		TrieNode<E> containedBy;

		// deletions:

		// this tree was deleted
		TrieNode<E> deleted;


		// adds and puts:

		// new and existing values for add, put and remap operations
		Object newValue, existingValue;
	
		// this added tree node was newly created for an add
		TrieNode<E> inserted;

		// this added tree node previously existed but had not been added yet
		TrieNode<E> added;

		// this added tree node was already added to the trie
		TrieNode<E> addedAlready;

		// remaps:

		Function<?, ?> remapper;

		static <E extends Address> TrieNode<E> getNextAdded(TrieNode<E> node) {
			while(node != null && !node.isAdded()) {
				// Since only one of upper and lower can be populated, whether we start with upper or lower does not matter
				TrieNode<E> next = node.getUpperSubNode();
				if(next == null) {
					node = node.getLowerSubNode();
				} else {
					node = next;
				}
			}
			return node;
		}

		TrieNode<E> getContaining() {
			TrieNode<E> containing = getNextAdded(this.containing);
			this.containing = containing;
			if(containing != null) {
				TrieNode<E> current = containing;
				do {
					TrieNode<E> next = current.getUpperSubNode();
					TrieNode<E> nextAdded;
					if(next == null) {
						next = current.getLowerSubNode();
						nextAdded = getNextAdded(next);
						if(next != nextAdded) {
							current.setLower(nextAdded);
						}
					} else {
						nextAdded = getNextAdded(next);
						if(next != nextAdded) {
							current.setUpper(nextAdded);
						}
					}
					current = nextAdded;
				} while(current != null);
			}
			return containing;
		}

		// add to the list of tree elements that contain the supplied argument
		void addContaining(TrieNode<E> containingSub) {
			TrieNode<E> cloned = containingSub.clone();
			if(containing == null) {
				containing = cloned;
			} else {
				Comparator<BinaryTreeNode<E>> comp = nodeComparator();
				if(comp.compare(containingEnd, cloned) > 0) {
					containingEnd.setLower(cloned);
				} else {
					containingEnd.setUpper(cloned);
				}
				containingEnd.adjustCount(1);
			}
			containingEnd = cloned;
		}
		
		//
		//
		//
		// for searching
		
		long followingBits;
		
		@Override
		public void setFollowingBits(long bits) {
			followingBits = bits;
		}
		
		TrieNode<E> node;
		
		@Override
		public void bitsMatch() {
			E existingAddr = node.getKey();
			Integer existingPref = existingAddr.getPrefixLength();
			Integer newPrefixLen = addr.getPrefixLength();
			containedBy = node;
			if(existingPref == null) {
				if(newPrefixLen == null) {
					// note that "added" is already true here, 
					// we can only be here if explicitly inserted already 
					// since it is a non-prefixed full address
					node.handleMatch(this);
				} else if(newPrefixLen == existingAddr.getBitCount()) {
					node.handleMatch(this);
				} else  {
					node.handleContained(this, newPrefixLen);
				}
			} else { 
				// we know newPrefixLen != null since we know all of the bits of newAddr match, 
				// which is impossible if newPrefixLen is null and existingPref not null
				if(newPrefixLen.intValue() == existingPref.intValue()) {
					if(node.isAdded()) {
						node.handleMatch(this);
					} else {
						node.handleNodeMatch(this);
					}
				} else if(existingPref == existingAddr.getBitCount()) { 
					node.handleMatch(this);
				} else { // existing prefix > newPrefixLen
					node.handleContained(this, newPrefixLen);
				}
			}
		}

		@Override
		public void bitsDoNotMatch(int matchedBits) {
			node.handleSplitNode(this, matchedBits);
		}

		@Override
		public FollowingBits bitsMatchPartially() {
			if(node.isAdded()) {
				node.handleContains(this);
				if(op == Operation.CONTAINING) {
					return null;
				}
			}
			return this;
		}
	}

	/**
	 * A comparator that provides the same ordering used by the trie,
	 * an ordering that works with prefix block subnets and individual addresses.
	 * The comparator is consistent with the equality and hashcode of address instances
	 * and can be used in other contexts.  However, it only works with prefix blocks and individual addresses,
	 * not with addresses like 1-2.3.4.5-6 which cannot be differentiated using this comparator from 1.3.4.5
	 * and is thus not consistent with equals and hashcode for subnets that are not CIDR prefix blocks.
	 * <p>
	 * The comparator first compares the prefix of addresses, with the full address value considered the prefix when 
	 * there is no prefix length, ie when it is a single address.  It takes the minimum m of the two prefix lengths and
	 * compares those m prefix bits in both addresses.  The ordering is determined by which of those two values is smaller or larger.
	 * <p>
	 * If those two values match, then it looks at the address with longer prefix.  
	 * If both prefix lengths match then both addresses are equal.
	 * Otherwise it looks at bit m in the address with larger prefix.  If 1 it is larger and if 0 it is smaller than the other.
	 * <p>
	 * When comparing an address with a prefix p and an address without, the first p bits in both are compared, and if equal,
	 * the bit at index p in the non-prefixed address determines the ordering, if 1 it is larger and if 0 it is smaller than the other.
	 * <p>
	 * When comparing an address with prefix length matching the bit count to an address with no prefix, they are considered equal if the bits match.
	 * For instance, 1.2.3.4/32 is equal to 1.2.3.4, and thus the trie does not allow 1.2.3.4/32 in the trie since it is indistinguishable from 1.2.3.4, 
	 * instead 1.2.3.4/32 is converted to 1.2.3.4 when inserted into the trie.
	 * <p>
	 * When comparing 0.0.0.0/0, which has no prefix, to other addresses, the first bit in the other address determines the ordering.
	 * If 1 it is larger and if 0 it is smaller than 0.0.0.0/0.
	 * 
	 * 
	 * @author scfoley
	 *
	 * @param <E>
	 */
	public static class AddressComparator<E extends Address> implements Comparator<E>, Serializable {

		private static final long serialVersionUID = 1L;

		@Override
		public int compare(E o1, E o2) {
			if(o1 == o2) {
				return 0;
			}
			int segmentCount = o1.getSegmentCount();
			int bitsPerSegment = o1.getBitsPerSegment();
			Integer o1Pref = o1.getPrefixLength();
			Integer o2Pref = o2.getPrefixLength();
			int bitsMatchedSoFar = 0;
			int i = 0;
			while(true) {
				AddressSegment segment1 = o1.getSegment(i);
				AddressSegment segment2 = o2.getSegment(i);
				Integer pref1 = getSegmentPrefLen(o1, o1Pref, bitsPerSegment, bitsMatchedSoFar, segment1);
				Integer pref2 = getSegmentPrefLen(o2, o2Pref, bitsPerSegment, bitsMatchedSoFar, segment2);
				int segmentPref2;
				if(pref1 != null) {
					int segmentPref1 = pref1;
					if(pref2 != null && (segmentPref2 = pref2) <= segmentPref1) {
						int matchingBits = getMatchingBits(segment1, segment2, segmentPref2, bitsPerSegment);
						if(matchingBits >= segmentPref2) {
							if(segmentPref2 == segmentPref1) {
								// same prefix block
								return 0;
							}
							// segmentPref2 is shorter prefix, prefix bits match, so depends on bit at index segmentPref2
							return segment1.isOneBit(segmentPref2) ? 1 : -1;
						}
						return segment1.getSegmentValue() - segment2.getSegmentValue();
					} else {
						int matchingBits = getMatchingBits(segment1, segment2, segmentPref1, bitsPerSegment);
						if(matchingBits >= segmentPref1) {
							if(segmentPref1 < bitsPerSegment) {
								return segment2.isOneBit(segmentPref1) ? -1 : 1;
							} else if(++i == segmentCount) {
								return 1; // o1 with prefix length matching bit count is the bigger
							} // else must check the next segment
						} else {
							return segment1.getSegmentValue() - segment2.getSegmentValue();
						}
					}
				} else if(pref2 != null) {
					segmentPref2 = pref2;
					int matchingBits = getMatchingBits(segment1, segment2, segmentPref2, bitsPerSegment);
					if(matchingBits >= pref2) {
						if(segmentPref2 < bitsPerSegment) {
							return segment1.isOneBit(segmentPref2) ? 1 : -1;
						} else if(++i == segmentCount) {
							return -1; // o2 with prefix length matching bit count is the bigger
						} // else must check the next segment
					} else {
						return segment1.getSegmentValue() - segment2.getSegmentValue();
					}
				} else {
					int matchingBits = getMatchingBits(segment1, segment2, bitsPerSegment, bitsPerSegment);
					if(matchingBits < bitsPerSegment) { // no match - the current subnet/address is not here
						return segment1.getSegmentValue() - segment2.getSegmentValue();
					} else if(++i == segmentCount) {
						// same address
						return 0;
					} // else must check the next segment
				}
				bitsMatchedSoFar += bitsPerSegment;
			}
		}
	}

	/**
	 * Returns the next address according to the trie ordering
	 * 
	 * @param <E>
	 * @param addr
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public static <E extends Address> E increment(E addr) {
		if(addr.isMax()) {
			return null;
		}
		if(addr.isIPAddress()) {
			IPAddress ipaddr = addr.toIPAddress();
			if(addr.isPrefixed()) {
				return (E) ipaddr.getUpper().setPrefixLength(ipaddr.getPrefixLength() + 1).toZeroHost();
			}
			return (E) ipaddr.toPrefixBlock(ipaddr.getBitCount() - (ipaddr.getTrailingBitCount(false) + 1));
		}
		
		if(addr.isPrefixed()) {
			return (E) addr.getUpper().setPrefixLength(addr.getPrefixLength() + 1).toPrefixBlock().getLower();
		}
		int trailingBitCount = 0;
		for(int i = addr.getSegmentCount() - 1; i >= 0; i--) {
			AddressSegment seg = addr.getSegment(i);
			if(!seg.isMax()) {
				trailingBitCount += Integer.numberOfTrailingZeros(~seg.getSegmentValue());
				break;
			}
			trailingBitCount += seg.getBitCount();
		}
		return (E) addr.setPrefixLength(addr.getBitCount() - (trailingBitCount + 1)).toPrefixBlock();
	}

	/**
	 * Returns the previous address according to the trie ordering
	 * 
	 * @param <E>
	 * @param addr
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public static <E extends Address> E decrement(E addr) {
		if(addr.isZero()) {
			return null;
		}
		if(addr.isIPAddress()) {
			IPAddress ipaddr = addr.toIPAddress();
			if(addr.isPrefixed()) {
				return (E) ipaddr.getLower().setPrefixLength(ipaddr.getPrefixLength() + 1).toMaxHost();
			}
			return (E) ipaddr.toPrefixBlock(ipaddr.getBitCount() - (ipaddr.getTrailingBitCount(true) + 1));
		}
		
		if(addr.isPrefixed()) {
			return (E) addr.getLower().setPrefixLength(addr.getPrefixLength() + 1).toPrefixBlock().getUpper();
		}
		int trailingBitCount = 0;
		for(int i = addr.getSegmentCount() - 1; i >= 0; i--) {
			AddressSegment seg = addr.getSegment(i);
			if(!seg.isZero()) {
				trailingBitCount += Integer.numberOfTrailingZeros(seg.getSegmentValue());
				break;
			}
			trailingBitCount += seg.getBitCount();
		}
		return (E) addr.setPrefixLength(addr.getBitCount() - (trailingBitCount + 1)).toPrefixBlock();
	}

	public static class TrieComparator<E extends Address> implements Comparator<BinaryTreeNode<E>>, Serializable {

		private static final long serialVersionUID = 1L;

		Comparator<E> comparator;

		TrieComparator(Comparator<E> comparator) {
			this.comparator = comparator;
		}

		@Override
		public int compare(BinaryTreeNode<E> tree1, BinaryTreeNode<E> tree2) {
			E o1 = tree1.getKey();
			E o2 = tree2.getKey();
			return comparator.compare(o1, o2);
		}
	};

	/**
	 * A node for a compact binary prefix trie whose elements are prefix block subnets or addresses,
	 * 
	 * @author scfoley
	 *
	 * @param <E>
	 */
	public static abstract class TrieNode<E extends Address> extends BinaryTreeNode<E> implements AddressTrieOps<E> {

		private static final long serialVersionUID = 1L;

		protected TrieNode(E item) {
			super(item);
		}

		/**
		 * Returns the node for the subnet block containing this node.
		 * 
		 * @return
		 */
		@Override
		public TrieNode<E> getParent() {
			return (TrieNode<E>) super.getParent();
		}

		/**
		 * Returns the sub-node whose address is largest in value
		 * 
		 * @return
		 */
		@Override
		public TrieNode<E> getUpperSubNode() {
			return (TrieNode<E>) super.getUpperSubNode();
		}

		/**
		 * Returns the sub node whose address is smallest in value
		 * 
		 * @return
		 */
		@Override
		public TrieNode<E> getLowerSubNode() {
			return (TrieNode<E>) super.getLowerSubNode();
		}

		private TrieNode<E> findNodeNear(E addr, boolean below, boolean exclusive) {
			addr = checkBlockOrAddress(addr, true);
			return findNodeNearNoCheck(addr, below, exclusive);
		}
		
		private TrieNode<E> findNodeNearNoCheck(E addr, boolean below, boolean exclusive) {
			OpResult<E> result = new OpResult<>(addr, below, exclusive);
			matchBits(result);
			TrieNode<E> backtrack = result.backtrackNode;
			if(backtrack != null) {
				TrieNode<E> parent = backtrack.getParent();
				while(parent != null && 
						(backtrack == (below ? parent.getLowerSubNode() : parent.getUpperSubNode()))) {
					backtrack = parent;
					parent = backtrack.getParent();
				}
				
				if(parent != null) {
					if(parent.isAdded()) {
						result.nearestNode = parent;
					} else {
						result.nearestNode = (below ? parent.previousAddedNode() : parent.nextAddedNode());
					}
				}
			}
			return result.nearestNode;
		}

		@Override
		public TrieNode<E> previousAddedNode() {
			return (TrieNode<E>) super.previousAddedNode();
		}

		@Override
		public TrieNode<E> nextAddedNode() {
			return (TrieNode<E>) super.nextAddedNode();
		}

		@Override
		public TrieNode<E> nextNode() {
			return (TrieNode<E>) super.nextNode();
		}

		@Override
		public TrieNode<E> previousNode() {
			return (TrieNode<E>) super.previousNode();
		}

		@Override
		public TrieNode<E> firstNode() {
			return (TrieNode<E>) super.firstNode();
		}

		@Override
		public TrieNode<E> firstAddedNode() {
			return (TrieNode<E>) super.firstAddedNode();
		}

		@Override
		public TrieNode<E> lastNode() {
			return (TrieNode<E>) super.lastNode();
		}

		@Override
		public TrieNode<E> lastAddedNode() {
			return (TrieNode<E>) super.lastAddedNode();
		}

		@Override
		public TrieNode<E> lowerAddedNode(E addr) {
			return findNodeNear(addr, true, true);
		}

		TrieNode<E> lowerNodeNoCheck(E addr) {
			return findNodeNearNoCheck(addr, true, true);
		}

		@Override
		public E lower(E addr) {
			return getNodeKey(lowerAddedNode(addr));
		}

		@Override
		public TrieNode<E> floorAddedNode(E addr) {
			return findNodeNear(addr, true, false);
		}

		TrieNode<E> floorNodeNoCheck(E addr) {
			return findNodeNearNoCheck(addr, true, false);
		}

		@Override
		public E floor(E addr) {
			return getNodeKey(floorAddedNode(addr));
		}

		@Override
		public TrieNode<E> higherAddedNode(E addr) {
			return findNodeNear(addr, false, true);
		}

		TrieNode<E> higherNodeNoCheck(E addr) {
			return findNodeNearNoCheck(addr, false, true);
		}

		@Override
		public E higher(E addr) {
			return getNodeKey(higherAddedNode(addr));
		}

		@Override
		public TrieNode<E> ceilingAddedNode(E addr) {
			return findNodeNear(addr, false, false);
		}

		TrieNode<E> ceilingNodeNoCheck(E addr) {
			return findNodeNearNoCheck(addr, false, false);
		}

		@Override
		public E ceiling(E addr) {
			return getNodeKey(ceilingAddedNode(addr));
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<? extends TrieNode<E>> nodeIterator(boolean forward) {
			return (Iterator<? extends TrieNode<E>>) super.nodeIterator(forward);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<? extends TrieNode<E>> allNodeIterator(boolean forward) {
			return (Iterator<? extends TrieNode<E>>) super.allNodeIterator(forward);
		}

		/**
		 * Iterates the added nodes, ordered by keys from largest prefix blocks to smallest and then to individual addresses,
		 *  in the sub-trie with this node as the root.
		 * <p>
		 * This iterator supports the {@link java.util.Iterator#remove()} operation.
		 * 
		 * @param lowerSubNodeFirst if true, for blocks of equal size the lower is first, otherwise the reverse order
		 * @return
		 */
		@SuppressWarnings("unchecked")
		public Iterator<? extends TrieNode<E>> blockSizeNodeIterator(boolean lowerSubNodeFirst) {
			return (Iterator<? extends TrieNode<E>>) super.blockSizeNodeIterator(lowerSubNodeFirst, true);
		}

		/**
		 * Iterates all the nodes, ordered by keys from largest prefix blocks to smallest and then to individual addresses,
		 *  in the sub-trie with this node as the root.
		 * <p>
		 * This iterator supports the {@link java.util.Iterator#remove()} operation.
		 * 
		 * @param lowerSubNodeFirst if true, for blocks of equal size the lower is first, otherwise the reverse order
		 * @return
		 */
		@SuppressWarnings("unchecked")
		public Iterator<? extends TrieNode<E>> blockSizeAllNodeIterator(boolean lowerSubNodeFirst) {
			return (Iterator<? extends TrieNode<E>>) super.blockSizeNodeIterator(lowerSubNodeFirst, false);
		}

		/**
		 * Iterates all nodes, ordered by keys from largest prefix blocks to smallest and then to individual addresses,
		 *  in the sub-trie with this node as the root.
		 * 
		 * @return
		 */
		@SuppressWarnings("unchecked")
		@Override
		public <C> CachingIterator<? extends TrieNode<E>, E, C> blockSizeCachingAllNodeIterator() {
			return (CachingIterator<? extends TrieNode<E>, E, C>) super.blockSizeCachingAllNodeIterator();
		}

		@SuppressWarnings("unchecked")
		@Override
		public <C> CachingIterator<? extends TrieNode<E>, E, C> containingFirstIterator(boolean forwardSubNodeOrder) {
			return (CachingIterator<? extends TrieNode<E>, E, C>) super.containingFirstIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public <C> CachingIterator<? extends TrieNode<E>, E, C> containingFirstAllNodeIterator(boolean forwardSubNodeOrder) {
			return (CachingIterator<? extends TrieNode<E>, E, C>) super.containingFirstAllNodeIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<? extends TrieNode<E>> containedFirstIterator(boolean forwardSubNodeOrder) {
			return (Iterator<? extends TrieNode<E>>) super.containedFirstIterator(forwardSubNodeOrder);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<? extends TrieNode<E>> containedFirstAllNodeIterator(boolean forwardSubNodeOrder) {
			return (Iterator<? extends TrieNode<E>>) super.containedFirstAllNodeIterator(forwardSubNodeOrder);
		}

		@Override
		public Spliterator<? extends TrieNode<E>> nodeSpliterator(boolean forward) {
			return nodeSpliterator(forward, true);
		}

		@Override
		public Spliterator<? extends TrieNode<E>> allNodeSpliterator(boolean forward) {
			return nodeSpliterator(forward, false);
		}

		@SuppressWarnings("unchecked")
		Spliterator<? extends TrieNode<E>> nodeSpliterator(boolean forward, boolean addedNodesOnly) {
			Comparator<BinaryTreeNode<E>> comp = forward ? nodeComparator() : reverseNodeComparator();
			Spliterator<? extends BinaryTreeNode<E>> spliterator = new NodeSpliterator<E>(
					forward,
					comp,
					this,
					forward ? firstNode() : lastNode(),
					getParent(),
					size(),
					changeTracker,
					addedNodesOnly /* added only */);
			return (Spliterator<? extends TrieNode<E>>) spliterator;
		}

		@Override
		public Spliterator<E> spliterator() {
			return new KeySpliterator<E>(nodeSpliterator(true, true), comparator());
		}

		@Override
		public Spliterator<E> descendingSpliterator() {
			return new KeySpliterator<E>(nodeSpliterator(false, true), reverseComparator());
		}

		@Override
		public boolean contains(E addr) {
			return doLookup(addr).exists;
		}

		@Override
		public boolean remove(E addr) {
			addr = checkBlockOrAddress(addr, true);
			OpResult<E> result = new OpResult<>(addr, Operation.INSERTED_DELETE);
			matchBits(result);
			return result.exists;
		}

		@Override
		public TrieNode<E> getNode(E addr) {
			return doLookup(addr).existingNode;
		}

		@Override
		public TrieNode<E> removeElementsContainedBy(E addr) {
			addr = checkBlockOrAddress(addr, true);
			OpResult<E> result = new OpResult<>(addr, Operation.SUBTREE_DELETE);
			matchBits(result);
			return result.deleted;
		}

		@Override
		public TrieNode<E> elementsContainedBy(E addr) {
			return doLookup(addr).containedBy;
		}

		// only added nodes are added to the linked list
		@Override
		public TrieNode<E> elementsContaining(E addr) {
			addr = checkBlockOrAddress(addr, true);
			OpResult<E> result = new OpResult<>(addr, Operation.ALL_CONTAINING);
			matchBits(result);
			return result.getContaining();
		}

		@Override
		public E longestPrefixMatch(E addr) {
			TrieNode<E> node = longestPrefixMatchNode(addr);
			return node == null ? null : node.getKey();
		}

		@Override
		public TrieNode<E> longestPrefixMatchNode(E addr) {
			return doLookup(addr).smallestContaining;
		}

		@Override
		public E shortestPrefixMatch(E addr) {
			TrieNode<E> node = shortestPrefixMatchNode(addr);
			return node == null ? null : node.getKey();
		}

		@Override
		public TrieNode<E> shortestPrefixMatchNode(E addr) {
			return doElementContains(addr);
		}

		@Override
		public boolean elementContains(E addr) {
			return doElementContains(addr) != null;
		}

		private TrieNode<E> doElementContains(E addr) {
			addr = checkBlockOrAddress(addr, true);
			OpResult<E> result = new OpResult<>(addr, Operation.CONTAINING);
			matchBits(result);
			return result.largestContaining;
		}

		protected OpResult<E> doLookup(E addr) {
			addr = checkBlockOrAddress(addr, true);
			OpResult<E> result = new OpResult<>(addr, Operation.LOOKUP);
			matchBits(result);
			return result;
		}

		private void removeSubtree(OpResult<E> result) {
			result.deleted = this;
			clear();
		}

		protected void removeOp(OpResult<E> result) {
			result.deleted = this;
			remove();
		}

		void matchBits(OpResult<E> result) {
			matchBitsFromIndex(0, result);
		}

		// traverses the tree, matching bits with prefix block nodes, until we can match no longer,
		// at which point it completes the operation, whatever that operation is
		void matchBitsFromIndex(int bitIndex, OpResult<E> result) {
			TrieNode<E> matchNode = this; 

			E newAddr = result.addr;
			Operation op = result.op;

			TrieKeyData newKeyData = getTrieKeyCache(newAddr);
			boolean simpleMatch = newKeyData != null && op != Operation.INSERT && op != Operation.NEAR && op != Operation.REMAP;

			E existingAddr = getKey();

			while(true) {
				result.node = matchNode;
				boolean continueToNext = matchAddressBits(simpleMatch, newAddr, existingAddr, bitIndex, result, newKeyData);
				if(continueToNext) {
					int bits = existingAddr.getPrefixLength();

					// matched all node bits up the given count, so move into sub-nodes
					matchNode = matchNode.matchSubNode(bits, result);
					if(matchNode == null) {
						// reached the end of the line
						break;
					}
					// Matched a sub-node.  
					// The sub-node was chosen according to the next bit. 
					// That bit is therefore now a match,
					// so increment the matched bits by 1, and keep going.
					bitIndex = bits + 1;
					existingAddr = matchNode.getKey();
				} else {
					break;
				}
			}
			result.node = null;
		}

		static interface FollowingBits {
			void setFollowingBits(long bits);
		}

		static interface KeyCompareResult {
			void bitsMatch();

			void bitsDoNotMatch(int matchedBits);

			// When this is called, if the returned value is non-null, 
			// then setFollowingBits must be called on the returned instance with either zero or a non-zero value
			// to indicate if the next bit following the prefix length of the node's address is 0 or 1 in the supplied address.
			FollowingBits bitsMatchPartially();
		}
		
		// Providing TrieKeyData for trie keys makes lookup faster.
		// However, it is optional, tries will work without it.
		protected static class TrieKeyData {
			// currently trie optimizations exist for 32 or 128 bits,
			// so providing TrieKeyData for other bit sizes provides no benefit at this time

			public Integer prefixLength;

			// 32 bit key caches must override these 4 methods:
			public boolean is32Bits() {
				return false;
			}

			public int getUint32Val() {
				return 0;
			}

			public int getMask32Val() {
				return 0;
			}

			public int getNextBitMask32Val() {
				return 0;
			}

			// 128 bit key caches must override these 6 methods:
			public boolean is128Bits() {
				return false;
			}

			public long getUint64LowVal() {
				return 0;
			}

			public long getUint64HighVal() {
				return 0;
			}

			public long getMask64HighVal() {
				return 0;
			}

			public long getMask64LowVal() {
				return 0;
			}

			public long getNextBitMask64Val() {
				return 0;
			}
		}

		protected TrieKeyData getTrieKeyCache(E addr) {
			return null;
		}
	
		boolean matchAddressBits(boolean simpleSearch, E newAddr, E existingAddr, int bitIndex, TrieNode.KeyCompareResult handleMatch, TrieKeyData newTrieCache)  {
			
			// this is the optimized path for the case where we do not need to know how many of the initial bits match in a mismatch
			// when we have a match, all bits match
			// when we have a mismatch, we do not need to know how many of the initial bits match
			// So there is no callback for a mismatch here.

			// The non-optimized code has 8 cases, 2 for each fully nested if or else block
			// I have added comments to see how this code matches up to those 8 cases

			if(simpleSearch) {
				TrieKeyData existingTrieCache = getTrieKeyCache(existingAddr);
				if(existingTrieCache != null) {
					if(existingTrieCache.is32Bits()) {
						if(newTrieCache.is32Bits()) {
							int existingVal = existingTrieCache.getUint32Val();
							Integer existingPrefLen = existingTrieCache.prefixLength;
							if(existingPrefLen == null) {
								int newVal = newTrieCache.getUint32Val();
								if(newVal == existingVal) {
									handleMatch.bitsMatch();
								} else {
									Integer newPrefLen = newTrieCache.prefixLength;
									if(newPrefLen != null) {
										int newMask = newTrieCache.getMask32Val();
										if((newVal & newMask) == (existingVal & newMask)) {
											// rest of case 1 and rest of case 5
											handleMatch.bitsMatch();
										}
									}
								}
							} else {
								int existingPrefLenBits = existingPrefLen;
								Integer newPrefLen = newTrieCache.prefixLength;
								if(existingPrefLenBits == 0) {
									if(newPrefLen != null && newPrefLen == 0) {
										handleMatch.bitsMatch();
									} else {
										FollowingBits followingBits = handleMatch.bitsMatchPartially();
										if(followingBits != null) {
											followingBits.setFollowingBits(newTrieCache.getUint32Val() & 0x80000000);
											return true;
										}
									}
								} else if(existingPrefLenBits == bitIndex) { // optimized case where no matching is required because bit index had advanced by just one
									if(newPrefLen != null && existingPrefLenBits >= newPrefLen) {
										handleMatch.bitsMatch();
									} else {
										FollowingBits followingBits = handleMatch.bitsMatchPartially();
										if(followingBits != null) {
											int nextBitMask = existingTrieCache.getNextBitMask32Val();
											followingBits.setFollowingBits(newTrieCache.getUint32Val() & nextBitMask);
											return true;
										}
									}
								} else {
									int existingMask = existingTrieCache.getMask32Val();
									int newVal = newTrieCache.getUint32Val();
									if((newVal & existingMask) == (existingVal & existingMask)) {
										if(newPrefLen != null && existingPrefLenBits >= newPrefLen) {
											handleMatch.bitsMatch();
										} else {
											FollowingBits followingBits = handleMatch.bitsMatchPartially();
											if(followingBits != null) {
												int nextBitMask = existingTrieCache.getNextBitMask32Val();
												followingBits.setFollowingBits(newVal & nextBitMask);
												return true;
											}
										}
									} else if(newPrefLen != null) {
										int newPrefLenBits = newPrefLen;
										if(existingPrefLenBits > newPrefLenBits) {
											int newMask = newTrieCache.getMask32Val();
											if((newTrieCache.getUint32Val() & newMask) == (existingVal & newMask)) {
												// rest of case 1 and rest of case 5
												handleMatch.bitsMatch();
											}
										}
									} // else case 4, 7
								}
							}
							return false;
						}
					} else if(existingTrieCache.is128Bits()) {
						if(newTrieCache != null && newTrieCache.is128Bits()) {
							Integer existingPrefLen = existingTrieCache.prefixLength;
							if(existingPrefLen == null) {
								long newLowVal = newTrieCache.getUint64LowVal();
								long existingLowVal = existingTrieCache.getUint64LowVal();
								if(newLowVal == existingLowVal &&
									newTrieCache.getUint64HighVal() == existingTrieCache.getUint64HighVal()) {
									handleMatch.bitsMatch();
								} else {
									Integer newPrefLen = newTrieCache.prefixLength;
									if(newPrefLen != null) {
										long newMaskLow = newTrieCache.getMask64LowVal();
										if((newLowVal & newMaskLow) == (existingLowVal & newMaskLow)) {
											long newMaskHigh = newTrieCache.getMask64HighVal();
											if((newTrieCache.getUint64HighVal() & newMaskHigh) == (existingTrieCache.getUint64HighVal() & newMaskHigh)) {
												// rest of case 1 and rest of case 5
												handleMatch.bitsMatch();
											}
										}
									} // else case 4, 7
								}
							} else {
								int existingPrefLenBits = existingPrefLen;
								Integer newPrefLen = newTrieCache.prefixLength;
								if(existingPrefLenBits == 0) {
									if(newPrefLen != null && newPrefLen == 0) {
										handleMatch.bitsMatch();
									} else {
										FollowingBits followingBits = handleMatch.bitsMatchPartially();
										if(followingBits != null) {
											followingBits.setFollowingBits(newTrieCache.getUint64HighVal() & 0x8000000000000000L);
											return true;
										}
									}
								} else if(existingPrefLenBits == bitIndex) { // optimized case where no matching is required because bit index had advanced by just one
									if(newPrefLen != null && existingPrefLenBits >= newPrefLen) {
										handleMatch.bitsMatch();
									} else {
										FollowingBits followingBits = handleMatch.bitsMatchPartially();
										if(followingBits != null) {
											long nextBitMask = existingTrieCache.getNextBitMask64Val();
											if(bitIndex > 63) /* IPv6BitCount - 65 */ {
												followingBits.setFollowingBits(newTrieCache.getUint64LowVal() & nextBitMask);
											} else {
												followingBits.setFollowingBits(newTrieCache.getUint64HighVal() & nextBitMask);
											}
											return true;
										}
									}
								} else if(existingPrefLenBits > 64) {
									long existingMaskLow = existingTrieCache.getMask64LowVal();
									long newLowVal = newTrieCache.getUint64LowVal();
									if((newLowVal & existingMaskLow) == (existingTrieCache.getUint64LowVal() & existingMaskLow)) {
										long existingMaskHigh = existingTrieCache.getMask64HighVal();
										if((newTrieCache.getUint64HighVal() & existingMaskHigh) == (existingTrieCache.getUint64HighVal() & existingMaskHigh)) {
											if(newPrefLen != null && existingPrefLenBits >= newPrefLen) {
												handleMatch.bitsMatch();
											} else {
												FollowingBits followingBits = handleMatch.bitsMatchPartially();
												if(followingBits != null) {
													long nextBitMask = existingTrieCache.getNextBitMask64Val();
													followingBits.setFollowingBits(newLowVal & nextBitMask);
													return true;
												}
											}
										} else if(newPrefLen != null && existingPrefLenBits > newPrefLen) {
											long newMaskLow = newTrieCache.getMask64LowVal();
											if((newTrieCache.getUint64LowVal() & newMaskLow) == (existingTrieCache.getUint64LowVal() & newMaskLow)) {
												long newMaskHigh = newTrieCache.getMask64HighVal();
												if((newTrieCache.getUint64HighVal() & newMaskHigh) == (existingTrieCache.getUint64HighVal() & newMaskHigh)) {
													// rest of case 1 and rest of case 5
													handleMatch.bitsMatch();
												}
											}
										} // else case 4, 7
									} else if(newPrefLen != null && existingPrefLenBits > newPrefLen) {
										long newMaskLow = newTrieCache.getMask64LowVal();
										if((newTrieCache.getUint64LowVal()&newMaskLow) == (existingTrieCache.getUint64LowVal()&newMaskLow)) {
											long newMaskHigh = newTrieCache.getMask64HighVal();
											if((newTrieCache.getUint64HighVal() & newMaskHigh) == (existingTrieCache.getUint64HighVal() & newMaskHigh)) {
												// rest of case 1 and rest of case 5
												handleMatch.bitsMatch();
											}
										}
									} // else case 4, 7
								} else if(existingPrefLenBits == 64) {
									if(newTrieCache.getUint64HighVal() == existingTrieCache.getUint64HighVal()) {
										if(newPrefLen != null && newPrefLen <= 64) {
											handleMatch.bitsMatch();
										} else {
											FollowingBits followingBits = handleMatch.bitsMatchPartially();
											if(followingBits != null) {
												followingBits.setFollowingBits(newTrieCache.getUint64LowVal() & 0x8000000000000000L);
												return true;
											}
										}
									} else {
										if(newPrefLen != null && newPrefLen < 64) {
											long newMaskHigh = newTrieCache.getMask64HighVal();
											if((newTrieCache.getUint64HighVal() & newMaskHigh) == (existingTrieCache.getUint64HighVal() & newMaskHigh)) {
												// rest of case 1 and rest of case 5
												handleMatch.bitsMatch();
											}
										}
									} // else case 4, 7
								} else { // existingPrefLen < 64
									long existingMaskHigh = existingTrieCache.getMask64HighVal();
									long newHighVal = newTrieCache.getUint64HighVal();
									if((newHighVal & existingMaskHigh) == (existingTrieCache.getUint64HighVal() & existingMaskHigh)) {
										if(newPrefLen != null && existingPrefLenBits >= newPrefLen) {
											handleMatch.bitsMatch();
										} else {
											FollowingBits followingBits = handleMatch.bitsMatchPartially();
											if(followingBits != null) {
												long nextBitMask = existingTrieCache.getNextBitMask64Val();
												followingBits.setFollowingBits(newHighVal & nextBitMask);
												return true;
											}
										}
									} else if(newPrefLen != null && existingPrefLenBits > newPrefLen) {
										long newMaskHigh = newTrieCache.getMask64HighVal();
										if((newTrieCache.getUint64HighVal() & newMaskHigh) == (existingTrieCache.getUint64HighVal() & newMaskHigh)) {
											// rest of case 1 and rest of case 5
											handleMatch.bitsMatch();
										}
									} // else case 4, 7
								}
							}
							return false;
						}
					}
				}
			}

			int bitsPerSegment = existingAddr.getBitsPerSegment();
			int bytesPerSegment = existingAddr.getBytesPerSegment();
			int segmentIndex = ParsedAddressGrouping.getHostSegmentIndex(bitIndex, bytesPerSegment, bitsPerSegment);
			int segmentCount = existingAddr.getSegmentCount();
			if(newAddr.getSegmentCount() != segmentCount || bitsPerSegment != newAddr.getBitsPerSegment()) {
				throw new IllegalArgumentException(getMessage("ipaddress.error.mismatched.bit.size"));
			}
			Integer existingPref = existingAddr.getPrefixLength();
			Integer newPrefLen = newAddr.getPrefixLength();

			// this block handles cases like where we matched matching ::ffff:102:304 to ::ffff:102:304/127,
			// and we found a subnode to match, but we know the final bit is a match due to the subnode being lower or upper,
			// so there is actually not more bits to match
			if(segmentIndex >= segmentCount) {
				// all the bits match
				handleMatch.bitsMatch();
				return false;
			}

			int bitsMatchedSoFar = ParsedAddressGrouping.getTotalBits(segmentIndex, bytesPerSegment, bitsPerSegment);
			while(true) {
				AddressSegment existingSegment = existingAddr.getSegment(segmentIndex);
				AddressSegment newSegment = newAddr.getSegment(segmentIndex);
				Integer segmentPref = getSegmentPrefLen(existingAddr, existingPref, bitsPerSegment, bitsMatchedSoFar, existingSegment);
				Integer newSegmentPref = getSegmentPrefLen(newAddr, newPrefLen, bitsPerSegment, bitsMatchedSoFar, newSegment);
				int newPrefixLen;
				if(segmentPref != null) {	
					int segmentPrefLen = segmentPref;
					if(newSegmentPref != null && (newPrefixLen = newSegmentPref) <= segmentPrefLen) {
						int matchingBits = getMatchingBits(existingSegment, newSegment, newPrefixLen, bitsPerSegment);
						if(matchingBits >= newPrefixLen) { 
							handleMatch.bitsMatch();
						} else {
							// no match - the bits don't match
							// matchingBits < newPrefLen < segmentPrefLen
							handleMatch.bitsDoNotMatch(bitsMatchedSoFar + matchingBits);
						}
					} else {
						int matchingBits = getMatchingBits(existingSegment, newSegment, segmentPrefLen, bitsPerSegment);
						if(matchingBits >= segmentPrefLen) { // match - the current subnet/address is a match so far, and we must go further to check smaller subnets
							FollowingBits followingBits = handleMatch.bitsMatchPartially();
							if(followingBits != null) {
								// calculate the followingBitsFlag

								// check if at end of segment, advance to next if so
								if(segmentPrefLen == bitsPerSegment) {
									segmentIndex++;
									if(segmentIndex == segmentCount) {
										return true;
									}
									newSegment = newAddr.getSegment(segmentIndex);
									segmentPrefLen = 0;
								}

								// check the bit for followingBitsFlag
								if(newSegment.isOneBit(segmentPrefLen)) {
									followingBits.setFollowingBits(0x8000000000000000L);
								}
								return true;
							}
							return false;
						}
						// matchingBits < segmentPrefLen - no match - the bits in current prefix do not match the prefix of the existing address
						handleMatch.bitsDoNotMatch(bitsMatchedSoFar + matchingBits);
					}
					return false;
				} else if(newSegmentPref != null) {
					newPrefixLen = newSegmentPref;
					int matchingBits = getMatchingBits(existingSegment, newSegment, newPrefixLen, bitsPerSegment);
					if(matchingBits >= newPrefixLen) { // the current bits match the current prefix, but the existing has no prefix
						handleMatch.bitsMatch();
					} else {
						// no match - the current subnet does not match the existing address
						handleMatch.bitsDoNotMatch(bitsMatchedSoFar + matchingBits);
					}
					return false;
				} else {
					int matchingBits = getMatchingBits(existingSegment, newSegment, bitsPerSegment, bitsPerSegment);
					if(matchingBits < bitsPerSegment) { // no match - the current subnet/address is not here
						handleMatch.bitsDoNotMatch(bitsMatchedSoFar + matchingBits);
						return false;
					} else if(++segmentIndex == segmentCount) { // match - the current subnet/address is a match
						// note that "added" is already true here, we can only be here if explicitly inserted already since it is a non-prefixed full address
						handleMatch.bitsMatch();
						return false;
					}
					bitsMatchedSoFar += bitsPerSegment;
				}
			}
		}

		private void handleContained(OpResult<E> result, int newPref) {
			Operation op = result.op;
			if(op == Operation.INSERT) {
				// if we have 1.2.3.4 and 1.2.3.4/32, and we are looking at the last segment,
				// then there are no more bits to look at, and this makes the former a sub-node of the latter.
				// In most cases, however, there are more bits in existingAddr, the latter, to look at.
				replace(result, newPref);
			} else  if(op == Operation.SUBTREE_DELETE) {
				removeSubtree(result);
			} else if(op == Operation.NEAR) {
				findNearest(result, newPref);
			} else if(op == Operation.REMAP) {
				remapNonExistingReplace(result, newPref);
			} 
		}

		private boolean handleContains(OpResult<E> result) {
			if(result.op == Operation.CONTAINING) {
				result.largestContaining = this;
				return true;
			} else if(result.op == Operation.ALL_CONTAINING) {
				result.addContaining(this);
				return true;
			}
			result.smallestContaining = this;
			return false;
		}

		private void handleSplitNode(OpResult<E> result, int totalMatchingBits) {
			E newAddr = result.addr;
			Operation op = result.op;	
			if(op == Operation.INSERT) {
				split(result, totalMatchingBits, createNew(newAddr));
			} else if(op == Operation.NEAR) {
				findNearest(result, totalMatchingBits);
			} else if(op == Operation.REMAP) {
				remapNonExistingSplit(result, totalMatchingBits);
			} 
		}

		// a node exists for the given key but the node is not added,
		// so not a match, but a split not required
		private void handleNodeMatch(OpResult<E> result) {
			Operation op = result.op;
			if(op == Operation.LOOKUP) {
				result.existingNode = this;
			} else if(op == Operation.INSERT) {
				existingAdded(result);
			} else if(op == Operation.SUBTREE_DELETE) {
				removeSubtree(result);
			} else if(op == Operation.NEAR) {
				findNearestFromMatch(result);
			} else if(op == Operation.REMAP) {
				remapNonAdded(result);
			}
		}

		private void handleMatch(OpResult<E> result) {
			result.exists = true;
			if(!handleContains(result)) {
				Operation op = result.op;
				if(op == Operation.LOOKUP) {
					matched(result);
				} else if(op == Operation.INSERT) {
					matchedInserted(result);
				} else if(op == Operation.INSERTED_DELETE) {
					removeOp(result);
				} else if(op == Operation.SUBTREE_DELETE) {
					removeSubtree(result);
				} else if(op == Operation.NEAR) {
					if(result.nearExclusive) {
						findNearestFromMatch(result);
					} else {
						matched(result);
					}
				} else if(op == Operation.REMAP) {
					remapMatch(result);
				}
			}
		}

		private void remapNonExistingReplace(OpResult<E> result, int totalMatchingBits) {
			if(remap(result, false)) {
				replace(result, totalMatchingBits);
			}
		}

		private void remapNonExistingSplit(OpResult<E> result, int totalMatchingBits) {
			if(remap(result, false)) {
				split(result, totalMatchingBits, createNew(result.addr));
			}
		}

		private TrieNode<E> remapNonExisting(OpResult<E> result) {
			if(remap(result, false)) {
				return createNew(result.addr);
			}
			return null;
		}

		private void remapNonAdded(OpResult<E> result) {
			if(remap(result, false)) {
				existingAdded(result);
			}
		}

		private void remapMatch(OpResult<E> result) {
			result.existingNode = this;
			if(remap(result, true)) {
				matchedInserted(result);
			}
		}

		/**
		 * Remaps the value for a node to a new value.  
		 * This operation, which works on mapped values, is for maps, so this base method here does nothing,
		 * but is overridden in map subclasses.
		 * 
		 * @param result
		 * @param match
		 * @return true if a new node needs to be created (match is null) or added (match is non-null)
		 */
		boolean remap(OpResult<E> result, boolean isMatch) {
			return false;
		}

		// this node matched when doing a lookup
		private void matched(OpResult<E> result) {
			result.existingNode = this;
			result.nearestNode = this;
		}

		// ** overridden by map trie **
		// similar to matched, but when inserting we see it already there.
		// this added node had already been added before
		void matchedInserted(OpResult<E> result) {
			result.existingNode = this;
			result.addedAlready = this;
		}

		// this node previously existed but was not added til now
		private void existingAdded(OpResult<E> result) {
			result.existingNode = this;
			result.added = this;
			added(result);
		}

		// this node is newly inserted and added
		private void inserted(OpResult<E> result) {
			result.inserted = this;
			added(result);
		}

		// ** overridden by map trie **
		void added(OpResult<E> result) {
			setNodeAdded(true);
			adjustCount(1);
			changeTracker.changed();
		}

		/**
		 * The current node and the new node both become sub-nodes of a new block node taking the position of the current node.
		 * 
		 * @param totalMatchingBits
		 * @param newAddr
		 */
		@SuppressWarnings("unchecked")
		private void split(OpResult<E> result, int totalMatchingBits, TrieNode<E> newSubNode) {
			E key = getKey();
			E newBlock;
			if(key.isIPAddress()) {
				newBlock = (E) key.toIPAddress().toPrefixBlock(totalMatchingBits);
			} else {
				newBlock = (E) key.setPrefixLength(totalMatchingBits).toPrefixBlock();
			}
			replaceToSub(newBlock, totalMatchingBits, newSubNode);
			newSubNode.inserted(result);
		}

		/**
		 * The current node is replaced by the new node and becomes a sub-node of the new node.
		 * 
		 * @param totalMatchingBits
		 * @param newAddr
		 */
		private void replace(OpResult<E> result, int totalMatchingBits) {
			result.containedBy = this;
			TrieNode<E> newNode = replaceToSub(result.addr, totalMatchingBits, null);
			newNode.inserted(result);
		}

		/**
		 * The current node is replaced by a new block of the given address.
		 * The current node and given node become sub-nodes.
		 * 
		 * @param newAssignedAddr
		 * @param result
		 * @param totalMatchingBits
		 * @param newSubNode
		 * @return
		 */
		private TrieNode<E> replaceToSub(E newAssignedAddr, int totalMatchingBits, TrieNode<E> newSubNode) {
			TrieNode<E> newNode = createNew(newAssignedAddr);
			newNode.size = size;
			TrieNode<E> parent = getParent();
			if(parent.getUpperSubNode() == this) {
				parent.setUpper(newNode);
			} else if(parent.getLowerSubNode() == this) {
				parent.setLower(newNode);
			}
			E existingAddr = getKey();
			if(totalMatchingBits < existingAddr.getBitCount() && 
					existingAddr.isOneBit(totalMatchingBits)) {
				if(newSubNode != null) {
					newNode.setLower(newSubNode);
				}
				newNode.setUpper(this);
			} else {
				newNode.setLower(this);
				if(newSubNode != null) {
					newNode.setUpper(newSubNode);
				}
			}
			return newNode;
		}

		// only called when lower/higher and not floor/ceiling since for a match ends things for the latter
		private void findNearestFromMatch(OpResult<E> result) {
			if(result.nearestFloor) {
				// looking for greatest element < queried address
				// since we have matched the address, we must go lower again,
				// and if we cannot, we must backtrack
				TrieNode<E> lower = getLowerSubNode();
				if(lower == null) {
					// no nearest node yet
					result.backtrackNode = this;
				} else {
					TrieNode<E> last;
					do {
						last = lower;
						lower = lower.getUpperSubNode();
					} while(lower != null);
					result.nearestNode = last;
				}
			} else {
				// looking for smallest element > queried address
				TrieNode<E> upper = getUpperSubNode();
				if(upper == null) {
					// no nearest node yet
					result.backtrackNode = this;
				} else {
					TrieNode<E> last;
					do {
						last = upper;
						upper = upper.getLowerSubNode();
					} while(upper != null);
					result.nearestNode = last;
				}
			}
		}

		private void findNearest(OpResult<E> result, int differingBitIndex) {
			E thisAddr = getKey();
			if(differingBitIndex < thisAddr.getBitCount() && thisAddr.isOneBit(differingBitIndex)) {
				// this element and all below are > than the query address
				if(result.nearestFloor) {
					// looking for greatest element < or <= queried address, so no need to go further
					// need to backtrack and find the last right turn to find node < than the query address again
					result.backtrackNode = this;
				} else {
					// looking for smallest element > or >= queried address
					TrieNode<E> lower = this, last;
					do {
						last = lower;
						lower = lower.getLowerSubNode();
					} while(lower != null);
					result.nearestNode = last;
				}
			} else {
				// this element and all below are < than the query address
				if(result.nearestFloor) {
					// looking for greatest element < or <= queried address
					TrieNode<E> upper = this, last;
					do {
						last = upper;
						upper = upper.getUpperSubNode();
					} while(upper != null);
					result.nearestNode = last;
				} else {
					// looking for smallest element > or >= queried address, so no need to go further
					// need to backtrack and find the last left turn to find node > than the query address again
					result.backtrackNode = this;
				}
			}
		}

		/**
		 * Initializes the tree with the given node
		 * 
		 * @param node
		 */
		void init(TrieNode<E> node) {
			E newAddr = node.getKey();
			if(newAddr.getBitCount() > 0 && newAddr.isOneBit(0)) {
				setUpper(node);
			} else {
				setLower(node);
			}
			size = (isAdded() ? 1 : 0) + node.size;
		}
		
		private TrieNode<E> matchSubNode(int bitIndex, OpResult<E> result) {
			E newAddr = result.addr;
			if(!FREEZE_ROOT && isEmpty()) {
				if(result.op == Operation.REMAP) {
					remapNonAdded(result);
				} else if(result.op == Operation.INSERT) {
					setKey(newAddr);
					existingAdded(result);
				}
			} else if(bitIndex >= newAddr.getBitCount()) {
				// we matched all bits, yet somehow we are still going
				// this can only happen when matching 1.2.3.4/32 to 1.2.3.4
				// which should never happen and so we do nothing
			} else if(result.followingBits != 0L) {
				result.setFollowingBits(0);
				TrieNode<E> upper = getUpperSubNode();
				if(upper == null) {
					// no match
					Operation op = result.op;
					if(op == Operation.INSERT) {
						upper = createNew(newAddr);
						setUpper(upper);
						upper.inserted(result);
					} else if(op == Operation.NEAR) {
						if(result.nearestFloor) {
							// With only one sub-node at most, normally that would mean this node must be added.
							// But there is one exception, when we are the non-added root node.
							// So must check for added here.
							if(isAdded()) {
								result.nearestNode = this;
							} else {
								// check if our lower sub-node is there and added.  It is underneath addr too.
								// find the highest node in that direction.
								TrieNode<E> lower = getLowerSubNode();
								if(lower != null) {
									TrieNode<E> res = lower;
									TrieNode<E> next = res.getUpperSubNode();
									while(next != null) {
										res = next;
										next = res.getUpperSubNode();
									}
									result.nearestNode = res;
								}
							}
						} else {
							result.backtrackNode = this;
						}
					} else if(op == Operation.REMAP) {
						upper = remapNonExisting(result);
						if(upper != null) {
							setUpper(upper);
							upper.inserted(result);
						}
					}
				} else {
					return upper;
				}
			} else {
				TrieNode<E> lower = getLowerSubNode();
				if(lower == null) {
					// no match
					Operation op = result.op;
					if(op == Operation.INSERT) {
						lower = createNew(newAddr);
						setLower(lower);
						lower.inserted(result);
					} else if(op == Operation.NEAR) {
						if(result.nearestFloor) {
							result.backtrackNode = this;
						} else {
							// With only one sub-node at most, normally that would mean this node must be added.
							// But there is one exception, when we are the non-added root node.
							// So must check for added here.
							if(isAdded()) {
								result.nearestNode = this;
							} else {
								// check if our upper sub-node is there and added.  It is above addr too.
								// find the highest node in that direction.
								TrieNode<E> upper = getUpperSubNode();
								if(upper != null) {
									TrieNode<E> res = upper;
									TrieNode<E> next = res.getLowerSubNode();
									while(next != null) {
										res = next;
										next = res.getLowerSubNode();
									}
									result.nearestNode = res;
								}
							}
						}
					} else if(op == Operation.REMAP) {
						lower = remapNonExisting(result);
						if(lower != null) {
							setLower(lower);
							lower.inserted(result);
						}
					} 
				} else {
					return lower;
				}
			}
			return null;
		}

		private TrieNode<E> createNew(E newAddr) {
			TrieNode<E> newNode = createNewImpl(newAddr);
			newNode.changeTracker = changeTracker;
			return newNode;
		}

		protected abstract TrieNode<E> createNewImpl(E newAddr);
		
		protected abstract AddressTrie<E> createNewTree();

		/**
		 * Creates a new sub-trie, copying the nodes starting with this node as root. 
		 * The nodes are copies of the nodes in this sub-trie, but their keys and values are not copies.
		 */
		public AddressTrie<E> asNewTrie() {
			AddressTrie<E> newTrie = createNewTree();
			newTrie.addTrie(this);
			return newTrie;
		}
		
		@Override
		public TrieNode<E> cloneTree() {
			return (TrieNode<E>) super.cloneTree();
		}

		@Override
		public TrieNode<E> clone() {
			return (TrieNode<E>) super.clone();
		}

		@Override
		TrieNode<E> cloneTreeBounds(Bounds<E> bounds) {
			return (TrieNode<E>) super.cloneTreeBounds(bounds);
		}

		@Override
		public boolean equals(Object o) {
			return o instanceof TrieNode && super.equals(o);
		}
	}

	static final TrieComparator<?> comparator = new TrieComparator<>(new AddressComparator<>());
	static final TrieComparator<?> reverseComparator = new TrieComparator<>(Collections.reverseOrder(new AddressComparator<>()));

	AddressTrieSet<E> set;
	AddressBounds<E> bounds;

	private TrieNode<E> subRoot; // if bounded, the root of the subtrie, which can change
	private Change subRootChange; // if trie was modified since last check for subroot, must check for new subroot

	protected AddressTrie(TrieNode<E> root) {
		super(root);
		root.changeTracker = new ChangeTracker();
	}

	protected AddressTrie(TrieNode<E> root, AddressBounds<E> bounds) {
		super(root);
		if(root.changeTracker == null) {
			root.changeTracker = new ChangeTracker();
		}
		this.bounds = bounds;
	}

	private static Integer getSegmentPrefLen(
			AddressSegmentSeries addr,
			Integer prefLen,
			int bitsPerSegment,
			int bitsMatchedSoFar,
			AddressSegment segment) {
		if(segment instanceof IPAddressSegment) {
			return ((IPAddressSegment) segment).getSegmentPrefixLength();
		} else if(prefLen != null) {
			Integer result = prefLen - bitsMatchedSoFar;
			if(result <= bitsPerSegment) {
				if(result < 0) {
					result = 0;
				}
				return result;
			}
		}
		return null;
	}

	private static int getMatchingBits(AddressSegment segment1, AddressSegment segment2, int maxBits, int bitsPerSegment) {
		if(maxBits == 0) {
			return 0;
		}
		int val1 = segment1.getSegmentValue();
		int val2 = segment2.getSegmentValue();
		int xor = val1 ^ val2;
		switch(bitsPerSegment) {
		case IPv4Address.BITS_PER_SEGMENT:
			return numberOfLeadingZerosByte(xor);
		case IPv6Address.BITS_PER_SEGMENT:
			return numberOfLeadingZerosShort(xor);
		default:
			return Integer.numberOfLeadingZeros(xor) + bitsPerSegment - Integer.SIZE;
		}
	}

	private static int numberOfLeadingZerosShort(int i) {
		int half = i >>> 8;
		if(half == 0) {
			return 8 + numberOfLeadingZerosByte(i & 0xff);
		}
		return numberOfLeadingZerosByte(half);
	}

	private static int numberOfLeadingZerosByte(int i) {
		if (i <= 0) {
			if(i == 0){
				return 8;
			}
			return 0;
		}
		int n = 1;
		if (i >>> 4 == 0) { n += 4; i <<= 4; }
		if (i >>> 6 == 0) { n += 2; i <<= 2; }
		n -= i >>> 7;
		return n;
	}

	@Override
	public boolean isEmpty() {
		if(bounds == null) {
			return super.isEmpty();
		}
		// we avoid calculating size for bounded tries
		return firstAddedNode() == null;
    }

	/**
	 * Returns the number of nodes in the trie, which is more than the number of added elements.
	 * 
	 * @return
	 */
	@Override
	public int nodeSize() {
		if(bounds == null) {
			return super.nodeSize();
		}
		int totalCount = 0;
		Iterator<? extends TrieNode<E>> iterator = allNodeIterator(true);
		while(iterator.hasNext()) {
			totalCount++;
			iterator.next();
		}
		return totalCount;
	}

	@Override
	public int size() {
		if(bounds == null) {
			return super.size();
		}
		int totalCount = 0;
		Iterator<? extends TrieNode<E>> iterator = nodeIterator(true);
		while(iterator.hasNext()) {
			TrieNode<E> node = iterator.next();
			if(node.isAdded() && bounds.isInBounds(node.getKey())) {
				totalCount++;
			}
		}
		return totalCount;
	}
	
	@Override
	public boolean add(E addr) {
		addr = checkBlockOrAddress(addr, true);
		if(bounds != null) {
			if(!bounds.isInBounds(addr)) {
				throwOutOfBounds();
			}
		}
		adjustRoot(addr);
		TrieNode<E> root = absoluteRoot();
		OpResult<E> result = new OpResult<>(addr, Operation.INSERT);
		root.matchBits(result);
		return !result.exists;
	}

	static void throwOutOfBounds() {
		throw new IllegalArgumentException(getMessage("ipaddress.error.address.out.of.range"));
	}

	protected void adjustRoot(E addr) {}

	@Override
	public TrieNode<E> addNode(E addr) {
		addr = checkBlockOrAddress(addr, true);
		if(bounds != null) {
			if(!bounds.isInBounds(addr)) {
				throwOutOfBounds();
			}
		}
		adjustRoot(addr);
		TrieNode<E> root = absoluteRoot();
		OpResult<E> result = new OpResult<>(addr, Operation.INSERT);
		root.matchBits(result);
		TrieNode<E> node = result.existingNode;
		if(node == null) {
			node = result.inserted;
		}
		return node;
	}

	static abstract class SubNodesMapping<E extends Address, N extends SubNodesMapping<E, N>> {
		// subNodes is the list of direct and indirect added sub-nodes in the original trie
		ArrayList<AssociativeTrieNode<E, N>> subNodes;
		
		abstract Object getUnderlyingValue();
	}
	
	protected static class SubNodesMappingBasic<E extends Address> extends SubNodesMapping<E, SubNodesMappingBasic<E>> {
		
		@Override
		Object getUnderlyingValue() {
			return null;
		}
	}
	
	
	/**
	 * Provides an associative trie in which the root and each added node are mapped to a list of their respective direct added nodes.
	 * This trie provides an alternative non-binary tree structure of the added nodes.
	 * It is used by {@link #toAddedNodesTreeString()} to produce a string showing the alternative structure.
	 * If there are no non-added nodes in this trie, then the alternative tree structure provided by this method is the same as the original trie.
	 *
	 * @return
	 */
	public abstract AddedTreeBase<E, ? extends SubNodesMapping<E, ? extends SubNodesMapping<E, ?>>> constructAddedNodesTree(); 

	/**
	* Constructs a trie in which added nodes are mapped to their list of added sub-nodes.
	* This trie provides an alternative non-binary tree structure of the added nodes.
	* It is used by ToAddedNodesTreeString to produce a string showing the alternative structure.
	* If there are no non-added nodes in this trie, 
	* then the alternative tree structure provided by this method is the same as the original trie.
	* 
	* @return
	*/
	protected void contructAddedTree(AssociativeAddressTrie<E, SubNodesMappingBasic<E>> emptyTrie) {
		emptyTrie.addTrie(absoluteRoot()); // does not add values
		
		CachingIterator<? extends AssociativeTrieNode<E, SubNodesMappingBasic<E>>, E, 
				AssociativeTrieNode<E, SubNodesMappingBasic<E>>> cachingIterator =
				emptyTrie.containingFirstAllNodeIterator(true);
		
		while(cachingIterator.hasNext()) {
			AssociativeTrieNode<E, SubNodesMappingBasic<E>> newNext = cachingIterator.next(), parent;
			
			// populate the values from the original trie into the new trie
			newNext.setValue(new SubNodesMappingBasic<E>());
			
			// cache this node with its sub-nodes
			cachingIterator.cacheWithLowerSubNode(newNext);
			cachingIterator.cacheWithUpperSubNode(newNext);
			
			// the cached object is our parent
			if(newNext.isAdded()) {
				parent = cachingIterator.getCached();
				if(parent != null) {
					// find added parent, or the root if no added parent
					// this part would be tricky if we accounted for the bounds,
					// maybe we'd have to filter on the bounds, and also look for the sub-root
					while(!parent.isAdded()) {
						AssociativeTrieNode<E, SubNodesMappingBasic<E>> parentParent = parent.getParent();
						if(parentParent == null) {
							break;
						}
						parent = parentParent;
					}
					// store ourselves with that added parent or root
					SubNodesMappingBasic<E> mappedNodes = parent.getValue();
					ArrayList<AssociativeTrieNode<E, SubNodesMappingBasic<E>>> addedSubs = mappedNodes.subNodes;
					if(addedSubs == null) {
						addedSubs = new ArrayList<AssociativeTrieNode<E, SubNodesMappingBasic<E>>>(newNext.size() - 1);
						mappedNodes.subNodes = addedSubs;
					}
					addedSubs.add(newNext);
				} // else root
			}
		}
		SubNodesMappingBasic<E> value = emptyTrie.getRoot().getValue();
		if(value != null && value.subNodes != null) {
			value.subNodes.trimToSize();
		}
		Iterator<? extends AssociativeTrieNode<E, SubNodesMappingBasic<E>>> iter = emptyTrie.allNodeIterator(true);
		while(iter.hasNext()) {
			SubNodesMappingBasic<E> list = iter.next().getValue();
			if(list != null && list.subNodes != null) {
				list.subNodes.trimToSize();
			}
		}
	}

	/**
	 * Provides a flattened version of the trie showing only the contained added nodes and their containment structure, which is non-binary.
	 * The root node is included, which may or may not be added.
	 * <p>
	 * See {@link #constructAddedNodesTree()}
	 * 
	 * @return
	 */
	public abstract String toAddedNodesTreeString();
	
	protected static <E extends Address, N extends SubNodesMapping<E, N>> String toAddedNodesTreeString(AssociativeAddressTrie<E, N> addedTree) {
		AssociativeTrieNode<E, N> root = addedTree.absoluteRoot();
		return toAddedNodesTreeString(root);
	}
	
	protected static <E extends Address, N extends SubNodesMapping<E, N>> String toAddedNodesTreeString(AssociativeTrieNode<E, N> root) {

		class IndentsNode {
			Indents indents;
			AssociativeTrieNode<E, N> node;

			IndentsNode(Indents indents, AssociativeTrieNode<E, N> node) {
				this.indents = indents;
				this.node = node;
			}
		}
		
		Deque<IndentsNode> stack = null;
		StringBuilder builder = new StringBuilder();
		builder.append('\n');
		AssociativeTrieNode<E, N> nextNode = root;
		String nodeIndent = "", subNodeIndent = "";
		IndentsNode nextItem;
		while(true) {
			SubNodesMapping<E, N> nextNodeList = nextNode.getValue();
			TrieNode.toNodeString(builder.append(nodeIndent), nextNode.isAdded(), nextNode.getKey(), nextNodeList.getUnderlyingValue()).append('\n');

			ArrayList<AssociativeTrieNode<E, N>> nextNodes = nextNodeList.subNodes;

			if(nextNodes != null && nextNodes.size() > 0) {
				
				AssociativeTrieNode<E, N> nNode, next;

				int i = nextNodes.size() - 1;
				Indents lastIndents = new Indents(
						subNodeIndent + BinaryTreeNode.RIGHT_ELBOW,
						subNodeIndent + BinaryTreeNode.BELOW_ELBOWS);
				nNode = nextNodes.get(i);
				next = nNode;
				if(stack == null) {
					stack = new ArrayDeque<>(root.size());
				}
				stack.addFirst(new IndentsNode(lastIndents, next));
				if(nextNodes.size() > 1) {
					Indents firstIndents = new Indents(
							subNodeIndent + BinaryTreeNode.LEFT_ELBOW,
							subNodeIndent + BinaryTreeNode.IN_BETWEEN_ELBOWS);
					for(--i; i >= 0; i--) {
						nNode = nextNodes.get(i);
						next = nNode;
						stack.addFirst(new IndentsNode(firstIndents, next));
					}
				}
			}
			if(stack == null) {
				break;
			}
			nextItem = stack.pollFirst();
			if(nextItem == null) {
				break;
			}
			nextNode = nextItem.node;
			Indents nextIndents = nextItem.indents;
			nodeIndent = nextIndents.nodeIndent;
			subNodeIndent = nextIndents.subNodeInd;
		}
		return builder.toString();
	}

	TrieNode<E> addNode(OpResult<E> result, TrieNode<E> fromNode, TrieNode<E> nodeToAdd, boolean withValues) {
		fromNode.matchBitsFromIndex(fromNode.getKey().getPrefixLength(), result);
		TrieNode<E> node = result.existingNode;
		return node == null ? result.inserted : node;
	}
	
	// Note: this method not called from sets or maps, so bounds does not apply
	TrieNode<E> addTrie(TrieNode<E> tree, boolean withValues) {
		CachingIterator<? extends TrieNode<E>, E, TrieNode<E>> iterator = 
				tree.containingFirstAllNodeIterator(true);
		TrieNode<E> toAdd = iterator.next();
		OpResult<E> result = new OpResult<>(toAdd.getKey(), Operation.INSERT);
		TrieNode<E> firstNode;
		TrieNode<E> root = absoluteRoot();
		boolean firstAdded = toAdd.isAdded();
		boolean addedOne = false;
		if(firstAdded) {
			addedOne = true;
			adjustRoot(toAdd.getKey());
			firstNode = addNode(result, root, toAdd, withValues);
		} else {
			firstNode = root;
		}
		TrieNode<E> lastAddedNode = firstNode;
		while(iterator.hasNext()) {
			iterator.cacheWithLowerSubNode(lastAddedNode);
			iterator.cacheWithUpperSubNode(lastAddedNode);
			toAdd = iterator.next();
			TrieNode<E> cachedNode = iterator.getCached();
			if(toAdd.isAdded()) {
				E addrNext = toAdd.getKey();
				if(!addedOne) {
					addedOne = true;
					adjustRoot(addrNext);
				}
				result.addr = addrNext;
				result.existingNode = null;
				result.inserted = null;
				result.setFollowingBits(0);
				lastAddedNode = addNode(result, cachedNode, toAdd, withValues);
			} else {
				lastAddedNode = cachedNode;
			}
		}
		if(!firstAdded) {
			firstNode = getNode(tree.getKey());
		}
		return firstNode;
	}

	@Override
	public TrieNode<E> addTrie(TrieNode<E> trie) {
		return addTrie(trie, false);
	}

	@Override
	public boolean contains(E addr) {
		if(bounds != null) {
			addr = checkBlockOrAddress(addr, true);
			if(!bounds.isInBounds(addr)) {
				return false;
			}
		}
		return absoluteRoot().contains(addr);
	}

	@Override
	public boolean remove(E addr) {
		if(bounds != null) {
			addr = checkBlockOrAddress(addr, true);
			if(!bounds.isInBounds(addr)) {
				return false;
			}
		}
		return absoluteRoot().remove(addr);
	}
	
	// The following four methods do not work when there are bounds, 
	// and have counterparts to be used from sets and maps

	@Override
	public TrieNode<E> removeElementsContainedBy(E addr) {
		if(bounds != null) {
			// should never reach here when there are bounds, since this is not exposed from set/map code
			throw new Error();
		}
		return absoluteRoot().removeElementsContainedBy(addr);
	}

	@Override
	public TrieNode<E> elementsContainedBy(E addr) {
		if(bounds != null) {
			// should never reach here when there are bounds, since this is not exposed from set/map code
			throw new Error();
		}
		return absoluteRoot().elementsContainedBy(addr);
	}

	@Override
	public TrieNode<E> elementsContaining(E addr) {
		if(bounds != null) {
			// should never reach here when there are bounds, since this is not exposed from set/map code
			throw new Error();
		}
		return absoluteRoot().elementsContaining(addr);
	}
	
	@Override
	public E longestPrefixMatch(E addr) {
		if(bounds != null) {
			// should never reach here when there are bounds, since this is not exposed from set/map code
			throw new Error();
		}
		return absoluteRoot().longestPrefixMatch(addr);
	}

	// only added nodes are added to the linked list
	@Override
	public TrieNode<E> longestPrefixMatchNode(E addr) {
		if(bounds != null) {
			// should never reach here when there are bounds, since this is not exposed from set/map code
			throw new Error();
		}
		return absoluteRoot().longestPrefixMatchNode(addr);
	}

	@Override
	public E shortestPrefixMatch(E addr) {
		if(bounds != null) {
			// should never reach here when there are bounds, since this is not exposed from set/map code
			throw new Error();
		}
		return absoluteRoot().shortestPrefixMatch(addr);
	}

	@Override
	public TrieNode<E> shortestPrefixMatchNode(E addr) {
		if(bounds != null) {
			// should never reach here when there are bounds, since this is not exposed from set/map code
			throw new Error();
		}
		return absoluteRoot().shortestPrefixMatchNode(addr);
	}

	@Override
	public boolean elementContains(E addr) {
		if(bounds != null) {
			// should never reach here when there are bounds, since this is not exposed from set/map code
			throw new Error();
		}
		return absoluteRoot().elementContains(addr);
	}

	// Is this subtrie affected by the "reverse" setting?  Well, we are gonna wrap it, so wrap it with the same reverse setting.
	@SuppressWarnings("unchecked")
	AddressTrie<E> elementsContainedByToSubTrie(E addr) {
		// We just construct a subtrie with bounds determined by the prefix block of E, nothing more is needed here
		AddressBounds<E> newBounds;
		E lower = (E) addr.getLower().withoutPrefixLength();
		E upper = (E) addr.getUpper().withoutPrefixLength();
		if(bounds == null) {
			newBounds = AddressBounds.createNewBounds(lower, true, upper, true, comparator());
		} else {
			newBounds = bounds.intersect(lower, true, upper, true);
		}
		if(newBounds == bounds) {
			return this;
		}
		return createSubTrie(newBounds);
	}

	AddressTrie<E> elementsContainingToTrie(E addr) {
		if(isEmpty()) {
			return this;
		}
		// this creates a completely new linked list of nodes with just the containing elements
		// then create an AddressTrie around then with the same bounds
		TrieNode<E> subRoot = getRoot();
		if(subRoot == null) {
			return createNew(bounds);
		}
		TrieNode<E> node = subRoot.elementsContaining(addr); // creates the new containing linked list
		if(node == null) {
			return createNew(bounds);
		}
		if (size() == node.size()) {
			return this;
		}
		return createNewSameBoundsFromList(node);
	}

	boolean elementContainsBounds(E addr) {
		if(bounds == null) {
			return elementContains(addr);
		}
		TrieNode<E> subRoot = getRoot();
		if(subRoot == null) {
			return false;
		}
		TrieNode<E> node = subRoot.elementsContaining(addr); // creates the new containing linked list
		if(node == null) {
			return false;
		}
		// Now we need to know if any of the nodes are within the bounds
		return !createNewSameBoundsFromList(node).isEmpty();
	}

	TrieNode<E> smallestElementContainingBounds(E addr) {
		if(bounds == null) {
			return longestPrefixMatchNode(addr);
		}
		TrieNode<E> subRoot = getRoot();
		if(subRoot == null) {
			return null;
		}
		TrieNode<E> node = subRoot.longestPrefixMatchNode(addr);
		if(node == null) {
			return null;
		}
		if(!bounds.isInBounds(node.getKey())) {
			node = subRoot.elementsContaining(addr); // creates the new containing linked list
			TrieNode<E> next, lastInBounds = bounds.isInBounds(node.getKey()) ? node : null;
			do {
				if((next = node.getLowerSubNode()) != null) {
					node = next;
					if(bounds.isInBounds(node.getKey())) {
						lastInBounds = node;
					}
				} else if((next = node.getUpperSubNode()) != null) {
					node = next;
					if(bounds.isInBounds(node.getKey())) {
						lastInBounds = node;
					}
				}
			} while(next != null);
			node = lastInBounds;
		}
		return node;
	}

	E longestPrefixMatchBounds(E addr) {
		TrieNode<E> node = smallestElementContainingBounds(addr);
		return node == null ? null : node.getKey();
	}

	// creates a new one-node trie with a new root and the given bounds
	protected abstract AddressTrie<E> createNew(AddressBounds<E> bounds);

	// create a trie with the same root as this one, but different bounds
	protected abstract AddressTrie<E> createSubTrie(AddressBounds<E> bounds);

	private AddressTrie<E> createNewSameBoundsFromList(TrieNode<E> node) {
		AddressTrie<E> newTrie = createNew(bounds);
		TrieNode<E> root = newTrie.absoluteRoot();
		if(node.getKey().equals(root.getKey())) {
			newTrie.root = node;
		} else {
			root.init(node);
		}
		ChangeTracker tracker = root.changeTracker;
		node.changeTracker = tracker;
		TrieNode<E> next = node;
		while(true) {
			TrieNode<E> lower = next.getLowerSubNode();
			if(lower == null) {
				next = next.getUpperSubNode();
				if(next == null) {
					break;
				}
			} else {
				next = lower;
			}
			next.changeTracker = tracker;
		}
		// change tracker needs to be in place before calculating size, which requires an iterator, which uses change tracker
		newTrie.root.size = BinaryTreeNode.SIZE_UNKNOWN;
		newTrie.root.size();
		return newTrie;
	}

	@Override
	public TrieNode<E> getNode(E addr) {
		TrieNode<E> subRoot;
		if(bounds != null) {
			addr = checkBlockOrAddress(addr, true);
			if(!bounds.isInBounds(addr)) {
				return null;
			}
			subRoot = getRoot();
			if(subRoot == null) {
				return null;
			}
		} else {
			subRoot = absoluteRoot();
		}
		return subRoot.getNode(addr);
	}

	@Override
	public Iterator<? extends TrieNode<E>> allNodeIterator(boolean forward) {
		if(bounds != null) {
			// This cannot work with bounds because we need to find the iterator boundary using ceiling/floor/high/lower,
			// which only work with added nodes.  Other iterators which filter based on the bounds can work.
			// Should never reach here when there are bounds, since this is not exposed from set/map code
			throw new Error();
		}
		return absoluteRoot().allNodeIterator(forward);
	}

	/**
	 * Iterates the added nodes in the trie, ordered by keys from largest prefix blocks to smallest, and then to individual addresses.
	 * <p>
	 * This iterator supports the {@link java.util.Iterator#remove()} operation.
	 * 
	 * @param lowerSubNodeFirst if true, for blocks of equal size the lower is first, otherwise the reverse order
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public Iterator<? extends TrieNode<E>> blockSizeNodeIterator(boolean lowerSubNodeFirst) {
		Iterator<? extends BinaryTreeNode<E>> iterator;
		if(bounds == null) {
			iterator = absoluteRoot().blockSizeNodeIterator(lowerSubNodeFirst);
		} else {
			iterator = new BlockSizeNodeIterator<E>(
					size(),
					bounds,
					true,
					getRoot(),
					!lowerSubNodeFirst,
					absoluteRoot().changeTracker);
		}
		return (Iterator<? extends TrieNode<E>>) iterator;
	}

	/**
	 * Iterates all nodes in the trie, ordered by keys from largest prefix blocks to smallest, and then to individual addresses.
	 * <p>
	 * This iterator supports the {@link java.util.Iterator#remove()} operation.
	 * 
	 * @param lowerSubNodeFirst if true, for blocks of equal size the lower is first, otherwise the reverse order
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public Iterator<? extends TrieNode<E>> blockSizeAllNodeIterator(boolean lowerSubNodeFirst) {
		Iterator<? extends BinaryTreeNode<E>> iterator;
		if(bounds == null) {
			iterator = absoluteRoot().blockSizeAllNodeIterator(lowerSubNodeFirst);
		} else { // at this time this is unreachable, we do not call this from set or map
			iterator = new BlockSizeNodeIterator<E>(
					0,
					bounds,
					false,
					getRoot(),
					!lowerSubNodeFirst,
					absoluteRoot().changeTracker);
		}
		return (Iterator<? extends TrieNode<E>>) iterator;
	}

	/**
	 * Iterates all nodes, ordered by keys from largest prefix blocks to smallest, and then to individual addresses.
	 * <p>
	 * This iterator supports the {@link java.util.Iterator#remove()} operation.
	 * 
	 * @return
	 */
	public <C> CachingIterator<? extends TrieNode<E>, E, C> blockSizeCachingAllNodeIterator() {
		if(bounds != null) {
			throw new Error();
		}
		return absoluteRoot().blockSizeCachingAllNodeIterator();
	}

	@SuppressWarnings("unchecked")
	@Override
	public <C> CachingIterator<? extends TrieNode<E>, E, C> containingFirstIterator(boolean forwardSubNodeOrder) {
		CachingIterator<? extends BinaryTreeNode<E>, E, C> iterator;
		if(bounds == null) {
			iterator = absoluteRoot().containingFirstIterator(forwardSubNodeOrder);
		} else {
			if(forwardSubNodeOrder) {
				iterator = new PreOrderNodeIterator<E, C>(
					bounds,
					true,
					true, // added only
					absoluteRoot(),
					null,
					absoluteRoot().changeTracker);
			} else {
				iterator = new PostOrderNodeIterator<E, C>(
					bounds,
					false,
					true, // added only
					absoluteRoot(),
					null,
					absoluteRoot().changeTracker);
			}
		}
		return (CachingIterator<? extends TrieNode<E>, E, C>) iterator;
	}

	@SuppressWarnings("unchecked")
	@Override
	public <C> CachingIterator<? extends TrieNode<E>, E, C> containingFirstAllNodeIterator(boolean forwardSubNodeOrder) {
		CachingIterator<? extends BinaryTreeNode<E>, E, C> iterator;
		if(bounds == null) {
			iterator = absoluteRoot().containingFirstAllNodeIterator(forwardSubNodeOrder);
		} else { // at this time this is unreachable, we do not call this from set or map
			if(forwardSubNodeOrder) {
				iterator = new PreOrderNodeIterator<E, C>(
					bounds,
					true,
					false, // added only
					absoluteRoot(),
					null,
					absoluteRoot().changeTracker);
			} else {
				iterator = new PostOrderNodeIterator<E, C>(
					bounds,
					false,
					false, // added only
					absoluteRoot(),
					null,
					absoluteRoot().changeTracker);
			}
		}
		return (CachingIterator<? extends TrieNode<E>, E, C>) iterator;
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<? extends TrieNode<E>> containedFirstIterator(boolean forwardSubNodeOrder) {
		Iterator<? extends BinaryTreeNode<E>> iterator;
		if(bounds == null) {
			iterator = absoluteRoot().containedFirstIterator(forwardSubNodeOrder);
		} else {
			iterator = containedFirstBoundedIterator(forwardSubNodeOrder, true);
		}
		return (Iterator<? extends TrieNode<E>>) iterator;
	}

	private Iterator<? extends BinaryTreeNode<E>> containedFirstBoundedIterator(boolean forwardSubNodeOrder, boolean addedNodesOnly) {
		Iterator<? extends BinaryTreeNode<E>> iterator;
		if(forwardSubNodeOrder) {
			BinaryTreeNode<E> startNode = absoluteRoot().firstPostOrderNode();
			iterator = new PostOrderNodeIterator<E, Object>(
					bounds,
					true, // forward
					addedNodesOnly, // added only
					startNode,
					null,
					absoluteRoot().changeTracker);
		} else {
			BinaryTreeNode<E> startNode = absoluteRoot().lastPreOrderNode();
			iterator = new PreOrderNodeIterator<E, Object>(
					bounds,
					false, // forward
					addedNodesOnly, // added only
					startNode,
					null,
					absoluteRoot().changeTracker);
		}
		return iterator;
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<? extends TrieNode<E>> containedFirstAllNodeIterator(boolean forwardSubNodeOrder) {
		Iterator<? extends BinaryTreeNode<E>> iterator;
		if(bounds == null) {
			iterator = absoluteRoot().containedFirstAllNodeIterator(forwardSubNodeOrder);
		} else {
			iterator = containedFirstBoundedIterator(forwardSubNodeOrder, false);
		}
		return (Iterator<? extends TrieNode<E>>) iterator;
	}

	@Override
	public Spliterator<E> spliterator() {
		return new KeySpliterator<E>(nodeSpliterator(true, true), comparator());
	}

	@Override
	public Spliterator<E> descendingSpliterator() {
		return new KeySpliterator<E>(nodeSpliterator(false, true), reverseComparator());
	}

	@Override
	public Spliterator<? extends TrieNode<E>> nodeSpliterator(boolean forward) {
		return nodeSpliterator(forward, true);
	}

	@Override
	public Spliterator<? extends TrieNode<E>> allNodeSpliterator(boolean forward) {
		if(bounds != null) {
			// This cannot work with bounds because we need to find the iterator boundary using ceiling/floor/high/lower,
			// which only work with added nodes.  Other iterators which filter based on the bounds can work.
			// Should never reach here when there are bounds, since this is not exposed from set/map code
			throw new Error();
		}
		return absoluteRoot().nodeSpliterator(forward, false);
	}

	@SuppressWarnings("unchecked")
	Spliterator<? extends TrieNode<E>> nodeSpliterator(boolean forward, boolean addedNodesOnly) {
		Spliterator<? extends TrieNode<E>> spliterator;
		if(bounds == null) {
			spliterator = absoluteRoot().nodeSpliterator(forward, addedNodesOnly);
		} else {
			Comparator<BinaryTreeNode<E>> comp = forward ? nodeComparator() : reverseNodeComparator();
			Spliterator<? extends BinaryTreeNode<E>> split = new NodeSpliterator<E>(
					forward,
					comp,
					getRoot(),
					forward ? firstAddedNode() : lastAddedNode(),
					forward ? getIteratingUpperBoundary() : getIteratingLowerBoundary(),
					size(),
					absoluteRoot().changeTracker,
					addedNodesOnly);
			spliterator = (Spliterator<? extends TrieNode<E>>) split;
		}
		return spliterator;
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<? extends TrieNode<E>> nodeIterator(boolean forward) {
		Iterator<? extends BinaryTreeNode<E>> iterator;
		if(bounds == null) {
			iterator = absoluteRoot().nodeIterator(forward);
		} else {
			iterator = new NodeIterator<E>(
				forward,
				true,
				forward ? firstAddedNode() : lastAddedNode(),
				forward ? getIteratingUpperBoundary() : getIteratingLowerBoundary(),
				absoluteRoot().changeTracker);
		}
		return (Iterator<? extends TrieNode<E>>) iterator;
	}

	@Override
	public TrieNode<E> firstNode() {
		return absoluteRoot().firstNode();
	}

	@Override
	public TrieNode<E> firstAddedNode() {
		if(bounds == null) {
			return absoluteRoot().firstAddedNode();
		}
		TrieNode<E> subRoot = getRoot();
		if(subRoot != null) {
			TrieNode<E> node = bounds.isLowerBounded() ?
				(bounds.lowerInclusive ? subRoot.ceilingNodeNoCheck(bounds.lowerBound) : subRoot.higherNodeNoCheck(bounds.lowerBound)) :
					subRoot.firstAddedNode();
			return (node == null || bounds.isAboveUpperBound(node.getKey())) ? null : node;
		}
		return null;
	}

	private TrieNode<E> getIteratingUpperBoundary() {
		TrieNode<E> subRoot = getRoot();
		if(subRoot == null) {
			return null;
		}
		if(bounds.isUpperBounded()) {
			return bounds.upperInclusive ? subRoot.higherNodeNoCheck(bounds.upperBound) : subRoot.ceilingNodeNoCheck(bounds.upperBound);//floorNodeBounded(bounds.lowerBound);
		}
		return subRoot.getParent();
	}

	@Override
	public TrieNode<E> lastNode() {
		return absoluteRoot().lastNode();
	}

	@Override
	public TrieNode<E> lastAddedNode() {
		if(bounds == null) {
			return absoluteRoot().lastAddedNode();
		}
		TrieNode<E> subRoot = getRoot();
		if(subRoot != null) {
			TrieNode<E> node = bounds.isUpperBounded() ?
					(bounds.upperInclusive ? 
							subRoot.floorNodeNoCheck(bounds.upperBound) : subRoot.lowerNodeNoCheck(bounds.upperBound)) : 
						subRoot.lastAddedNode();
			return (node == null || bounds.isBelowLowerBound(node.getKey())) ? null : node;
		}
		return null;
	}

	private TrieNode<E> getIteratingLowerBoundary() {
		TrieNode<E> subRoot = getRoot();
		if(subRoot == null) {
			return null;
		}
		if(bounds.isLowerBounded()) {
			return bounds.lowerInclusive ? subRoot.lowerNodeNoCheck(bounds.lowerBound) : subRoot.floorNodeNoCheck(bounds.lowerBound);
		}
		return subRoot.getParent();
	}

	/**
	 * Returns a comparator for the trie order
	 * 
	 * @return
	 */
	public Comparator<E> getComparator() {
		return comparator();
	}

	@SuppressWarnings("unchecked")
	static <E extends Address> Comparator<E> comparator() {
		return (Comparator<E>) comparator.comparator;
	}

	@SuppressWarnings("unchecked")
	static <E extends Address> Comparator<BinaryTreeNode<E>> nodeComparator() {
		return (TrieComparator<E>) comparator;
	}

	@SuppressWarnings("unchecked")
	static <E extends Address> Comparator<E> reverseComparator() {
		return (Comparator<E>) reverseComparator.comparator;
	}

	@SuppressWarnings("unchecked")
	static <E extends Address> Comparator<BinaryTreeNode<E>> reverseNodeComparator() {
		return (TrieComparator<E>) reverseComparator;
	}

	/**
	 * Returns a java.util.NavigableSet that uses this as the backing data structure.
	 * Added elements of this trie are the elements in the set.
	 * 
	 * @return
	 */
	public AddressTrieSet<E> asSet() {
		AddressTrieSet<E> set = this.set;
		if(set == null) {
			set = new AddressTrieSet<E>(this);
		}
		return set;
	}

	protected TrieNode<E> absoluteRoot() {
		return (TrieNode<E>) root;
	}

	@Override
	public TrieNode<E> getRoot() {
		if(bounds == null) {
			return absoluteRoot();
		}
		if(subRootChange != null && !absoluteRoot().changeTracker.isChangedSince(subRootChange)) {
			// was previously calculated and there has been no change to the trie since then
			return subRoot;
		}
		TrieNode<E> current = absoluteRoot();
		do {
			E currentKey = current.getKey();
			if(bounds.isLowerBounded() && bounds.isBelowLowerBound(currentKey)) {
				current = current.getUpperSubNode();
			} else if(bounds.isUpperBounded() && bounds.isAboveUpperBound(currentKey)) {
				current = current.getLowerSubNode();
			} else {
				// inside the bounds
				break;
			}
		} while(current != null);
		subRootChange = absoluteRoot().changeTracker.getCurrent();
		subRoot = current;
		return current;
	}

	@Override
	public TrieNode<E> lowerAddedNode(E addr) {
		if(bounds == null) {
			return absoluteRoot().lowerAddedNode(addr);
		}
		addr = checkBlockOrAddress(addr, true);
		return lowerNodeBounded(addr);
	}

	private TrieNode<E> lowerNodeBounded(E addr) {
		TrieNode<E> subRoot = getRoot();
		if(subRoot != null) {
			TrieNode<E> node = bounds.isAboveUpperBound(addr) ? 
					lastAddedNode() : subRoot.lowerNodeNoCheck(addr);
			return (node == null || bounds.isBelowLowerBound(node.getKey())) ? null : node;
		}
		return null;
	}

	@Override
	public E lower(E addr) {
		return getNodeKey(lowerAddedNode(addr));
	}

	@Override
	public TrieNode<E> floorAddedNode(E addr) {
		if(bounds == null) {
			return absoluteRoot().floorAddedNode(addr);
		}
		addr = checkBlockOrAddress(addr, true);
		return floorNodeBounded(addr);
	}

	private TrieNode<E> floorNodeBounded(E addr) {
		TrieNode<E> subRoot = getRoot();
		if(subRoot != null) {
			TrieNode<E> node = bounds.isAboveUpperBound(addr) ? 
					lastAddedNode() : subRoot.floorNodeNoCheck(addr);
			return (node == null || bounds.isBelowLowerBound(node.getKey())) ? null : node;
		}
		return null;
	}

	@Override
	public E floor(E addr) {
		return getNodeKey(floorAddedNode(addr));
	}

	@Override
	public TrieNode<E> higherAddedNode(E addr) {
		if(bounds == null) {
			return absoluteRoot().higherAddedNode(addr);
		}
		addr = checkBlockOrAddress(addr, true);
		return higherNodeBounded(addr);
	}

	private TrieNode<E> higherNodeBounded(E addr) {
		TrieNode<E> subRoot = getRoot();
		if(subRoot != null) {
			TrieNode<E> node = bounds.isBelowLowerBound(addr) ? 
					firstAddedNode() : subRoot.higherNodeNoCheck(addr);
			return (node == null || bounds.isAboveUpperBound(node.getKey())) ? null : node;
		}
		return null;
	}

	@Override
	public E higher(E addr) {
		return getNodeKey(higherAddedNode(addr));
	}

	@Override
	public TrieNode<E> ceilingAddedNode(E addr) {
		if(bounds == null) {
			return absoluteRoot().ceilingAddedNode(addr);
		}
		addr = checkBlockOrAddress(addr, true);
		return ceilingNodeBounded(addr);
	}

	private TrieNode<E> ceilingNodeBounded(E addr) {
		TrieNode<E> subRoot = getRoot();
		if(subRoot != null) {
			TrieNode<E> node = bounds.isBelowLowerBound(addr) ? 
					firstAddedNode() : subRoot.ceilingNodeNoCheck(addr);
			return (node == null || bounds.isAboveUpperBound(node.getKey())) ? null : node;
		}
		return null;
	}

	@Override
	public E ceiling(E addr) {
		return getNodeKey(ceilingAddedNode(addr));
	}

	static <E extends Address> E getNodeKey(TrieNode<E> node) {
		return (node == null) ? null : node.getKey();
	}

	@Override
	public void clear() {
		if(bounds == null) {
			super.clear();
		} else {
			Iterator<? extends BinaryTreeNode<E>> iterator = nodeIterator(true);
			while(iterator.hasNext()) {
				BinaryTreeNode<E> node = iterator.next();
				if(bounds.isInBounds(node.getKey())) {
					iterator.remove();
				}
			}
		}
	}

	@Override
	public AddressTrie<E> clone() {
		AddressTrie<E> result = (AddressTrie<E>) super.clone();
		result.set = null;
		if(bounds == null) {
			result.root = getRoot().cloneTree();
		} else {
			TrieNode<E> root = absoluteRoot();
			if(bounds.isInBounds(root.getKey())) {
				result.root = root.cloneTreeBounds(bounds);
			} else {
				// clone the root ourselves, then clone the trie starting from the subroot, and make it a child of the root
				BinaryTreeNode<E> clonedRoot = root.cloneTreeNode(new ChangeTracker()); // clone root node only
				result.root = clonedRoot;
				clonedRoot.setNodeAdded(false); // not in bounds, so not part of new trie
				clonedRoot.setLower(null);
				clonedRoot.setUpper(null);
				TrieNode<E> subRoot = getRoot();
				if(subRoot != null) {
					TrieNode<E> subCloned = subRoot.cloneTreeBounds(bounds);
					if(subCloned != null) {
						result.absoluteRoot().init(subCloned);// attach cloned sub-root to root
					} else {
						clonedRoot.size = clonedRoot.isAdded() ? 1 : 0;
					}
				} else {
					clonedRoot.size = clonedRoot.isAdded() ? 1 : 0;
				}
			}
			result.bounds = null;
		}
		return result;
	}

	/**
	 * Returns whether the given argument is a trie with a set of nodes that equal the set of nodes in this trie
	 */
	@Override
	public boolean equals(Object o) {
		return o instanceof AddressTrie && super.equals(o);
	}

	@Override
	public String toString() {
		if(bounds == null) {
			return super.toString();
		}
		return toString(true);
	}

	String noBoundsString() { // useful for debugging
		return absoluteRoot().toTreeString(true, true);
	}

	@Override
	public String toString(boolean withNonAddedKeys) {
		if(bounds == null) {
			return super.toString(withNonAddedKeys);
		}
		StringBuilder builder = new StringBuilder("\n");
		printTree(builder, new Indents(), withNonAddedKeys);
		return builder.toString();
	}

	void printTree(StringBuilder builder, Indents indents, boolean withNonAddedKeys) {
		TrieNode<E> subRoot = getRoot();
		if(subRoot == null) {
			return;
		}
		subRoot.printTree(builder, indents, withNonAddedKeys, true, 
				this.<Indents>containingFirstAllNodeIterator(true));
	}

	/**
	 * Produces a visual representation of the given tries joined by a single root node, with one node per line.
	 * 
	 * @param withNonAddedKeys
	 * @param tries
	 * @return
	 */
	public static String toString(boolean withNonAddedKeys, AddressTrie<?> ...tries) {
		int totalEntrySize = 0;
		for(int i=0; i < tries.length; i++) {
			totalEntrySize += tries[i].size();
		}
		StringBuilder builder = new StringBuilder(totalEntrySize * 120);
		builder.append('\n').append(BinaryTreeNode.NON_ADDED_NODE_CIRCLE);
		boolean isEmpty = tries == null;
		if(!isEmpty) {
			AddressTrie<?> lastTree = null;
			int lastTreeIndex;
			for(lastTreeIndex = tries.length - 1; lastTreeIndex >= 0; lastTreeIndex--) {
				if(tries[lastTreeIndex] != null) {
					lastTree = tries[lastTreeIndex];
					break;
				}
			}
			isEmpty = lastTree == null;
			if(!isEmpty) {
				int totalSize = lastTree.size();
				for(int i = 0; i < lastTreeIndex; i++) {
					AbstractTree<?> tree = tries[i];
					if(tree != null) {
						totalSize += tree.size();
					}
				}
				if(withNonAddedKeys) {
					builder.append(' ').append(Address.SEGMENT_WILDCARD_STR).append(" (").append(totalSize).append(')');
				}
				builder.append('\n');
				for(int i = 0; i < lastTreeIndex; i++) {
					AddressTrie<?> tree = tries[i];
					if(tree != null) {
						tree.printTree(builder, new Indents(BinaryTreeNode.LEFT_ELBOW, BinaryTreeNode.IN_BETWEEN_ELBOWS), withNonAddedKeys);
					}
				}
				lastTree.printTree(builder, new Indents(BinaryTreeNode.RIGHT_ELBOW, BinaryTreeNode.BELOW_ELBOWS), withNonAddedKeys);
			}
		}
		if(isEmpty) {
			if(withNonAddedKeys) {
				builder.append(' ').append(Address.SEGMENT_WILDCARD_STR).append(" (0)");
			}
			builder.append('\n');
		}
		return builder.toString();
	}
}
