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
import java.util.List;
import java.util.Objects;
import java.util.Spliterator;
import java.util.TreeSet;
import java.util.function.Function;

import inet.ipaddr.Address;
import inet.ipaddr.AddressSegment;
import inet.ipaddr.AddressSegmentSeries;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressSegment;
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
 * The trie can also be used as the backing structure for a {@link TreeSet} which is a {@link java.util.NavigableSet}.
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
 * <ul><li>1, 2: the natural sorted trie order, forward and reverse (spliterating is also an option for these two orders).  A comparator is also provided for this order.
 * </li><li>3, 4: pre-order tree traversal, in which parent node is visited before sub-nodes, with sub-nodes visited in forward or reverse order
 * </li><li>5, 6: post-order tree traversal, in which sub-nodes are visited before parent nodes, with sub-nodes visited in forward or reverse order
 * </li><li>7, 8: prefix-block order, in which larger prefix blocks are visited before smaller, and blocks of equal size are visited in forward or reverse sorted order
 * </li></ul>
 * <p>
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
 * Instead, you could aggregate multiple subtries to create a collection multiple address types or versions.
 * You can use the method {@link #toString(boolean, AddressTrie...)} for a String that represents multiple tries as a single tree.
 * <p>
 * Tries are thread-safe when not being modified (elements added or removed), but are not thread-safe when one thread is modifying the trie.
 * For thread safety when modifying, one option is to use {@link Collections#synchronizedNavigableSet(java.util.NavigableSet)} on {@link #asSet()}.
 * <p>
 * 
 * @author scfoley
 *
 * @param <E>
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
				//res = (E) upperBound.increment(1);
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
				//res = (E) lowerBound.increment(-1);
				res = decrement(lowerBound);
				oneBelowLowerBound = res;
			}
			return res != null && res.equals(addr);
		}
		
		@Override
		boolean isAdjacentBelowUpperBound(E addr) { 
			E res = oneBelowUpperBound;
			if(res == null) {
				res = decrement(upperBound);
				//res = (E) upperBound.increment(-1);
				oneBelowUpperBound = res;
			}
			return res != null && res.equals(addr);
		}
		
		// matches the value just below the lower bound (only applies to discrete quantities)
		@Override
		boolean isAdjacentAboveLowerBound(E addr) {
			E res = oneAboveLowerBound;
			if(res == null) {
				res = increment(lowerBound);
				//res = (E) lowerBound.increment(1);
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
	    LOOKUP, // find node for E
	    NEAR, // closest match, going down trie to get element considered closest.
	    	// Whether one thing is closer than another is determined by the sorted order.
	    	// For example, for subnet 1.2.0.0/16, 1.2.128.0 is closest address on the high side, 1.2.127.255 is closest address on the low side
	    CONTAINING, // list the nodes whose keys contain E
	    INSERTED_DELETE, // remove node for E
	    SUBNET_DELETE // remove nodes whose keys are contained by E
	}
	
	// not optimized for size, since only temporary, to be used for a single operation
	protected static class OpResult<E extends Address> {
		E addr;
		
		// whether near is searching for a floor or ceiling
		// a floor is greatest element below addr
		// a ceiling is lowest element above addr
		final boolean nearestFloor; 
		
		// whether near cannot be an exact match
		final boolean nearExclusive;
		
		final Operation op;
		
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
		//boolean backtrack;

		// contains:  

		// A linked list of the tree elements, from largest to smallest, 
		// that contain the supplied argument, and the end of the list
		TrieNode<E> containing, containingEnd;

		// at least one tree element contains the the supplied argument
		boolean contains;

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
			int bitsMatchedSoFar = 0;
			int extraBits = Integer.SIZE - bitsPerSegment;
			int i = 0;
			while(true) {
				AddressSegment segment1 = o1.getSegment(i);
				AddressSegment segment2 = o2.getSegment(i);
				Integer pref1 = getSegmentPrefLen(o1, bitsMatchedSoFar, segment1);
				Integer pref2 = getSegmentPrefLen(o2, bitsMatchedSoFar, segment2);
				int segmentPref2;
				if(pref1 != null) {
					int segmentPref1 = pref1;
					if(pref2 != null && (segmentPref2 = pref2) <= segmentPref1) {
						int matchingBits = getMatchingBits(segment1, segment2, segmentPref2, extraBits);
						if(matchingBits >= segmentPref2) {
							if(segmentPref2 == segmentPref1) {
								// same prefix block
								return 0;
							} else {
								// segmentPref2 is shorter prefix, prefix bits match, so depends on bit at index segmentPref2
								return segment1.isOneBit(segmentPref2) ? 1 : -1;
							}
						} else {
							return segment1.getSegmentValue() - segment2.getSegmentValue();
						}
					} else {
						int matchingBits = getMatchingBits(segment1, segment2, segmentPref1, extraBits);
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
					int matchingBits = getMatchingBits(segment1, segment2, segmentPref2, extraBits);
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
					int matchingBits = getMatchingBits(segment1, segment2, bitsPerSegment, extraBits);
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
		if(addr instanceof IPAddress) {
			IPAddress ipaddr = (IPAddress) addr;
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
		if(addr instanceof IPAddress) {
			IPAddress ipaddr = (IPAddress) addr;
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
		public TrieNode<E> floorAddedNode(E addr) {
			return findNodeNear(addr, true, false);
		}

		TrieNode<E> floorNodeNoCheck(E addr) {
			return findNodeNearNoCheck(addr, true, false);
		}

		@Override
		public TrieNode<E> higherAddedNode(E addr) {
			return findNodeNear(addr, false, true);
		}

		TrieNode<E> higherNodeNoCheck(E addr) {
			return findNodeNearNoCheck(addr, false, true);
		}

		@Override
		public TrieNode<E> ceilingAddedNode(E addr) {
			return findNodeNear(addr, false, false);
		}

		TrieNode<E> ceilingNodeNoCheck(E addr) {
			return findNodeNearNoCheck(addr, false, false);
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
			addr = checkBlockOrAddress(addr, true);
			OpResult<E> result = new OpResult<>(addr, Operation.LOOKUP);
			matchBits(result);
			return result.exists;
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
			addr = checkBlockOrAddress(addr, true);
			OpResult<E> result = new OpResult<>(addr, Operation.LOOKUP);
			matchBits(result);
			TrieNode<E> ret = result.existingNode;
			return ret;
		}

		@Override
		public TrieNode<E> removeElementsContainedBy(E addr) {
			addr = checkBlockOrAddress(addr, true);
			OpResult<E> result = new OpResult<>(addr, Operation.SUBNET_DELETE);
			matchBits(result);
			return result.deleted;
		}

		@Override
		public TrieNode<E> elementsContainedBy(E addr) {
			addr = checkBlockOrAddress(addr, true);
			OpResult<E> result = new OpResult<>(addr, Operation.LOOKUP);
			matchBits(result);
			return result.containedBy;
		}

		// only added nodes are added to the linked list
		@Override
		public TrieNode<E> elementsContaining(E addr) {
			addr = checkBlockOrAddress(addr, true);
			OpResult<E> result = new OpResult<>(addr, Operation.CONTAINING);
			matchBits(result);
			return result.getContaining();
		}

		@Override
		public boolean elementContains(E addr) {
			addr = checkBlockOrAddress(addr, true);
			OpResult<E> result = new OpResult<>(addr, Operation.LOOKUP);
			matchBits(result);
			return result.contains;
		}

		private void removeSubnet(OpResult<E> result) {
			result.deleted = this;
			clear();
		}

		protected void remove(OpResult<E> result) {
			result.deleted = this;
			remove();
		}

		void matchBits(OpResult<E> result) {
			matchBits(0, result);
		}

		void matchBits(int bitIndex, OpResult<E> result) {
			matchBits(this, bitIndex, result);
		}

		// traverses the tree, matching bits with prefix block nodes, until we can match no longer,
		// at which point it completes the operation, whatever that operation is
		static <E extends Address> void matchBits(TrieNode<E> node, int bitIndex, OpResult<E> result) {
			while(true) {
				int bits = node.matchNodeBits(bitIndex, result);
				if(bits >= 0) { 
					// matched all node bits up the given count, so move into sub-nodes
					node = node.matchSubNode(bits, result);
					if(node == null) {
						// reached the end of the line
						break;
					}
					// Matched a sub-node.  
					// The sub-node was chosen according to that next bit. 
					// That bit is therefore now a match,
					// so increment the matched bits by 1, and keep going.
					bitIndex = bits + 1;
				} else {
					// reached the end of the line
					break;
				}
			}
		}

		int matchNodeBits(int bitIndex, OpResult<E> result) {
			E newAddr = result.addr;
			Operation op = result.op;
			AddressSegmentSeries existingAddr = getKey();
			int bitsPerSegment = existingAddr.getBitsPerSegment();
			int segmentIndex = bitIndex / bitsPerSegment;
			int segmentCount = existingAddr.getSegmentCount();
			// this block handles cases like handling 1.2.3.4 and 1.2.3.4/32
			// but since those two return true for equals(), we do not allow both in our tries and we do not actually need this case,
			// but we do keep it for alternative tries that do not need the collection to consistent with equals()
			if(segmentIndex >= segmentCount) {
				Integer existingPref = existingAddr.getPrefixLength();
				Integer newPref = newAddr.getPrefixLength();
				// note that "added" is already true here, we can only be here if explicitly inserted already 
				if(Objects.equals(existingPref, newPref)) {
					result.containedBy = this;
					handleMatch(result);
				} else if(existingPref == null) {
					result.containedBy = this;
					handleContained(result, newPref);
				} else { // newPref == null
					handleContains(result);
					return existingPref;
				}
				return -1;
			}
			if(newAddr.getSegmentCount() != segmentCount) {
				// to handle this is tricky.  For a:b:c:d:e:f I would need
				// to convert to an address with prefix length 48, which I do not support.
				// Not only that, the prefixed address would be equal with the original, which is an equality problem.
				// So overall, it is not supported, it doesn't make sense.
				//
				// However, for MAC addresses, we do allow the first inserted address to determine the bit size of the trie.
				throw new IllegalArgumentException(getMessage("ipaddress.error.mismatched.bit.size"));
			}
			int bitsMatchedSoFar = segmentIndex * bitsPerSegment;
			int extraBits = Integer.SIZE - bitsPerSegment;
			while(true) {
				AddressSegment existingSegment = existingAddr.getSegment(segmentIndex);
				AddressSegment newSegment = newAddr.getSegment(segmentIndex);
				Integer segmentPref = getSegmentPrefLen(existingAddr, bitsMatchedSoFar, existingSegment);
				Integer newPref = getSegmentPrefLen(newAddr, bitsMatchedSoFar, newSegment);
				int newPrefixLen;
				if(segmentPref != null) {	
					int segmentPrefLen = segmentPref;
					if(newPref != null && (newPrefixLen = newPref) <= segmentPrefLen) {
						int matchingBits = getMatchingBits(existingSegment, newSegment, newPrefixLen, extraBits);
						if(matchingBits >= newPrefixLen) { // the bits of current prefix match
							result.containedBy = this;
							if(newPrefixLen == segmentPrefLen) {
								if(isAdded()) {
									handleMatch(result);
								} else if(op == Operation.LOOKUP) {
									result.existingNode = this;
								} else if(op == Operation.INSERT) {
									existingAdded(result);
								} else if(op == Operation.SUBNET_DELETE) {
									removeSubnet(result);
								} else if(op == Operation.NEAR) {
									//findNearest(result, bitsMatchedSoFar + newPrefixLen);
									findNearestFromMatch(result);
								} else if(op == Operation.REMAP) {
									remapNonAdded(result);
								}
								break;
							} else { // newPrefixLen < segmentPrefLen, matchingBits >= newPrefixLen
								handleContained(result, bitsMatchedSoFar + newPrefixLen);
							}
						} else {
							// no match - the bits don't match
							// matchingBits < newPrefLen < segmentPrefLen
							handleSplitNode(result, bitsMatchedSoFar + matchingBits);
						}
					} else {
						int matchingBits = getMatchingBits(existingSegment, newSegment, segmentPrefLen, extraBits);
						if(matchingBits >= segmentPrefLen) { // match - the current subnet/address is a match so far, and we must go further to check smaller subnets
							if(isAdded()) {
								handleContains(result);
							}
							return segmentPrefLen + bitsMatchedSoFar;
						} else {
							// matchingBits < segmentPrefLen - no match - the bits in current prefix do not match the prefix of the existing address
							handleSplitNode(result, bitsMatchedSoFar + matchingBits);
						}
					}
					break;
				} else if(newPref != null) {
					newPrefixLen = newPref;
					int matchingBits = getMatchingBits(existingSegment, newSegment, newPrefixLen, extraBits);
					if(matchingBits >= newPrefixLen) { // the current bits match the current prefix, but the existing has no prefix
						result.containedBy = this;
						handleContained(result, bitsMatchedSoFar + newPrefixLen);
					} else {
						// no match - the current subnet does not match the existing address
						handleSplitNode(result, bitsMatchedSoFar + matchingBits);
					}
					break;
				} else {
					int matchingBits = getMatchingBits(existingSegment, newSegment, bitsPerSegment, extraBits);
					if(matchingBits < bitsPerSegment) { // no match - the current subnet/address is not here
						handleSplitNode(result, bitsMatchedSoFar + matchingBits);
						break;
					} else if(++segmentIndex == segmentCount) { // match - the current subnet/address is a match
						result.containedBy = this;
						// note that "added" is already true here, we can only be here if explicitly inserted already since it is a non-prefixed full address
						handleMatch(result);
						break;
					}
					bitsMatchedSoFar += bitsPerSegment;
				}
			}
			return -1;
		}

		private void handleContained(OpResult<E> result, int newPref) {
			Operation op = result.op;
			if(op == Operation.INSERT) {
				// if we have 1.2.3.4 and 1.2.3.4/32, and we are looking at the last segment,
				// then there are no more bits to look at, and this makes the former a sub-node of the latter.
				// In most cases, however, there are more bits in existingAddr, the latter, to look at.
				replace(result, newPref);
			} else  if(op == Operation.SUBNET_DELETE) {
				removeSubnet(result);
			} else if(op == Operation.NEAR) {
				findNearest(result, newPref);
			} else if(op == Operation.REMAP) {
				remapNonExistingReplace(result, newPref);
			} 
		}

		private boolean handleContains(OpResult<E> result) {
			result.contains = true;
			if(result.op == Operation.CONTAINING) {
				result.addContaining(this);
				return true;
			}
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

		private void handleMatch(OpResult<E> result) {
			result.exists = true;
			if(!handleContains(result)) {
				Operation op = result.op;
				if(op == Operation.LOOKUP) {
					matched(result);
				} else if(op == Operation.INSERT) {
					matchedInserted(result);
				} else if(op == Operation.INSERTED_DELETE) {
					remove(result);
				} else if(op == Operation.SUBNET_DELETE) {
					removeSubnet(result);
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
			setAdded(true);
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
			E newBlock = (E) getKey().setPrefixLength(totalMatchingBits).toPrefixBlock();
			replace(newBlock, result, totalMatchingBits, newSubNode);
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
			TrieNode<E> newNode = replace(result.addr, result, totalMatchingBits, null);
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
		private TrieNode<E> replace(E newAssignedAddr, OpResult<E> result, int totalMatchingBits, TrieNode<E> newSubNode) {
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
			} else if(bitIndex < newAddr.getBitCount() && newAddr.isOneBit(bitIndex)) {
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
				// if we have 1.2.3.4 and 1.2.3.4/32, and we are looking at the last segment,
				// then there are no more bits to look at, and this makes the former a sub-node of the latter.
				// However, because 1.2.3.4 and 1.2.3.4/32 return true for equals(), we avoid putting both in the tree,
				// and instead we always convert to 1.2.3.4 first.
				// In most cases, however, there are more bits in newAddr, the former, to look at.
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

		@Override
		public TrieNode<E> cloneTree() {
			return (TrieNode<E>) super.cloneTree();
		}

		@Override
		public TrieNode<E> clone() {
			return (TrieNode<E>) super.clone();
		}

		@Override
		TrieNode<E> cloneTree(Bounds<E> bounds) {
			return (TrieNode<E>) super.cloneTree(bounds);
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
			int bitsMatchedSoFar,
			AddressSegment segment) {
		if(segment instanceof IPAddressSegment) {
			return ((IPAddressSegment) segment).getSegmentPrefixLength();
		} else if(addr.isPrefixed()) {
			int existingPrefLen = addr.getPrefixLength();
			if(existingPrefLen <= bitsMatchedSoFar + addr.getBitsPerSegment()) {
				Integer result = existingPrefLen - bitsMatchedSoFar;
				if(result < 0) {
					result = 0;
				}
				return result;
			}
		}
		return null;
	}

	private static int getMatchingBits(AddressSegment segment1, AddressSegment segment2, int maxBits, int adjustment) {
		if(maxBits == 0) {
			return 0;
		}
		int val1 = segment1.getSegmentValue();
		int val2 = segment2.getSegmentValue();
		int xor = val1 ^ val2;
		if(adjustment == IPv6Address.BITS_PER_SEGMENT) {
			return numberOfLeadingZerosShort(xor);
		} else if(adjustment == (32 - IPv4Address.BITS_PER_SEGMENT)) {
			return numberOfLeadingZerosByte(xor);
		}
		return Integer.numberOfLeadingZeros(xor) - adjustment;
	}

	private static int numberOfLeadingZerosShort(int i) {
		if (i == 0)
			return 16;
		int n = 1;
		if (i >>> 8 == 0) { n +=  8; i <<=  8; }
		if (i >>> 12 == 0) { n +=  4; i <<=  4; }
		if (i >>> 14 == 0) { n +=  2; i <<=  2; }
		n -= i >>> 15;
		return n;
	}

	private static int numberOfLeadingZerosByte(int i) {
		if (i == 0)
			return 8;
		int n = 1;
		if (i >>> 4 == 0) { n +=  4; i <<=  4; }
		if (i >>> 6 == 0) { n +=  2; i <<=  2; }
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
	 * Returns the number of nodes in the trie, which is more than the number of elements.
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

	/**
	 * Provides an associative trie in which the root and each added node are mapped to a list of their respective direct added nodes.
	 * This trie provides an alternative non-binary tree structure of the added nodes.
	 * It is used by {@link #toAddedNodesTreeString()} to produce a string showing the alternative structure.
	 * If there are no non-added nodes in this trie, then the alternative tree structure provided by this method is the same as the original trie.
	 *
	 * @return
	 */
	public abstract AssociativeAddressTrie<E, ? extends List<? extends AssociativeTrieNode<E, ?>>> constructAddedNodesTree();

	/**
	 * Provides a flattened version of the trie showing only the contained added nodes and their containment structure, which is non-binary.
	 * The root node is included, which may or may not be added.
	 * <p>
	 * See {@link #constructAddedNodesTree()}
	 * 
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public String toAddedNodesTreeString() {
		AssociativeAddressTrie<E, ? extends List<? extends AssociativeTrieNode<E, ?>>> addedTree = constructAddedNodesTree();
		class IndentsNode {
			Indents indents;
			AssociativeTrieNode<E, List<AssociativeTrieNode<E, ?>>> node;
			
			IndentsNode(Indents indents, AssociativeTrieNode<E, List<AssociativeTrieNode<E, ?>>> node) {
				this.indents = indents;
				this.node = node;
			}
		}
		
		Deque<IndentsNode> stack = null;
		AssociativeTrieNode<E, ? extends List<? extends AssociativeTrieNode<E, ?>>> root = addedTree.absoluteRoot();
		StringBuilder builder = new StringBuilder();
		builder.append('\n');
		AssociativeTrieNode<E, List<AssociativeTrieNode<E, ?>>> nextNode = (AssociativeTrieNode<E, List<AssociativeTrieNode<E, ?>>>) root;
		String nodeIndent = "", subNodeIndent = "";
		IndentsNode nextItem;
		while(true) {
			builder.append(nodeIndent).
				append(nextNode.isAdded() ? BinaryTreeNode.ADDED_NODE_CIRCLE : BinaryTreeNode.NON_ADDED_NODE_CIRCLE).
				append(' ').append(nextNode.getKey()).append('\n');
			List<AssociativeTrieNode<E, ?>> nextNodes = nextNode.getValue();
			if(nextNodes != null && nextNodes.size() > 0) {
				
				AssociativeTrieNode<E, ?> nNode;
				AssociativeTrieNode<E, List<AssociativeTrieNode<E, ?>>> next;
				
				int i = nextNodes.size() - 1;
				Indents lastIndents = new Indents(
						subNodeIndent + BinaryTreeNode.RIGHT_ELBOW,
						subNodeIndent + BinaryTreeNode.BELOW_ELBOWS);
				nNode = nextNodes.get(i);
				next = (AssociativeTrieNode<E, List<AssociativeTrieNode<E, ?>>>) nNode;
				if(stack == null) {
					stack = new ArrayDeque<>(addedTree.size());
				}
				stack.addFirst(new IndentsNode(lastIndents, next));
				if(nextNodes.size() > 1) {
					Indents firstIndents = new Indents(
							subNodeIndent + BinaryTreeNode.LEFT_ELBOW,
							subNodeIndent + BinaryTreeNode.IN_BETWEEN_ELBOWS);
					for(--i; i >= 0; i--) {
						nNode = nextNodes.get(i);
						next = (AssociativeTrieNode<E, List<AssociativeTrieNode<E, ?>>>) nNode;
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

	/**
	* Constructs a trie in which added nodes are mapped to their list of added sub-nodes.
	* 
	* @return
	*/
	@SuppressWarnings("unchecked")
	protected void contructAddedTree(AssociativeAddressTrie<E, ? extends List<? extends AssociativeTrieNode<E, ?>>> emptyTrie) {
		emptyTrie.addTrie(absoluteRoot());
		CachingIterator<? extends AssociativeTrieNode<E, ? extends List<? extends AssociativeTrieNode<E, ?>>>, E,
				AssociativeTrieNode<E, List<? extends AssociativeTrieNode<E, ?>>>> iterator = 
					emptyTrie.containingFirstAllNodeIterator(true);
		while(iterator.hasNext()) {
			AssociativeTrieNode<E, List<? extends AssociativeTrieNode<E, ?>>> next = (AssociativeTrieNode<E, List<? extends AssociativeTrieNode<E, ?>>>) iterator.next(), parent;
			// cache this node with its sub-nodes
			iterator.cacheWithLowerSubNode(next);
			iterator.cacheWithUpperSubNode(next);
			
			// the cached object is our parent
			if(next.isAdded()) {
				parent = iterator.getCached();
				if(parent != null) {
					// find added parent, or the root if no added parent
					// this part would be tricky if we accounted for the bounds,
					// maybe we'd have to filter on the bounds, and also look for the sub-root
					while(!parent.isAdded()) {
						AssociativeTrieNode<E, List<? extends AssociativeTrieNode<E, ?>>> parentParent = parent.getParent();
						if(parentParent == null) {
							break;
						}
						parent = parentParent;
					}
					// store ourselves with that added parent or root
					List<AssociativeTrieNode<E, ?>> addedSubs = (List<AssociativeTrieNode<E, ?>>) parent.getValue();
					if(addedSubs == null) {
						addedSubs = new ArrayList<AssociativeTrieNode<E, ?>>(next.size() - 1);
						parent.setValue(addedSubs);
					}
					addedSubs.add(next);
				} // else root
			}
		}
		Iterator<? extends AssociativeTrieNode<E, ? extends List<? extends TrieNode<E>>>> iter = emptyTrie.allNodeIterator(true);
		AssociativeTrieNode<E, ? extends List<? extends TrieNode<E>>> root = emptyTrie.absoluteRoot();
		List<? extends TrieNode<E>> list = root.getValue();
		if(list != null) {
			((ArrayList<? extends TrieNode<E>>) list).trimToSize();
		}
		while(iter.hasNext()) {
			list = iter.next().getValue();
			if(list != null) {
				((ArrayList<? extends TrieNode<E>>) list).trimToSize();
			}
		}
	}

	TrieNode<E> addNode(OpResult<E> result, TrieNode<E> fromNode, TrieNode<E> nodeToAdd, boolean withValues) {
		fromNode.matchBits(fromNode.getKey().getPrefixLength(), result);
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
			//return new KeySpliterator<E>(descendingNodeSpliterator(), comp.comparator);
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
				result.root = root.cloneTree(bounds);
			} else {
				// clone the root ourselves, then clone the trie starting from the subroot, and make it a child of the root
				BinaryTreeNode<E> clonedRoot = root.cloneTreeNode(new ChangeTracker()); // clone root node only
				result.root = clonedRoot;
				clonedRoot.setAdded(false); // not in bounds, so not part of new trie
				clonedRoot.setLower(null);
				clonedRoot.setUpper(null);
				TrieNode<E> subRoot = getRoot();
				if(subRoot != null) {
					TrieNode<E> subCloned = subRoot.cloneTree(bounds);
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

	public static String toString(boolean withNonAddedKeys, AddressTrie<?> ...tries) {
		StringBuilder builder = new StringBuilder('\n' + BinaryTreeNode.NON_ADDED_NODE_CIRCLE);
		String topLabel =  ' ' + Address.SEGMENT_WILDCARD_STR;
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
					builder.append(topLabel).append(" (").append(totalSize).append(')');
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
				builder.append(topLabel).append(" (0)");
			}
			builder.append('\n');
		}
		return builder.toString();
	}
}
