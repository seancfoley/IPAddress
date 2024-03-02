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
import java.math.BigInteger;
import java.util.Comparator;
import java.util.ConcurrentModificationException;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.PriorityQueue;
import java.util.Spliterator;
import java.util.function.BinaryOperator;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;

import inet.ipaddr.Address;
import inet.ipaddr.format.util.BinaryTreeNode.ChangeTracker.Change;
import inet.ipaddr.ipv6.IPv6Address;

/**
 * A binary tree node. 
 * <p>
 * Some binary tree nodes are considered "added" and others are not.
 * Those nodes created for key elements added to the tree are "added" nodes.  
 * Those that are not added are those nodes created to serve as junctions for the added nodes.
 * Only added elements contribute to the size of a tree.  
 * When removing nodes, non-added nodes are removed automatically whenever they are no longer needed,
 * which is when an added node has less than two added sub-nodes.
 * <p>
 * BinaryTreeNode objects have a read-only API, in the sense that they cannot be constructed directly.
 * Instead they are created indirectly by tree operations or by cloning existing nodes.
 * <p>
 * The API does allow you to remove them from trees, or to clone them.  They can also be used to traverse a tree. 
 * <p>
 * Nodes have various properties: the key, parent node, lower sub-node, upper sub-node, "added" property, and size.  
 * The "added" property can change if the node changes status following tree operations.
 * If removed from a tree the parent property can change, and the sub-nodes can change when sub-nodes are removed from the tree,
 * or other nodes are inserted into the tree, changing sub-nodes.  
 * However, none of these can be explicitly changed directly, they can only be changed indirectly by tree operations.
 * The key of a node never changes.
 * 
 * @author scfoley
 *
 * @param <E>
 */
public class BinaryTreeNode<E> implements TreeOps<E> {

	private static final long serialVersionUID = 1L;

	static String getMessage(String key) {
		return AbstractTree.getMessage(key);
	}

	static class Bounds<E> implements Serializable {

		private static final long serialVersionUID = 1L;

		final Comparator<? super E> comparator;

		final E lowerBound, upperBound;
		final boolean lowerInclusive, upperInclusive;

		Bounds(E lowerBound, boolean lowerInclusive, E upperBound, boolean upperInclusive, Comparator<? super E> comparator) {
			if(comparator == null) {
				throw new NullPointerException();
			}
			this.comparator = comparator;
			this.lowerBound = lowerBound;
			this.upperBound = upperBound;
			this.lowerInclusive = lowerInclusive;
			this.upperInclusive = upperInclusive;
			if(upperBound != null) {
				if(isBelowLowerBound(upperBound)) {
					throw new IllegalArgumentException(getMessage("ipaddress.error.address.lower.exceeds.upper") + " " + lowerBound + ", " + upperBound);
				}
			}
		}

		// throws IllegalArgumentException if expands the existing bounds on either end,
		// returns null if equivalent to the existing bounds
		Bounds<E> restrict(E lowerBound, boolean lowerInclusive, E upperBound, boolean upperInclusive) {
			return restrict(lowerBound, lowerInclusive, upperBound, upperInclusive, true);
		}
		
		Bounds<E> restrict(E lowerBound, boolean lowerInclusive, E upperBound, boolean upperInclusive, boolean thro) {
			// One thing we check is that the new bounds are at least more restrictive (when new bound is specified).
			// Also, when an exclusive bound is adjacent to an inclusive bound, we choose the exclusive bound.
			if(lowerBound != null) {
				BoundsCheck check = compareToLowerBound(lowerBound, lowerInclusive);
				if(check.isLessRestrictive()) {
					if(thro) {
						throw new IllegalArgumentException(getMessage("ipaddress.error.lower.below.range") + " " + lowerBound);
					}
					lowerBound = null;
				} else if(!check.isMoreRestrictive()) {
					// new bound has no effect
					if(check != BoundsCheck.EQUIVALENT_TO_INCLUSIVE) {
						// We prefer exclusive.
						// but if not switching inclusive to exclusive, no point in using the new bounds
						// for EQUIVALENT_TO_UNBOUNDED, SAME and EQUIVALENT_TO_EXCLUSIVE we throw away the new bound
						lowerBound = null;
					} // else EQUIVALENT_TO_INCLUSIVE means the new bound is exclusive, the existing one inclusive, so we choose the new one
				}
			}
			if(upperBound != null) {
				BoundsCheck check = compareToUpperBound(upperBound, upperInclusive);
				if(check.isLessRestrictive()) {
					if(thro) {
						throw new IllegalArgumentException(getMessage("ipaddress.error.lower.above.range") + " " + upperBound);
					}
					upperBound = null;
				} else if(!check.isMoreRestrictive()) {
					// new bound has no effect
					if(check != BoundsCheck.EQUIVALENT_TO_INCLUSIVE) {
						// we prefer exclusive,
						// but if not switching inclusive to exclusive, no point in using the new bounds
						upperBound = null;
					}// else EQUIVALENT_TO_INCLUSIVE means the new bound is exclusive, the existing one inclusive, so we choose the new one
				}
			}
			if(lowerBound == null) {
				if(upperBound == null) {
					return null;
				}
				lowerBound = this.lowerBound;
				lowerInclusive = this.lowerInclusive;
			}
			if(upperBound == null) {
				upperBound = this.upperBound;
				upperInclusive = this.upperInclusive;
			}
			return createBounds(lowerBound, lowerInclusive, upperBound, upperInclusive, comparator);
		}

		// return this if the intersection is equivalent to the existing
		Bounds<E> intersect(E lowerBound, boolean lowerInclusive, E upperBound, boolean upperInclusive) {
			Bounds<E> newBounds = restrict(lowerBound, lowerInclusive, upperBound, upperInclusive, false);
			if(newBounds == null) {
				return this;
			}
			return newBounds;
		}

		Bounds<E> createBounds(E lowerBound, boolean lowerInclusive, E upperBound, boolean upperInclusive, Comparator<? super E> comparator) {
			return new Bounds<E>(lowerBound, lowerInclusive, upperBound, upperInclusive, comparator);
		}

		public boolean isInBounds(E addr) {
			return isWithinLowerBound(addr) && isWithinUpperBound(addr);
		}

		public E getLowerBound() {
			return lowerBound;
		}

		public E getUpperBound() {
			return upperBound;
		}

		public boolean lowerIsInclusive() {
			return lowerInclusive;
		}

		public boolean upperIsInclusive() {
			return upperInclusive;
		}

		public boolean isLowerBounded() {
			return lowerBound != null;
		}

		public boolean isUpperBounded() {
			return upperBound != null;
		}

		public boolean isUnbounded() {
			return !isLowerBounded() && !isUpperBounded();
		}

		private int compare(E one, E two) {
			return comparator.compare(one, two);
		}

		public boolean isBelowLowerBound(E addr) {
			return isLowerBounded() && 
					(lowerInclusive ? compare(addr, lowerBound) < 0 :
						compare(addr, lowerBound) <= 0);
		}

		public boolean isWithinLowerBound(E addr) {
			return !isBelowLowerBound(addr);					
		}

		public boolean isAboveUpperBound(E addr) {
			return isUpperBounded() && 
					(upperInclusive ? compare(addr, upperBound) > 0 :
						compare(addr, upperBound) >= 0);
		}

		public boolean isWithinUpperBound(E addr) {
			return !isAboveUpperBound(addr);
		}

		BoundsCheck compareToLowerBound(E addr, boolean inclusive) {
			if(isLowerBounded()) {
				if(inclusive) {
					if(lowerInclusive) {
						// [existing [addr
						return BoundsCheck.convertEquivBoundaryComparison(compare(lowerBound, addr));
					}
					// (existing [addr
					int comp = compare(lowerBound, addr);
					if(comp >= 0) {
						return BoundsCheck.OUTSIDE;
					} else if(isAdjacentAboveLowerBound(addr)) {
						return BoundsCheck.EQUIVALENT_TO_EXCLUSIVE;
					}
					return BoundsCheck.INSIDE;
				} else if(lowerInclusive) {
					// [existing (addr
					int comp = compare(lowerBound, addr);
					if(comp <= 0) {
						return BoundsCheck.INSIDE;
					} else if(isAdjacentBelowLowerBound(addr)) {
						return BoundsCheck.EQUIVALENT_TO_INCLUSIVE;
					}
					return BoundsCheck.OUTSIDE;
				}
				// (existing (addr
				return BoundsCheck.convertEquivBoundaryComparison(compare(lowerBound, addr));
			}
			if(inclusive && isMin(addr)) {
				return BoundsCheck.EQUIVALENT_TO_UNBOUNDED;
			}
			return BoundsCheck.INSIDE;
		}

		BoundsCheck compareToUpperBound(E addr, boolean inclusive) {
			if(isUpperBounded()) {
				if(inclusive) {
					if(upperInclusive) {
						//existing] addr]
						return BoundsCheck.convertEquivBoundaryComparison(compare(addr, upperBound)); 
					}
					//existing) addr]
					int comp = compare(addr, upperBound);
					if(comp >= 0) {
						return BoundsCheck.OUTSIDE;
					} else if(isAdjacentBelowUpperBound(addr)) {
						return BoundsCheck.EQUIVALENT_TO_EXCLUSIVE;
					}
					return BoundsCheck.INSIDE;
				} else if(upperInclusive) {
					//existing] addr)
					int comp = compare(addr, upperBound);
					if(comp <= 0) {
						return BoundsCheck.INSIDE;
					} else if(isAdjacentAboveUpperBound(addr)) {
						return BoundsCheck.EQUIVALENT_TO_INCLUSIVE;
					}
					return BoundsCheck.OUTSIDE;
				}
				//existing) addr)
				return BoundsCheck.convertEquivBoundaryComparison(compare(addr, upperBound));
			}
			if(inclusive && isMax(addr)) {
				return BoundsCheck.EQUIVALENT_TO_UNBOUNDED;
			}
			return BoundsCheck.INSIDE;
		}

		static enum BoundsCheck {
			INSIDE(false, true), 
			EQUIVALENT_TO_UNBOUNDED(false, false), // no existing boundary, test boundary is closed at the end of range
			EQUIVALENT_TO_EXCLUSIVE(false, false), // existing boundary is exclusive, test boundary is inclusive and 1 step inside
			EQUIVALENT_TO_INCLUSIVE(false, false), // existing boundary is inclusive, test boundary is exclusive and 1 step outside
			SAME(false, false), 
			OUTSIDE(true, false);

			private boolean less, more;

			BoundsCheck(boolean lessRestrictive, boolean moreRestrictive) {
				less = lessRestrictive;
				more = moreRestrictive;
			}

			boolean isLessRestrictive() {
				return less;
			}

			boolean isMoreRestrictive() {
				return more;
			}

			static BoundsCheck convertEquivBoundaryComparison(int comparison) {
				if(comparison > 0) {
					return OUTSIDE;
				} else if(comparison < 0) {
					return INSIDE;
				}
				return SAME;
			}
		}

		// For discrete types, override the methods below

		boolean isMax(E addr) {
			return false;
		}

		boolean isMin(E addr) {
			return false;
		}

		boolean isAdjacentAboveUpperBound(E addr) {
			return false;
		}

		boolean isAdjacentBelowUpperBound(E addr) {
			return false;
		}

		boolean isAdjacentAboveLowerBound(E addr) {
			return false;
		}

		boolean isAdjacentBelowLowerBound(E addr) {
			return false;
		}

		public String toCanonicalString() {
			return toCanonicalString(" -> ");
		}

		public String toCanonicalString(String separator) {
			Function<? super E, String> stringer = Object::toString;
			return toString(stringer, separator, stringer);
		}

		public String toString(Function<? super E, String> lowerStringer, String separator, Function<? super E, String> upperStringer) {
			return toString(getLowerBound(), lowerIsInclusive(), getUpperBound(), upperIsInclusive(),
					lowerStringer, separator, upperStringer);
		}

		static <E> String toString(
				E lower,
				boolean lowerIsInclusive,
				E upper,
				boolean upperIsInclusive,
				Function<? super E, String> lowerStringer,
				String separator,
				Function<? super E, String> upperStringer) {
			String lowerStr;
			if(lower == null) {
				lowerStr = "";
			} else {
				lowerStr = lowerStringer.apply(lower);
				if(lowerIsInclusive) {
					lowerStr = '[' + lowerStr;
				} else {
					lowerStr = '(' + lowerStr;
				}
			}
			String upperStr;
			if(upper == null) {
				upperStr = "";
			} else {
				upperStr = upperStringer.apply(upper);
				if(upperIsInclusive) {
					upperStr += ']';
				} else {
					upperStr += ')';
				}
			}
			return lowerStr + separator + upperStr;
		}

		@Override
		public String toString() {
			return toCanonicalString();
		}
	}

	static class ChangeTracker implements Serializable {

		private static final long serialVersionUID = 1L;

		static class Change implements Cloneable, Serializable {

			private static final long serialVersionUID = 1L;

			boolean shared;

			private BigInteger big = BigInteger.ZERO;
			private int small;

			void increment() {
				if(++small == 0) {
					big = big.add(BigInteger.ONE);
				}
			}

			@Override
			public boolean equals(Object o) {
				return o instanceof Change && equalsChange((Change) o);
			}

			public boolean equalsChange(Change change) {
				return small == change.small && big.equals(change.big);
			}

			@Override
			public Change clone() {
				try {
					return (Change) super.clone();
				} catch (CloneNotSupportedException cannotHappen) {
					return null;
				}
			}

			@Override
			public String toString() {
				return big + " " + small;
			}
		}

		ChangeTracker() {}

		private Change currentChange = new Change();

		void changedSince(Change change) throws ConcurrentModificationException {
			if(isChangedSince(change)) {
				throw new ConcurrentModificationException();
			}
		}

		boolean isChangedSince(Change otherChange) {
			return !currentChange.equalsChange(otherChange);
		}

		Change getCurrent() {
			Change change = this.currentChange;
			change.shared = true;
			return change;
		}

		void changed() {
			Change change = this.currentChange;
			if(change.shared) {
				change = change.clone();
				change.shared = false;
				change.increment();
				this.currentChange = change;
			} // else nobody is watching the current change, so no need to do anything
		}

		@Override
		public String toString() {
			return "current change: " + currentChange;
		}
	}

	/**
	 * When set to true, the root is always 0.0.0.0/0 or ::/0 and setItem is never called,
	 * so the keys of a node never change.  This can make code that accessed nodes directly more predictable,
	 * a node will never change identity (although for a mapped node, the mapped value can change).
	 * <p>
	 * When set to false, the root of the tree is replaced by whatever node can replace it.
	 * So the tree is one node smaller and the depth is smaller by one.
	 * The down-side is that the root node can change identity, becoming the node for some other value, 
	 * and vice versa, some other valued node can become a root node again.
	 * So it is not advisable to work directly with nodes and change the tree at the same time.
	 */
	protected static boolean FREEZE_ROOT = true;

	// setting size to this value will cause a recalculation on calls to size(),
	// but in normal operation the size value starts at 0 and is never set to this value,
	// at this point it is just a debugging option
	static final int SIZE_UNKNOWN = -1;

	// describes the address or subnet
	private E item;
	private BinaryTreeNode<E> parent, lower, upper;
	int size;
	ChangeTracker changeTracker;

	// some nodes represent elements added to the tree and others are nodes generated internally when other nodes are added
	private boolean added;

	protected BinaryTreeNode(E item) { 
		this.item = item;
	}

	// when FREEZE_ROOT is true, this is never called (and FREEZE_ROOT is always true)
	protected void setKey(E item) {
		this.item = item;
	}

	/**
	 * Gets the key used for placing the node in the tree.
	 * 
	 * @return the key used for placing the node in the tree.
	 */
	public E getKey() {
		return item;
	}

	/**
	 * Returns whether this is the root of the backing tree.
	 * 
	 * @return
	 */
	public boolean isRoot() {
		return parent == null;
	}

	/**
	 * Gets the node from which this node is a direct child node, or null if this is the root.
	 * 
	 * @return
	 */
	public BinaryTreeNode<E> getParent() {
		return parent;
	}

	void setParent(BinaryTreeNode<E> parent) {
		this.parent = parent;
	}

	/**
	 * Gets the direct child node whose key is largest in value
	 * 
	 * @return
	 */
	public BinaryTreeNode<E> getUpperSubNode() {
		return upper;
	}

	/**
	 * Gets the direct child node whose key is smallest in value
	 * 
	 * @return
	 */
	public BinaryTreeNode<E> getLowerSubNode() {
		return lower;
	}

	protected void setUpper(BinaryTreeNode<E> upper) {
		this.upper = upper;
		if(upper != null) {
			upper.setParent(this);
		}
	}

	protected void setLower(BinaryTreeNode<E> lower) {
		this.lower = lower;
		if(lower != null) {
			lower.setParent(this);
		}
	}

	/**
	 * Some binary tree nodes are considered "added" and others are not.
	 * Those nodes created for key elements added to the tree are "added" nodes.  
	 * Those that are not added are those nodes created to serve as junctions for the added nodes.
	 * Only added elements contribute to the size of a tree.  
	 * When removing nodes, non-added nodes are removed automatically whenever they are no longer needed,
	 * which is when an added node has less than two added sub-nodes.
	 * 
	 * @return whether this node represents an element added to the tree
	 */
	public boolean isAdded() {
		return added;
	}

	/**
	 * Make this node an added node, which is equivalent to adding the corresponding address to the tree.
	 * If already added, this method has no effect.
	 * <p>
	 * You cannot set an added node to non-added, for that you should remove the node from the tree by calling {@link #remove()}.
	 * A non-added node will only remain in the tree if it needs to in the tree.
	 */
	public void setAdded() {
		if(!added) {
			setNodeAdded(true);
			adjustCount(1);
		}
	}

	protected void setNodeAdded(boolean added) {
		this.added = added;
	}

	/**
	 * Returns the count of nodes added to the sub-tree starting from this node as root and moving downwards to sub-nodes.
	 * This is a constant-time operation since the size is maintained in each node and adjusted with each add and remove operation in the sub-tree.
	 * @return
	 */
	public int size() {
		int storedSize = size;
		if(storedSize == SIZE_UNKNOWN) {
			Iterator<? extends BinaryTreeNode<E>> iterator = containedFirstAllNodeIterator(true);
			while(iterator.hasNext()) {
				BinaryTreeNode<E> next = iterator.next();
				int nodeSize = next.isAdded() ? 1 : 0;
				BinaryTreeNode<E> lower = next.getLowerSubNode();
				if(lower != null) {
					nodeSize += lower.size;
				}
				BinaryTreeNode<E> upper = next.getUpperSubNode();
				if(upper != null) {
					nodeSize += upper.size;
				}
				next.size = nodeSize;
			}
			storedSize = size;
		}
		return storedSize;
	}

	/**
	 * Returns the count of all nodes in the tree starting from this node and extending to all sub-nodes.
	 * Unlike {@link #size()}, this is not a constant-time operation and must visit all sub-nodes of this node.
	 * @return
	 */
	public int nodeSize() {
		int totalCount = 0;
		Iterator<? extends BinaryTreeNode<E>> iterator = iterator(true, false);//nodeIterator();xxx added only xxx;
		while(iterator.hasNext()) {
			totalCount++;
			iterator.next();
		}
		return totalCount;
	}

	void adjustCount(int delta) {
		if(delta != 0) {
			BinaryTreeNode<E> node = this;
			do {
				node.size += delta;
				node = node.getParent();
			} while(node != null);
		}
	}

	/**
	 * Removes this node from the list of added nodes, 
	 * and also removes from the tree if possible.  
	 * If it has two sub-nodes, it cannot be removed from the tree, in which case it is marked as not "added",
	 * nor is it counted in the tree size.
	 * Only added nodes can be removed from the tree.  If this node is not added, this method does nothing.
	 */
	public void remove() {
		if(!isAdded()) {
			return;
		}
		if(FREEZE_ROOT && isRoot()) {
			removed();
		} else if(getUpperSubNode() == null) {
			replaceThis(getLowerSubNode()); // also handles case of lower == null
		} else if(getLowerSubNode() == null) {
			replaceThis(getUpperSubNode());
		} else { // has two sub-nodes
			removed();
		}
	}

	void removed() {
		adjustCount(-1);
		setNodeAdded(false);
		changeTracker.changed();
	}

	/**
	 * Makes the parent of this point to something else, thus removing this and all sub-nodes from the tree
	 * @param replacement
	 */
	void replaceThis(BinaryTreeNode<E> replacement) {
		replaceThisRecursive(replacement, 0);
		changeTracker.changed();
	}

	void replaceThisRecursive(BinaryTreeNode<E> replacement, int additionalSizeAdjustment) {
		if(isRoot()) {
			replaceThisRoot(replacement);
			return;
		}
		BinaryTreeNode<E> parent = getParent();
		if(parent.getUpperSubNode() == this) {
			// we adjust parents first, using the size and other characteristics of ourselves,
			// before the parent severs the link to ourselves with the call to setUpper,
			// since the setUpper call is allowed to change the characteristics of the child,
			// and in some cases this does adjust the size of the child.
			adjustTree(parent, replacement, additionalSizeAdjustment, true);
			parent.setUpper(replacement);
		} else if(parent.getLowerSubNode() == this) {
			adjustTree(parent, replacement, additionalSizeAdjustment, false);
			parent.setLower(replacement);
		} else {
			throw new Error(); // will never reach here, indicates tree is corrupted somehow
		}
	}

	private void adjustTree(BinaryTreeNode<E> parent, BinaryTreeNode<E> replacement, int additionalSizeAdjustment, boolean replacedUpper) {
		int sizeAdjustment = -size;
		if(replacement == null) {
			if(!parent.isAdded() && (!FREEZE_ROOT || !parent.isRoot())) {
				parent.size += sizeAdjustment;
				BinaryTreeNode<E> parentReplacement = 
						replacedUpper ? parent.getLowerSubNode() : parent.getUpperSubNode();
				parent.replaceThisRecursive(parentReplacement, sizeAdjustment);
			} else {
				parent.adjustCount(sizeAdjustment + additionalSizeAdjustment);
			}
		} else {
			parent.adjustCount(replacement.size + sizeAdjustment + additionalSizeAdjustment);
		}
		setParent(null);
	}

	protected void replaceThisRoot(BinaryTreeNode<E> replacement) {
		if(replacement == null) {
			setNodeAdded(false);
			setUpper(null);
			setLower(null);
			if(!FREEZE_ROOT) {
				setKey(null);
			}
			size = 0;
		} else {
			// We never go here when FREEZE_ROOT is true
			setNodeAdded(replacement.isAdded());
			setUpper(replacement.getUpperSubNode());
			setLower(replacement.getLowerSubNode());
			setKey(replacement.getKey());
			size = replacement.size;
		}
	}

	/**
	 * Removes this node and all sub-nodes from the tree, after which isEmpty() will return true.
	 */
	public void clear() {
		replaceThis(null);
	}

	/**
	 * Returns where there are not any elements in the sub-tree with this node as the root.
	 */
	public boolean isEmpty() {
		return !isAdded() && getUpperSubNode() == null && getLowerSubNode() == null;
	}

	/**
	 * Returns whether this node is in the tree (is a node for which {@link #isAdded()} is true)
	 * and additional there are other elements in the sub-tree with this node as the root.
	 */
	public boolean isLeaf() {
		return isAdded() && getUpperSubNode() == null && getLowerSubNode() == null;
	}

	/**
	 * Returns the first (lowest valued) node in the sub-tree originating from this node.
	 * 
	 * @return
	 */
	public BinaryTreeNode<E> firstNode() {
		BinaryTreeNode<E> first = this;
		while(true) {
			BinaryTreeNode<E> lower = first.getLowerSubNode();
			if(lower == null) {
				return first;
			}
			first = lower;
		}
	}

	/**
	 * Returns the first (lowest valued) added node in the sub-tree originating from this node,
	 * or null if there are no added entries in this tree or sub-tree
	 * @return
	 */
	public BinaryTreeNode<E> firstAddedNode() {
		BinaryTreeNode<E> first = firstNode();
		if(first.isAdded()) {
			return first;
		}
		return first.nextAddedNode();
	}

	/**
	 * Returns the last (highest valued) node in the sub-tree originating from this node.
	 * 
	 * @return
	 */
	public BinaryTreeNode<E> lastNode() {
		BinaryTreeNode<E> last = this;
		while(true) {
			BinaryTreeNode<E> upper = last.getUpperSubNode();
			if(upper == null) {
				return last;
			}
			last = upper;
		}
	}

	/**
	 * Returns the last (highest valued) added node in the sub-tree originating from this node,
	 * or null if there are no added entries in this tree or sub-tree
	 * @return
	 */
	public BinaryTreeNode<E> lastAddedNode() {
		BinaryTreeNode<E> last = lastNode();
		if(last.isAdded()) {
			return last;
		}
		return last.previousAddedNode();
	}

	BinaryTreeNode<E> firstPostOrderNode() {
		BinaryTreeNode<E> next = this, nextNext;
		while(true) {
			nextNext = next.getLowerSubNode();
			if(nextNext == null) {
				nextNext = next.getUpperSubNode();
				if(nextNext == null) {
					return next;
				}
			} 
			next = nextNext;
		}
	}

	BinaryTreeNode<E> lastPreOrderNode() {
		BinaryTreeNode<E> next = this, nextNext;
		while(true) {
			nextNext = next.getUpperSubNode();
			if(nextNext == null) {
				nextNext = next.getLowerSubNode();
				if(nextNext == null) {
					return next;
				}
			} 
			next = nextNext;
		}
	}

	/**
	 * Returns the node that follows this node following the tree order
	 * 
	 * @return
	 */
	public BinaryTreeNode<E> nextNode() {
		return nextNode(null);
	}

//	in-order
//	
//				8x
//		4x					12x
//	2x		6x			10x		14x
//1x 3x		5x 7x		9x 11x	13x 15x
	BinaryTreeNode<E> nextNode(BinaryTreeNode<E> bound) {
		BinaryTreeNode<E> next = getUpperSubNode();
		if(next != null) {
			while(true) {
				BinaryTreeNode<E> nextLower = next.getLowerSubNode();
				if(nextLower == null) {
					return next;
				}
				next = nextLower;
			}
		} else {
			next = getParent();
			if(next == bound) {
				return null;
			}
			BinaryTreeNode<E> current = this;
			while(next != null && current == next.getUpperSubNode()) {
				current = next;
				next = next.getParent();
				if(next == bound) {
					return null;
				}
			}
		}
		return next;
	}

	/**
	 * Returns the node that precedes this node following the tree order.
	 * 
	 * @return
	 */
	public BinaryTreeNode<E> previousNode() {
		return previousNode(null);
	}

//	reverse order
//
//				8x
//		12x					4x
//	14x		10x			6x		2x
//15x 13x	11x 9x		7x 5x	3x 1x
	BinaryTreeNode<E> previousNode(BinaryTreeNode<E> bound) {
		BinaryTreeNode<E> previous = getLowerSubNode();
		if(previous != null) {
			while(true) {
				BinaryTreeNode<E> previousUpper = previous.getUpperSubNode();
				if(previousUpper == null) {
					break;
				}
				previous = previousUpper;
			}
		} else {
			previous = getParent();
			if(previous == bound) {
				return null;
			}
			BinaryTreeNode<E> current = this;
			while(previous != null && current == previous.getLowerSubNode()) {
				current = previous;
				previous = previous.getParent();
				if(previous == bound) {
					return null;
				}
			}
		}
		return previous;
	}
	
//	pre order
//				1x
//		2x						9x
//3x		6x				10x		13x
//4x 5x		7x 8x		11x 12x		14x 15x
	// this one starts from root, ends at last node, all the way right
	BinaryTreeNode<E> nextPreOrderNode(BinaryTreeNode<E> end) {
		BinaryTreeNode<E> next = getLowerSubNode();
		if(next == null) {
			// cannot go left/lower
			next = getUpperSubNode();
			if(next == null) {
				// cannot go right/upper
				BinaryTreeNode<E> current = this;
				next = getParent();
				// so instead, keep going up until we can go right 
				while(next != null) {
					if(next == end) {
						return null;
					}
					if(current == next.getLowerSubNode()) {
						// parent is higher
						BinaryTreeNode<E> nextNext = next.getUpperSubNode();
						if(nextNext != null) {
							return nextNext;
						}
					}
					current = next;
					next = next.getParent();
				}
			}
		}
		return next;
	}

//	reverse post order
//				1x
//		9x					2x
//	13x		10x			6x		3x
//15x 14x	12x 11x		8x 7x	5x 4x
	// this one starts from root, ends at first node, all the way left
	// this is the mirror image of nextPreOrderNode, so no comments
	BinaryTreeNode<E> previousPostOrderNode(BinaryTreeNode<E> end) {
		BinaryTreeNode<E> next = getUpperSubNode();
		if(next == null) {
			next = getLowerSubNode();
			if(next == null) {
				BinaryTreeNode<E> current = this;
				next = getParent();
				while(next != null) {
					if(next == end) {
						return null;
					}
					if(current == next.getUpperSubNode()) {
						BinaryTreeNode<E> nextNext = next.getLowerSubNode();
						if(nextNext != null) {
							next = nextNext;
							break;
						}
					}
					current = next;
					next = next.getParent();
				}
			}
		}
		return next;
	}

//	reverse pre order
//	
//				15x
//		14x					7x
//	13x		10x			6x		3x
//12x 11x	9x 8x		5x 4x	2x 1x

	// this one starts from last node, all the way right, ends at root
	// this is the mirror image of nextPostOrderNode, so no comments
	BinaryTreeNode<E> previousPreOrderNode(BinaryTreeNode<E> end) {
		BinaryTreeNode<E> next = getParent();
		if(next == null || next == end) {
			return null;
		}
		if(next.getLowerSubNode() == this) {
			return next;
		}
		BinaryTreeNode<E> nextNext = next.getLowerSubNode();
		if(nextNext == null) {
			return next;
		}
		next = nextNext;
		while(true) {
			nextNext = next.getUpperSubNode();
			if(nextNext == null) {
				nextNext = next.getLowerSubNode();
				if(nextNext == null) {
					return next;
				}
			}
			next = nextNext;
		}
	}
	
//	post order
//				15x
//		7x					14x
//	3x		6x			10x		13x
//1x 2x		4x 5x		8x 9x	11x 12x
	// this one starts from first node, all the way left, ends at root
	BinaryTreeNode<E> nextPostOrderNode(BinaryTreeNode<E> end) {
		BinaryTreeNode<E> next = getParent();
		if(next == null || next == end) {
			return null;
		}
		if(next.getUpperSubNode() == this) {
			// we are the upper sub-node, so parent is next
			return next;
		}
		// we are the lower sub-node
		BinaryTreeNode<E> nextNext = next.getUpperSubNode();
		if(nextNext == null) {
			// parent has no upper sub-node, so parent is next
			return next;
		}
		// go to parent's upper sub-node
		next = nextNext;
		// now go all the way down until we can go no further, favoring left/lower turns over right/upper
		while(true) {
			nextNext = next.getLowerSubNode();
			if(nextNext == null) {
				nextNext = next.getUpperSubNode();
				if(nextNext == null) {
					return next;
				}
				//next = nextNext;
			} //else {
				next = nextNext;
			//}
		}
	}

	/**
	 * Returns the next node in the tree that is an added node, following the tree order,
	 * or null if there is no such node.
	 * 
	 * @return
	 */
	public BinaryTreeNode<E> nextAddedNode() {
		return nextAdded(null, BinaryTreeNode<E>::nextNode);
	}

	/**
	 * Returns the previous node in the tree that is an added node, following the tree order in reverse, 
	 * or null if there is no such node.
	 * 
	 * @return
	 */
	public BinaryTreeNode<E> previousAddedNode() {
		return nextAdded(null, BinaryTreeNode<E>::previousNode);
	}

	private static <E> BinaryTreeNode<E> nextTest(BinaryTreeNode<E> current, BinaryTreeNode<E> end, BinaryOperator<BinaryTreeNode<E>> nextOperator, Predicate<BinaryTreeNode<E>> tester) {
		do {
			current = nextOperator.apply(current, end);
			if(current == end || current == null) {
				return null;
			}
		} while(!tester.test(current));
		return current;
	}

	private BinaryTreeNode<E> nextAdded(BinaryTreeNode<E> end, BinaryOperator<BinaryTreeNode<E>> nextOperator) {
		return nextTest(this, end, nextOperator, BinaryTreeNode<E>::isAdded);
	}
	
	private BinaryTreeNode<E> nextInBounds(BinaryTreeNode<E> end, BinaryOperator<BinaryTreeNode<E>> nextOperator, Bounds<E> bounds) {
		return nextTest(this, end, nextOperator, node -> bounds.isInBounds(node.getKey()));
	}

	/**
	 * Returns an iterator that iterates through the elements of the sub-tree with this node as the root.
	 * The iteration is in sorted element order.
	 * 
	 * @return
	 */
	@Override
	public Iterator<E> iterator() {
		return new KeyIterator<E>(nodeIterator(true));
	}

	/**
	 * Returns an iterator that iterates through the elements of the subtrie with this node as the root.
	 * The iteration is in reverse sorted element order.
	 * 
	 * @return
	 */
	@Override
	public Iterator<E> descendingIterator() {
		return new KeyIterator<E>(nodeIterator(false));
	}

	/**
	 * Iterates through the added nodes of the sub-tree with this node as the root, in forward or reverse tree order.
	 * 
	 * @return
	 */
	@Override
	public Iterator<? extends BinaryTreeNode<E>> nodeIterator(boolean forward) {
		return iterator(forward, true);
	}

	/**
	 * Iterates through all the nodes of the sub-tree with this node as the root, in forward or reverse tree order.
	 * 
	 * @return
	 */
	@Override
	public Iterator<? extends BinaryTreeNode<E>> allNodeIterator(boolean forward) {
		return iterator(forward, false);
	}

	// not public because this class is generic and not aware of address, blocks, prefix lengths, etc
	<C> CachingIterator<? extends BinaryTreeNode<E>, E, C> blockSizeCachingAllNodeIterator() {
		return new BlockSizeCachingNodeIterator<E, C>(this, false, changeTracker);
	}

	// not public because this class is generic and not aware of address, blocks, prefix lengths, etc
	Iterator<? extends BinaryTreeNode<E>> blockSizeNodeIterator(boolean lowerSubNodeFirst, boolean addedNodesOnly) {
		return new BlockSizeNodeIterator<E>(
				addedNodesOnly ? size() : 0,
				addedNodesOnly,
				this,
				!lowerSubNodeFirst,
				changeTracker);
	}

	@Override
	public <C> CachingIterator<? extends BinaryTreeNode<E>, E, C> containingFirstIterator(boolean forwardSubNodeOrder)  {
		return containingFirstIterator(forwardSubNodeOrder, true);
	}
	
	@Override
	public <C> CachingIterator<? extends BinaryTreeNode<E>, E, C> containingFirstAllNodeIterator(boolean forwardSubNodeOrder)  {
		return containingFirstIterator(forwardSubNodeOrder, false);
	}

	private <C> CachingIterator<? extends BinaryTreeNode<E>, E, C> containingFirstIterator(boolean forwardSubNodeOrder, boolean addedNodesOnly)  {
		if(forwardSubNodeOrder) {
			return new PreOrderNodeIterator<E, C>(
					true, // forward
					addedNodesOnly, // added only
					this,
					getParent(),
					changeTracker);
		} else {
			return new PostOrderNodeIterator<E, C>(
					false, // forward
					addedNodesOnly, // added only
					this,
					getParent(),
					changeTracker);
		}
	}

	@Override
	public Iterator<? extends BinaryTreeNode<E>> containedFirstIterator(boolean forwardSubNodeOrder)  {
		return containedFirstIterator(forwardSubNodeOrder, true);
	}

	@Override
	public Iterator<? extends BinaryTreeNode<E>> containedFirstAllNodeIterator(boolean forwardSubNodeOrder)  {
		return containedFirstIterator(forwardSubNodeOrder, false);
	}
	
	private Iterator<? extends BinaryTreeNode<E>> containedFirstIterator(boolean forwardSubNodeOrder, boolean addedNodesOnly)  {
		if(forwardSubNodeOrder) {
			return new PostOrderNodeIterator<E, Object>(
					true,
					addedNodesOnly, // added only
					firstPostOrderNode(),
					getParent(),
					changeTracker);
		} else {
			return new PreOrderNodeIterator<E, Object>(
					false,
					addedNodesOnly, // added only
					lastPreOrderNode(),
					getParent(),
					changeTracker);
		}
	}

	private NodeIterator<E> iterator(boolean forward, boolean addedOnly) {
		return new NodeIterator<E>(
				forward,
				addedOnly,
				forward ? firstNode() : lastNode(),
				getParent(),
				changeTracker);
	}

	static class KeyIterator<E> implements Iterator<E> {
		private Iterator<? extends BinaryTreeNode<E>> iterator;

		KeyIterator(Iterator<? extends BinaryTreeNode<E>> iterator) {
			this.iterator = iterator;
		}

		@Override
		public boolean hasNext() {
			return iterator.hasNext();
		}

		@Override
		public E next() {
			return iterator.next().getKey();
		}

		@Override
		public void remove() {
			iterator.remove();
		}
	}

	public static interface CachingIterator<N extends BinaryTreeNode<E>, E, C> extends Iterator<N> {
		/**
		 * After {@link #next()} has returned a node, 
		 * if an object was cached by a call to {@link #cacheWithLowerSubNode(Object)} or {@link #cacheWithUpperSubNode(Object)} 
		 * was called when that node's parent was previously returned by {@link #next()},
		 * then this returns that cached object.
		 * 
		 * @return the cached object
		 */
		C getCached();

		/**
		 * After {@link #next()} has returned a node, 
		 * calling this method caches the provided object with the lower sub-node so that it can 
		 * be retrieved with {@link #getCached()} when the lower sub-node is visited later.
		 * <p>
		 * Returns false if it could not be cached, either because the node has since been removed with a call to {@link #remove()},
		 * because {@link #next()} has not been called yet, or because there is no lower sub node for the node previously returned by {@link #next()}.
		 * <p>
		 * The caching and retrieval is done in constant time.
		 * 
		 * @param object the object to be retrieved later.
		 * 
		 */
		boolean cacheWithLowerSubNode(C object);

		/**
		 * After {@link #next()} has returned a node, 
		 * calling this method caches the provided object with the upper sub-node so that it can 
		 * be retrieved with {@link #getCached()} when the upper sub-node is visited later.
		 * <p>
		 * Returns false if it could not be cached, either because the node has since been removed with a call to {@link #remove()},
		 * because {@link #next()} has not been called yet, or because there is no upper sub node for the node previously returned by {@link #next()}.
		 * <p>
		 * The caching and retrieval is done in constant time.
		 * 
		 * 
		 * @param object the object to be retrieved later.
		 * 
		 * @return
		 */
		public boolean cacheWithUpperSubNode(C object);
	}

	/**
	 * This tree iterator does a binary tree traversal 
	 * in which every node will be visited before the node's sub-nodes are visited.
	 * It will visit nodes in key order of smallest address prefix-length to largest, which is largest block size to smallest.
	 * When prefix lengths match, order will go by prefix value.  
	 * For this comparison, an address with no prefix length is considered to have a prefix length extending to the end of the address.
	 */
	static class BlockSizeNodeIterator<E> extends AbstractNodeIterator<E> {
	
		static class Comp<E extends Address> implements Comparator<BinaryTreeNode<E>> {
			private final boolean reverseBlocksEqualSize;

			Comp(boolean reverseBlocksEqualSize) {
				this.reverseBlocksEqualSize = reverseBlocksEqualSize;
			}

			@Override
			public int compare(BinaryTreeNode<E> node1, BinaryTreeNode<E> node2) {
				E addr1 = node1.getKey();
				E addr2 = node2.getKey();
				if(addr1 == addr2) {
					return 0;
				}
				if(addr1.isPrefixed()) {
					if(addr2.isPrefixed()) {
						int val = addr1.getPrefixLength() - addr2.getPrefixLength();
						if(val == 0) {
							int compVal = compareLowValues(addr1, addr2);
							return reverseBlocksEqualSize ? -compVal : compVal;
						}
						return val;
					}
					return -1;
				}
				if(addr2.isPrefixed()) {
					return 1;
				}
				int compVal = compareLowValues(addr1, addr2);
				return reverseBlocksEqualSize ? -compVal : compVal;
			}
		};

		private static final Comparator<?> COMP = new Comp<>(false), REVERSE_COMP = new Comp<>(true);

		// heap will have either a caching objectwith the node or just the node
		PriorityQueue<BinaryTreeNode<E>> queue;
		private final boolean addedOnly;
		private final Bounds<E> bounds;

		// this one starts from root, ends at last node, all the way right
		BlockSizeNodeIterator(
				int treeSize, // can be zero if calculating size is expensive
				boolean addedOnly,
				BinaryTreeNode<E> start,
				boolean reverseBlocksEqualSize,
				ChangeTracker changeTracker) {
			this(treeSize, null, addedOnly, start, reverseBlocksEqualSize, changeTracker);
		}

		@SuppressWarnings("unchecked")
		BlockSizeNodeIterator(
				int treeSize, // can be zero if calculating size is expensive
				Bounds<E> bounds,
				boolean addedOnly,
				BinaryTreeNode<E> start,
				boolean reverseBlocksEqualSize,
				ChangeTracker changeTracker) {
			super(start, null, changeTracker);
			this.addedOnly = addedOnly;
			this.bounds = bounds;
			Comparator<BinaryTreeNode<E>> comp = 
					(Comparator<BinaryTreeNode<E>>) (reverseBlocksEqualSize ? REVERSE_COMP : COMP);
			if(treeSize > 0) {
				int initialCapacity = treeSize >> 1;
				if(initialCapacity == 0) {
					initialCapacity = 1;
				}
				queue = new PriorityQueue<>(initialCapacity, comp);
			} else {
				queue = new PriorityQueue<>(comp);
			}
			next = getStart(start, null, bounds, addedOnly);
		}

		@Override
		BinaryOperator<BinaryTreeNode<E>> getToNextOperation() {
			BinaryOperator<BinaryTreeNode<E>> op = operator;
			if(op == null) {
				op = (currentNode, endNode) -> {
					BinaryTreeNode<E> lower = currentNode.getLowerSubNode();
					if(lower != null) {
						queue.add(lower);
					}
					BinaryTreeNode<E> upper = currentNode.getUpperSubNode();
					if(upper != null) {
						queue.add(upper);
					}
					BinaryTreeNode<E> node = queue.poll();
					return node == endNode ? null : node;
				};
				if(addedOnly) {
					BinaryOperator<BinaryTreeNode<E>> wrappedOp = op;
					op = (currentNode, endNode) -> currentNode.nextAdded(endNode, wrappedOp);
				}
				if(bounds != null) {
					BinaryOperator<BinaryTreeNode<E>> wrappedOp = op;
					op = (currentNode, endNode) -> currentNode.nextInBounds(endNode, wrappedOp, bounds);
				}
				operator = op;
			}
			return op;
		}
	}

	static int compareLowValues(Address one, Address two) {
		return Address.ADDRESS_LOW_VALUE_COMPARATOR.compare(one, two);
	}

	/**
	 * This is a tree iterator that does a binary tree traversal 
	 * in which every node will be visited before the node's sub-nodes are visited.
	 * This tree iterator will visit nodes in key order of smallest address prefix-length first. 
	 * When prefix lengths match, the order will be by prefix value.  
	 * For this comparison, an address with no prefix length is considered to have a prefix length extending to the end of the address.
	 * <p>
	 * This tree iterator allows you to provide iteration context from a parent to its sub-nodes when iterating.
	 * <p>
	 */
	static class BlockSizeCachingNodeIterator<E, C> extends AbstractNodeIterator<E> implements CachingIterator<BinaryTreeNode<E>, E, C> {
		
		static class Comp<E extends Address> implements Comparator<Cached<E, ?>> {

			private final boolean reverseBlocksEqualSize;

			Comp(boolean reverseBlocksEqualSize) {
				this.reverseBlocksEqualSize = reverseBlocksEqualSize;
			}

			@Override
			public int compare(Cached<E, ?> o1, Cached<E, ?> o2) {
				BinaryTreeNode<E> node1 = o1.node, node2 = o2.node;
				E addr1 = node1.getKey(), addr2 = node2.getKey();
				if(addr1 == addr2) {
					return 0;
				}
				if(addr1.isPrefixed()) {
					if(addr2.isPrefixed()) {
						int val = addr1.getPrefixLength() - addr2.getPrefixLength();
						if(val == 0) {
							int compVal = compareLowValues(addr1, addr2);
							return reverseBlocksEqualSize ? -compVal : compVal;
						}
						return val;
					}
					return -1;
				}
				if(addr2.isPrefixed()) {
					return 1;
				}
				int compVal = compareLowValues(addr1, addr2);
				return reverseBlocksEqualSize ? -compVal : compVal;
			}
		};

		static class Cached<E, C> {
			BinaryTreeNode<E> node;
			C cached;
		}

		private static final Comparator<?> COMP = new Comp<>(false), REVERSE_COMP = new Comp<>(true);

		// heap will have the caching object with the node
		private PriorityQueue<Cached<E, C>> queue;

		private C cacheItem;
		private Cached<E, C> nextCachedItem;
		private Cached<E, C> lowerCacheObj, upperCacheObj;

		// this one starts from root, ends at last node, all the way right
		BlockSizeCachingNodeIterator(
				int treeSize,
				BinaryTreeNode<E> start,
				boolean reverseBlocksEqualSize,
				ChangeTracker changeTracker) {
			super(start, null, changeTracker);
			@SuppressWarnings("unchecked")
			Comparator<Cached<E, C>> comp = (Comparator<Cached<E, C>>) (reverseBlocksEqualSize ? REVERSE_COMP : COMP);
			if(treeSize == 0) {
				queue = new PriorityQueue<>(comp);
			} else {
				queue = new PriorityQueue<>(treeSize >> 1, comp);
			}
			next = getStart(start, null, null, false);
		}
		
		BlockSizeCachingNodeIterator(
				BinaryTreeNode<E> start,
				boolean reverseBlocksEqualSize,
				ChangeTracker changeTracker) {
			this(0, start, reverseBlocksEqualSize, changeTracker);
		}

		@Override
		BinaryOperator<BinaryTreeNode<E>> getToNextOperation() {
			BinaryOperator<BinaryTreeNode<E>> op = operator;
			if(op == null) {
				op = (currentNode, endNode) -> {
					BinaryTreeNode<E> lower = currentNode.getLowerSubNode();
					if(lower != null) {
						Cached<E, C> cached = new Cached<>();
						cached.node = lower;
						lowerCacheObj = cached;
						queue.add(cached);
					} else {
						lowerCacheObj = null;
					}
					BinaryTreeNode<E> upper = currentNode.getUpperSubNode();
					if(upper != null) {
						Cached<E, C> cached = new Cached<>();
						cached.node = upper;
						upperCacheObj = cached;
						queue.add(cached);
					} else {
						upperCacheObj = null;
					}
					if(nextCachedItem != null) {
						cacheItem = nextCachedItem.cached;
					}
					Cached<E, C> cached =  queue.poll();
					if(cached != null) {
						BinaryTreeNode<E> node = cached.node;
						if(node != endNode) {
							nextCachedItem = cached;
							return node;
						}
						
					}
					nextCachedItem = null;
					return null;
				};
				operator = op;
			}
			return op;
		}

		@Override
		public C getCached() {
			return cacheItem;
		}

		@Override
		public boolean cacheWithLowerSubNode(C object) {
			if(lowerCacheObj != null) {
				lowerCacheObj.cached = object;
				return true;
			}
			return false;
		}

		@Override
		public boolean cacheWithUpperSubNode(C object) {
			if(upperCacheObj != null) {
				upperCacheObj.cached = object;
				return true;
			}
			return false;
		}
	}

	/**
	 * The caching only useful when in reverse order, since you have to visit parent nodes first for it to be useful.
	 * 
	 * @author scfoley
	 *
	 * @param <N>
	 * @param <E>
	 * @param <C>
	 */
	static class PostOrderNodeIterator<E, C> extends SubNodeCachingIterator<E, C> {

		//starts from first node, all the way left, ends at root
		PostOrderNodeIterator(
				boolean isForward,
				boolean addedOnly,
				BinaryTreeNode<E> start,
				BinaryTreeNode<E> bound,
				ChangeTracker changeTracker) {
			this(null, isForward, addedOnly, start, bound, changeTracker);
		}
		
		PostOrderNodeIterator(
				Bounds<E> bounds,
				boolean isForward,
				boolean addedOnly,
				BinaryTreeNode<E> start,
				BinaryTreeNode<E> end,
				ChangeTracker changeTracker) {
			super(bounds, isForward, addedOnly, start, end, changeTracker);
		}

		@Override
		void checkCaching() {
			if(isForward) {
				throw new Error();
			}
		}

		@Override
		void populateCacheItem() {
			if(!isForward) {
				super.populateCacheItem();
			}
		}

		@Override
		BinaryOperator<BinaryTreeNode<E>> getToNextOperation() {
			BinaryOperator<BinaryTreeNode<E>> op = operator;
			if(op == null) {
				op = isForward ? BinaryTreeNode<E>::nextPostOrderNode : BinaryTreeNode<E>::previousPostOrderNode;
				// do the added-only filter first, because it is simpler
				if(addedOnly) {
					BinaryOperator<BinaryTreeNode<E>> wrappedOp = op;
					op = (currentNode, endNode) -> currentNode.nextAdded(endNode, wrappedOp);
				}
				if(bounds != null) {
					BinaryOperator<BinaryTreeNode<E>> wrappedOp = op;
					op = (currentNode, endNode) -> currentNode.nextInBounds(endNode, wrappedOp, bounds);
				}
				operator = op;
			}
			return op;
		}

		@Override
		public void remove() {
			if(!isForward || addedOnly) {
				super.remove();
				return;
			}

			// Example:
			// Suppose we are at right sub-node, just visited left.  Next node is parent, but not added.
			// When right is removed, so is the parent, so that the left takes its place.
			// But parent is our next node.  Now our next node is invalid.  So we are lost.
			// This is avoided for iterators that are "added" only.
			throw new UnsupportedOperationException();
		}
	}

	/**
	 * The caching only useful when in forward order, since you have to visit parent nodes first for it to be useful.
	 * @author scfoley
	 *
	 * @param <N>
	 * @param <E>
	 * @param <C>
	 */
	static class PreOrderNodeIterator<E, C> extends SubNodeCachingIterator<E, C> {

		// this one starts from root, ends at last node, all the way right
		PreOrderNodeIterator(
				boolean isForward,
				boolean addedOnly,
				BinaryTreeNode<E> start,
				BinaryTreeNode<E> bound,
				ChangeTracker changeTracker) {
			this(null, isForward, addedOnly, start, bound, changeTracker);
		}

		PreOrderNodeIterator(
				Bounds<E> bounds,
				boolean isForward,
				boolean addedOnly,
				BinaryTreeNode<E> start,
				BinaryTreeNode<E> end,
				ChangeTracker changeTracker) {
			super(bounds, isForward, addedOnly, start, end, changeTracker);
		}

		@Override
		BinaryOperator<BinaryTreeNode<E>> getToNextOperation() {
			BinaryOperator<BinaryTreeNode<E>> op = operator;
			if(op == null) {
				op = isForward ? BinaryTreeNode<E>::nextPreOrderNode : BinaryTreeNode<E>::previousPreOrderNode;
				// do the added-only filter first, because it is simpler
				if(addedOnly) {
					BinaryOperator<BinaryTreeNode<E>> wrappedOp = op;
					op = (currentNode, endNode) -> currentNode.nextAdded(endNode, wrappedOp);
				}
				if(bounds != null) {
					BinaryOperator<BinaryTreeNode<E>> wrappedOp = op;
					op = (currentNode, endNode) -> currentNode.nextInBounds(endNode, wrappedOp, bounds);
				}
				operator = op;
			}
			return op;
		}

		@Override
		void checkCaching() {
			if(!isForward) {
				throw new Error();
			}
		}

		@Override
		void populateCacheItem() {
			if(isForward) {
				super.populateCacheItem();
			}
		}
		
		@Override
		public void remove() {
			if(isForward || addedOnly) {
				super.remove();
				return;
			}
			// Example:
			// Suppose we are moving in reverse direction, at left sub-node, just visited right.  
			// Neither node has children.
			// Next node is parent, but not added.
			// When left is removed, so is the parent, so that the right takes its place.
			// But parent is our next node, and we already visited right.  
			// Now our next node is invalid.  So we are lost.
			// This is avoided for iterators that are "added" only.
			throw new UnsupportedOperationException();
		}
	}

	static abstract class SubNodeCachingIterator<E, C> extends AbstractNodeIterator<E> implements CachingIterator<BinaryTreeNode<E>, E, C> {
		private static final int STACK_SIZE = IPv6Address.BIT_COUNT + 2; // 129 for prefixes /0 to /128 and also 1 more for non-prefixed

		private C cacheItem;
		
		private E nextKey;
		private C nextCached;
		private Object stack[];
		private int stackIndex = -1;
		
		final Bounds<E> bounds;
		final boolean addedOnly, isForward;

		SubNodeCachingIterator(
				Bounds<E> bounds,
				boolean isForward,
				boolean addedOnly,
				BinaryTreeNode<E> start,
				BinaryTreeNode<E> end,
				ChangeTracker changeTracker) {
			super(start, end, changeTracker);
			this.isForward = isForward;
			this.addedOnly = addedOnly;
			this.bounds = bounds;
			next = getStart(start, end, bounds, addedOnly);
		}

		@Override
		BinaryTreeNode<E> doNext() {
			BinaryTreeNode<E> result = super.doNext();
			populateCacheItem();
			return result;
		}

		abstract void checkCaching();

		@Override
		public C getCached() {
			checkCaching();
			return cacheItem;
		}

		@SuppressWarnings("unchecked")
		void populateCacheItem() {
			E nextKey = this.nextKey;
			if(nextKey != null && current.getKey() == nextKey) {
				cacheItem = nextCached;
				nextCached = null;
				nextKey = null;
			} else {
				Object stack[] = this.stack;
				if(stack != null) {
					int stackIndex = this.stackIndex;
					if(stackIndex >= 0 && stack[stackIndex] == current.getKey()) {
						cacheItem = (C) stack[stackIndex + STACK_SIZE];
						stack[stackIndex + STACK_SIZE] = null;
						stack[stackIndex] = null;
						this.stackIndex--;
					} else {
						cacheItem = null;
					}
				} else {
					cacheItem = null;
				}
			}
		}

		@Override
		public boolean cacheWithLowerSubNode(C object) {
			return isForward ? cacheWithFirstSubNode(object) : cacheWithSecondSubNode(object);
		}

		@Override
		public boolean cacheWithUpperSubNode(C object) {
			return isForward ? cacheWithSecondSubNode(object) : cacheWithFirstSubNode(object);
		}

		// the sub-node will be the next visited node
		private boolean cacheWithFirstSubNode(C object) {
			checkCaching();
			if(current != null) {
				BinaryTreeNode<E> firstNode = isForward ? current.getLowerSubNode() : current.getUpperSubNode();
				if(firstNode != null) {
					if((addedOnly && !firstNode.isAdded()) || (bounds != null && !bounds.isInBounds(firstNode.getKey()))) {
						firstNode = getToNextOperation().apply(firstNode, current);
					}
					if(firstNode != null) {
						// the lower sub-node is always next if it exists
						nextKey = firstNode.getKey();
						//System.out.println(current + " cached with " + firstNode + ": " + object);
						nextCached = object;
						return true;
					}
				}
			}
			return false;
		}

		// the sub-node will only be the next visited node if there is no other sub-node, 
		// otherwise it might not be visited for a while
		private boolean cacheWithSecondSubNode(C object) {
			checkCaching();
			if(current != null) {
				BinaryTreeNode<E> secondNode = isForward ? current.getUpperSubNode() : current.getLowerSubNode();
				if(secondNode != null) {
					if((addedOnly && !secondNode.isAdded()) || (bounds != null && !bounds.isInBounds(secondNode.getKey()))) {
						secondNode = getToNextOperation().apply(secondNode, current);
					}
					if(secondNode != null) {
						// if there is no lower node, we can use the nextCached field since upper is next when no lower sub-node
						BinaryTreeNode<E> firstNode = isForward ? current.getLowerSubNode() : current.getUpperSubNode();
						if(firstNode == null) {
							nextKey = secondNode.getKey();
							nextCached = object;
						} else {
							if(stack == null) {
								stack = new Object[STACK_SIZE << 1];
							}
							stackIndex++;
							stack[stackIndex] = secondNode.getKey();
							stack[stackIndex + STACK_SIZE] = object;
						}
						return true;
					}
				}
			}
			return false;
		}
	}

	static class NodeIterator<E> extends AbstractNodeIterator<E> {

		final boolean forward, addedOnly;

		NodeIterator(
				boolean forward,
				boolean addedOnly,
				BinaryTreeNode<E> start, // inclusive
				BinaryTreeNode<E> end, // non-inclusive
				ChangeTracker changeTracker) {
			super(start, end, changeTracker);
			this.forward = forward;
			this.addedOnly = addedOnly;
			next = getStart(start, end, null, addedOnly);
		}

		@Override
		BinaryOperator<BinaryTreeNode<E>> getToNextOperation() {
			BinaryOperator<BinaryTreeNode<E>> op = operator;
			if(op == null) {
				op = forward ? BinaryTreeNode<E>::nextNode : BinaryTreeNode<E>::previousNode;
				if(addedOnly) {
					BinaryOperator<BinaryTreeNode<E>> wrappedOp = op;
					op = (currentNode, endNode) -> currentNode.nextAdded(endNode, wrappedOp);
				}
				operator = op;
			}
			return op;
		}
	}

	abstract static class AbstractNodeIterator<E> implements Iterator<BinaryTreeNode<E>> {
		private final ChangeTracker changeTracker;
		private Change currentChange;
		
		BinaryTreeNode<E> current, next;
		BinaryTreeNode<E> end; // a non-null node that denotes the end, possibly parent of the starting node
		
		// takes current node and end as args
		BinaryOperator<BinaryTreeNode<E>> operator;

		AbstractNodeIterator(
				BinaryTreeNode<E> start, // inclusive
				BinaryTreeNode<E> end, // non-inclusive
				ChangeTracker changeTracker) {
			this.end = end;
			this.changeTracker = changeTracker;
			if(changeTracker != null) {
				currentChange = changeTracker.getCurrent();
			}
		}

		abstract BinaryOperator<BinaryTreeNode<E>> getToNextOperation();

		BinaryTreeNode<E> getStart(
				BinaryTreeNode<E> start,
				BinaryTreeNode<E> end,
				Bounds<E> bounds,
				boolean addedOnly) {
			if(start == end || start == null) {
				return null;
			}
			if(!addedOnly || start.isAdded()) {
				if(bounds == null || bounds.isInBounds(start.getKey())) {
					return start;
				}
			}
			return toNext(start);
		}

		@Override
		public boolean hasNext() {
			return next != null;
		}

		@Override
		public BinaryTreeNode<E> next() {
			if(!hasNext()) {
				throw new NoSuchElementException();
			}
			return doNext();
		}

		BinaryTreeNode<E> nextNoThrow() {
			if(!hasNext()) {
				return null;
			}
			return doNext();
		}

		BinaryTreeNode<E> doNext() {
			ChangeTracker changeTracker = this.changeTracker;
			if(changeTracker != null) {
				changeTracker.changedSince(currentChange);
			}
			current = next;
			next = toNext(next);
			return current;
		}

		BinaryTreeNode<E> toNext(BinaryTreeNode<E> current) {
			//lastLookAtCurrent(previous);
			BinaryOperator<BinaryTreeNode<E>> op = getToNextOperation();
			BinaryTreeNode<E> result = op.apply(current, end);
			return result;
		}

		@Override
		public void remove() {
			if (current == null) {
                throw new IllegalStateException(getMessage("ipaddress.error.no.iterator.element.to.remove"));
			}
			ChangeTracker changeTracker = this.changeTracker;
			if(changeTracker != null) {
				changeTracker.changedSince(currentChange);
			}
			current.remove();
			current = null;
			if(changeTracker != null) {
				currentChange = changeTracker.getCurrent();
			}
		}
	}

	static class NodeSpliterator<E> implements Spliterator<BinaryTreeNode<E>> {
		private final ChangeTracker changeTracker;
		private Change currentChange;
		
		private final Comparator<? super BinaryTreeNode<E>> comparator;
		
		private static enum Side {
			ALL, BEGINNING, ENDING;
		}
		
		private Side position; // ALL, LOWER, or UPPER
		
		private BinaryTreeNode<E> begin, end, root;
		private NodeIterator<E> iterator;
		private long sizeEstimate;
		private final boolean addedOnly, forward;

		NodeSpliterator(
				boolean forward,
				Comparator<? super BinaryTreeNode<E>> comparator,
				BinaryTreeNode<E> root,
				BinaryTreeNode<E> begin,
				BinaryTreeNode<E> end,
				long size,
				ChangeTracker changeTracker,
				boolean addedOnly) {
			this(forward, comparator, Side.ALL, begin, end, size, changeTracker, addedOnly);
			this.root = root;
		}
		
		private NodeSpliterator(
				boolean forward,
				Comparator<? super BinaryTreeNode<E>> comparator,
				Side position,
				BinaryTreeNode<E> begin,
				BinaryTreeNode<E> end,
				long sizeEstimate,
				ChangeTracker changeTracker,
				boolean addedOnly) {
			this.comparator = comparator;
			this.sizeEstimate = sizeEstimate;
			this.end = end;
			this.begin = begin;
			this.position = position;
			this.changeTracker = changeTracker;
			this.addedOnly = addedOnly;
			this.forward = forward;
			currentChange = changeTracker.getCurrent();
		}
		
		@Override
		public String toString() {
			return "spliterator from " + begin + " to " + end;
		}
		
		private BinaryTreeNode<E> getMiddle()  {
			BinaryTreeNode<E> mid;
			if(position == Side.BEGINNING) {
				mid = forward ? end.getLowerSubNode() : end.getUpperSubNode();
			} else if(position == Side.ENDING) {
				mid = forward ? begin.getUpperSubNode() : begin.getLowerSubNode();
				if(mid != null && end != null && getComparator().compare(mid, end) >= 0) {
					// can only happen with bounded trees, in which there are more nodes to follow,
					// but there is in fact a potential middle node anyway.  In non-bounded trees,
					// the existince of that middle node means there are more nodes to follow.
					return null;
				}
			} else {//splitPosition == ALL
				mid = root;
			}
			return mid;
		}
		
		private BinaryTreeNode<E> nextNode(BinaryTreeNode<E> current, BinaryTreeNode<E> bound) {
			return forward ? current.nextNode(bound) : current.previousNode(bound);
		}
		
		@Override
		public Spliterator<BinaryTreeNode<E>> trySplit() {
			if(begin == null) {
				// nothing to split
				return null;
			}
			changeTracker.changedSince(currentChange);
			BinaryTreeNode<E> mid = getMiddle();
			if(mid == null) {
				return null;
			}
			BinaryTreeNode<E> current;
			if(iterator == null) {
				current = begin;
			} else {
				current = iterator.next;
				if(current == null) {
					return null;
				}
			}
			if(current == end) {
				return null;
			}

			position = Side.ENDING;
			
			// first we check if left split is empty, and if so, we split ourselves (the right split) again
			if((current == mid || getComparator().compare(current, mid) >= 0)) {
				begin = current;
				//the current left split which goes up to mid is empty, so split ourselves again to produce another left split
				return trySplit();
			} else {
				begin = mid;
				if (addedOnly) while(!current.isAdded()) {
					current = nextNode(current, mid);
					if((current == mid || current == null)) {
						//the current left split is empty, so split ourselves again to produce another left split
						return trySplit();
					}
				}
			}
			
			
			// now we check if right split is empty
			BinaryTreeNode<E> next = mid;
			if (addedOnly) while(!next.isAdded()) {
				next = nextNode(next, end);
				if(next == end || next == null) {
					//the current right split is empty, so we copy over the left split to ourselves, and split again
					begin = current;
					end = mid;
					position = Side.BEGINNING;
					if(iterator != null) {
						iterator.end = mid;
					}
					return trySplit();
				}
			}
			
			// at this point we have two non-zero sized spliterators, so we're done
			long sizeEst = sizeEstimate;
			NodeSpliterator<E> lowerSplit = new NodeSpliterator<>(
					forward, comparator, Side.BEGINNING, current, mid, sizeEst >>> 1, changeTracker, addedOnly);
			sizeEstimate = (sizeEst + 1) >>> 1;
			if(iterator != null) {
				lowerSplit.iterator = iterator;
				iterator.end = mid;
			}
			iterator = null;
			return lowerSplit;
		}

		private NodeIterator<E> createIterator() {
			return new NodeIterator<E>(forward, addedOnly, begin, end, changeTracker);
		}

		private NodeIterator<E> provideIterator() {
			changeTracker.changedSince(currentChange);
			NodeIterator<E> iter = iterator;
			if(iter == null) {
				iter = createIterator();
				iterator = iter;
			}
			return iter;
		}

		@Override
		public boolean tryAdvance(Consumer<? super BinaryTreeNode<E>> action) {
			// change tracking exception handled by iterator
			BinaryTreeNode<E> next = provideIterator().nextNoThrow();
			if(next != null) {
				action.accept(next);
				return true;
			} else if(action == null) {
				throw new NullPointerException();
			}
			return false;
		}

		@Override
		public void forEachRemaining(Consumer<? super BinaryTreeNode<E>> action) {
			// change tracking exception handled by iterator
			BinaryTreeNode<E> next = provideIterator().nextNoThrow();
			if(next != null) {
				action.accept(next);
				while(true) {
					next = iterator.nextNoThrow();
					if(next == null) {
						break;
					}
					action.accept(next);
				}
			} else if(action == null) {
				throw new NullPointerException();
			}
	    }

		@Override
		public long estimateSize() {
			return sizeEstimate;
		}

		@Override
		public int characteristics() {
			int characteristics = Spliterator.DISTINCT | Spliterator.SORTED | Spliterator.ORDERED | Spliterator.NONNULL;
			if(position == Side.ALL) {
				characteristics |= Spliterator.SIZED;
			}
			return characteristics;
        }

        @Override
		public Comparator<? super BinaryTreeNode<E>> getComparator() {
        	return comparator;
        }
	}

	static class KeySpliterator<E> implements Spliterator<E> {
		private final Spliterator<? extends BinaryTreeNode<E>> wrapped;
		private final Comparator<? super E> comparator;

		KeySpliterator(Spliterator<? extends BinaryTreeNode<E>> wrapped,
				Comparator<? super E> comparator) {
			this.wrapped = wrapped;
			this.comparator = comparator;
		}

		private static <E> Consumer<? super BinaryTreeNode<E>> wrapAction(Consumer<? super E> action) {
			return node -> action.accept(node.getKey());
		}

		@Override
		public boolean tryAdvance(Consumer<? super E> action) {
			//return wrapped.tryAdvance(node -> wrapIt(node, action));
			return wrapped.tryAdvance(wrapAction(action));
		}

		@Override
		public void forEachRemaining(Consumer<? super E> action) {
			wrapped.forEachRemaining(wrapAction(action));
	    }

		@Override
		public Comparator<? super E> getComparator() {
			return comparator;
	    }

		@Override
		public Spliterator<E> trySplit() {
			Spliterator<? extends BinaryTreeNode<E>> split = wrapped.trySplit();
			if(split == null) {
				return null;
			}
			return new KeySpliterator<E>(split, comparator);
		}

		@Override
		public long estimateSize() {
			return wrapped.estimateSize();
		}

		@Override
		public long getExactSizeIfKnown() {
			return wrapped.getExactSizeIfKnown();
		}

		@Override
		public int characteristics() {
			return wrapped.characteristics();
		}

		@Override
		public String toString() {
			return wrapped.toString();
		}
	}

	//https://jrgraphix.net/r/Unicode/2500-257F
	//https://jrgraphix.net/r/Unicode/25A0-25FF
	static final String NON_ADDED_NODE_CIRCLE = "\u25cb";
	static final String ADDED_NODE_CIRCLE = "\u25cf";
	
	static final String LEFT_ELBOW = "\u251C\u2500"; 	// |-
	static final String IN_BETWEEN_ELBOWS = "\u2502 "; 	// |
	static final String RIGHT_ELBOW = "\u2514\u2500"; 	// --
	static final String BELOW_ELBOWS = "  ";

	static class Indents {
		final String nodeIndent, subNodeInd;
		
		Indents() {
			this("", "");
		}
		
		Indents(String nodeIndent, String subNodeIndent) {
			this.nodeIndent = nodeIndent;
			this.subNodeInd = subNodeIndent;
		}
	}

	/**
	 * Returns a visual representation of the sub-tree with this node as root, with one node per line.
	 * 
	 * @param withNonAddedKeys whether to show nodes that are not added nodes
	 * @param withSizes whether to include the counts of added nodes in each sub-tree
	 * @return
	 */
	public String toTreeString(boolean withNonAddedKeys, boolean withSizes) {
		StringBuilder builder = new StringBuilder("\n");
		printTree(builder, new Indents(), withNonAddedKeys, withSizes, this.<Indents>containingFirstAllNodeIterator(true));
		return builder.toString();
	}

	void printTree(StringBuilder builder, 
			Indents initialIndents,
			boolean withNonAdded, 
			boolean withSizes,
			CachingIterator<? extends BinaryTreeNode<E>, E, Indents> iterator) {
		while(iterator.hasNext()) {
			BinaryTreeNode<E> next = iterator.next();
			Indents cached = iterator.getCached();
			String nodeIndent, subNodeIndent;
			if(cached == null) {
				nodeIndent = initialIndents.nodeIndent;
				subNodeIndent = initialIndents.subNodeInd;
			} else {
				nodeIndent = cached.nodeIndent;
				subNodeIndent = cached.subNodeInd;
			}
			if(withNonAdded || next.isAdded()) {
				builder.append(nodeIndent).append(next); // appending next adds the ADDED_NODE_CIRCLE first
				if(withSizes) {
					builder.append(" (").append(next.size()).append(')');
				}
				builder.append('\n');
			} else {
				builder.append(nodeIndent).append(NON_ADDED_NODE_CIRCLE + "\n");
			}
			BinaryTreeNode<E> upper = next.getUpperSubNode(), lower = next.getLowerSubNode();
			if(upper != null) {
				if(lower != null) {
					Indents lowerIndents = new Indents(
							subNodeIndent + LEFT_ELBOW,
							subNodeIndent + IN_BETWEEN_ELBOWS);
					iterator.cacheWithLowerSubNode(lowerIndents);
				}
				Indents upperIndents = new Indents(
						subNodeIndent + RIGHT_ELBOW,
						subNodeIndent + BELOW_ELBOWS);
				iterator.cacheWithUpperSubNode(upperIndents);
			} else if(lower != null) {
				Indents lowerIndents = new Indents(
						subNodeIndent + RIGHT_ELBOW,
						subNodeIndent + BELOW_ELBOWS);
				iterator.cacheWithLowerSubNode(lowerIndents);
			}
		}
	}

	/**
	 * Returns a visual representation of this node including the key, with an open circle indicating this node is not an added node,
	 * a closed circle indicating this node is an added node.
	 */
	@Override
	public String toString() {
		return toNodeString(new StringBuilder(50), isAdded(), getKey(),  null).toString();
	}

	static <E, V> StringBuilder toNodeString(StringBuilder builder, boolean isAdded, E key, V value) {
		builder.append(isAdded ? ADDED_NODE_CIRCLE: NON_ADDED_NODE_CIRCLE).append(' ').append(key);
		if(value != null) {
			builder.append(" = ").append(value);
		}
		return builder;
	}

	/**
	 * Clones the node.  Keys remain the same, but the parent node and the lower and upper sub-nodes 
	 * are all set to null.
	 */
	@SuppressWarnings("unchecked")
	@Override
	public BinaryTreeNode<E> clone() {
		try {
			BinaryTreeNode<E> result = (BinaryTreeNode<E>) super.clone();
			result.setParent(null);
			result.setLower(null);
			result.setUpper(null);
			result.size = isAdded() ? 1 : 0;
			result.changeTracker = null;
			return result;
		} catch (CloneNotSupportedException e) {
			return null;
		}
	}

	@SuppressWarnings("unchecked")
	BinaryTreeNode<E> cloneTreeNode(ChangeTracker changeTracker) {
		try {
			BinaryTreeNode<E> result = (BinaryTreeNode<E>) super.clone();
			result.setParent(null);
			//result.setLower(null);
			//result.setUpper(null);
			result.changeTracker = changeTracker;
			return result;
		} catch (CloneNotSupportedException e) {
			return null;
		}
	}

	@SuppressWarnings("unchecked")
	BinaryTreeNode<E> cloneTree(ChangeTracker changeTracker, Bounds<E> bounds) {
		BinaryTreeNode<E> rootClone = cloneTreeNode(changeTracker);
		BinaryTreeNode<E> clonedNode = rootClone;
		SubNodeCachingIterator<E, ?> iterator = (SubNodeCachingIterator<E, ?>) clonedNode.containingFirstAllNodeIterator(true);
		boolean recalculateSize = false;
		do {
			BinaryTreeNode<E> lower = clonedNode.getLowerSubNode();
			if(bounds != null) {
				while(true) {
					if(lower == null) {
						break;
					} else if(bounds.isWithinLowerBound(lower.getKey())) {
						if(!lower.isAdded()) {
							BinaryTreeNode<E> next = lower.getLowerSubNode();
							while(bounds.isBelowLowerBound(next.getKey())) {
								next = next.getUpperSubNode();
								if(next == null) {
									lower = lower.getUpperSubNode();
									recalculateSize = true;
									break;
								}
							}
						}
						break;
					}
					recalculateSize = true;
					// outside bounds, try again
					lower = lower.getUpperSubNode();
				}
			}
			if(lower != null) {
				clonedNode.setLower(lower.cloneTreeNode(changeTracker));
			} else {
				clonedNode.setLower(null);
			}
			BinaryTreeNode<E> upper = clonedNode.getUpperSubNode();
			if(bounds != null) {
				while(true) {
					if(upper == null) {
						break;
					} else if(bounds.isWithinUpperBound(upper.getKey())) {
						if(!upper.isAdded()) {
							BinaryTreeNode<E> next = upper.getUpperSubNode();
							while(bounds.isAboveUpperBound(next.getKey())) {
								next = next.getLowerSubNode();
								if(next == null) {
									upper = upper.getLowerSubNode();
									recalculateSize = true;
									break;
								}
							}
						}
						
						break;
					}
					recalculateSize = true;
					// outside bounds, try again
					upper = upper.getLowerSubNode();
				}
			}
			if(upper != null) {
				clonedNode.setUpper(upper.cloneTreeNode(changeTracker));
			} else {
				clonedNode.setUpper(null);
			}
			iterator.next(); // returns current clonedNode
			clonedNode = iterator.next;
		} while(iterator.hasNext() /* basically this checks clonedNode != null */);
		if(!rootClone.isAdded() && !isRoot()) {
			BinaryTreeNode<E> lower = rootClone.getLowerSubNode();
			if(lower == null) {
				rootClone = rootClone.getUpperSubNode();
			} else if(rootClone.getUpperSubNode() == null) {
				rootClone = lower;
			}
		}
		if(recalculateSize && rootClone != null) {
			rootClone.size = SIZE_UNKNOWN;
			rootClone.size();
		}
		return rootClone;
	}

	BinaryTreeNode<E> cloneTreeBounds(Bounds<E> bounds) {
		return cloneTree(new ChangeTracker(), bounds);
	}

	/**
	 * Clones the sub-tree starting with this node as root. 
	 * The nodes are cloned, but their keys and values are not cloned.
	 */
	public BinaryTreeNode<E> cloneTree() {
		return cloneTreeBounds(null);
	}

	/**
	 * The hash code is the hash code of the key value
	 */
	@Override
	public int hashCode() {
		return getKey().hashCode();
    }

	/**
	 * The hash code is the sum of the hash codes of all the added elements in the sub-tree with this node as the root
	 */
	public int treeHashCode()  {
		int hashCode = 0;
		Iterator<? extends BinaryTreeNode<?>> these = nodeIterator(true);
		while(these.hasNext()) {
			BinaryTreeNode<?> node = these.next();
			hashCode += node.hashCode();
		}
	    return hashCode;
	}

	/**
	 * Returns whether the key values match those of the given node
	 */
	@Override
	public boolean equals(Object o) {
		if (o == this) {
            return true;
		}
		if(o instanceof BinaryTreeNode<?>) {
			BinaryTreeNode<?> other = (BinaryTreeNode<?>) o;
			return getKey().equals(other.getKey());
		}
		return false;
	}

	/**
	 * Returns whether the sub-tree represented by this node as the root node matches the given sub-tree
	 */
	public boolean treeEquals(BinaryTreeNode<?> other) {
		if (other == this) {
			return true;
		}
		if(other.size() != size()) {
			return false;
		}
		Iterator<? extends BinaryTreeNode<?>> these = nodeIterator(true),
				others = other.nodeIterator(true);
		while(these.hasNext()) {
			BinaryTreeNode<?> node = these.next(), otherNode = others.next();
			if(!node.equals(otherNode)) {
				return false;
			}
		}
		return true;
	}
}
