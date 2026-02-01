/*
 * Copyright 2020-2024 Sean C Foley
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

import java.math.BigInteger;
import java.util.Iterator;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import inet.ipaddr.Address;
import inet.ipaddr.AddressSegmentSeries;
import inet.ipaddr.HostIdentifierException;
import inet.ipaddr.IPAddressSegmentSeries;
import inet.ipaddr.format.util.AddressTrieOps.AddressTrieAddOps;
import inet.ipaddr.format.util.BinaryTreeNode.KeyIterator;

abstract class AbstractTree<E extends Address> implements AddressTrieAddOps<E> {

	private static final long serialVersionUID = 1L;

	static ResourceBundle bundle;
	
	static {
		//reuse the same properties file
		String propertyFileName = "IPAddressResources";
		String name = HostIdentifierException.class.getPackage().getName() + '.' + propertyFileName;
		try {
			bundle = ResourceBundle.getBundle(name);
		} catch (MissingResourceException e) {
			System.err.println("bundle " + name + " is missing");
		}
	}
	
	static String getMessage(String key) {
		if(bundle != null) {
			try {
				return bundle.getString(key);
				
			} catch (MissingResourceException e1) {}
		}
		return key;
	}
	
	BinaryTreeNode<E> root;

	protected AbstractTree(BinaryTreeNode<E> root) {
		this.root = root;
	}

	/**
	 * Returns the root of this trie
	 * @return
	 */
	public BinaryTreeNode<E> getRoot() {
		return root;
	}

	/**
	 * Returns the number of elements in the tree.  
	 * Only nodes for which {@link BinaryTreeNode#isAdded()} returns true are counted.
	 * When zero is returned, {@link #isEmpty()} returns true.
	 * 
	 * @return
	 */
	public int size() {
		return getRoot().size();
	}

	/**
	 * Returns the number of nodes in the tree, which is always more than the number of elements.
	 * 
	 * @return
	 */
	public int nodeSize() {
		return getRoot().nodeSize();
	}
	
	/**
	 * Returns the total number of addresses covered by prefix block subnets added to the trie, including individual addresses added as well.
	 * @return
	 */
	public BigInteger getMatchingAddressCount() {
		return getRoot().getMatchingAddressCount();
	}

	/**
	 * Ensures the address is either an individual address or a prefix block subnet.
	 * 
	 * @param <E>
	 * @param addr
	 * @param thro
	 * @return
	 */
	@SuppressWarnings("unchecked")
	static <E extends Address> E checkBlockOrAddress(E addr, boolean thro) {
		if(!addr.isMultiple()) {
			if(!addr.isPrefixed()) {
				return addr;
			}
			return (E) addr.withoutPrefixLength();
		} else if(addr.isSinglePrefixBlock()) {
			return addr;
		} else {
			AddressSegmentSeries series;
			if(addr instanceof IPAddressSegmentSeries) {
				series = ((IPAddressSegmentSeries) addr).assignPrefixForSingleBlock();
			} else {
				Integer newPrefix = addr.getPrefixLengthForSingleBlock();
				series = newPrefix == null ? null : addr.setPrefixLength(newPrefix, false);
			}
			if(series != null) {
				return (E) series;
			}
		}
		if(thro) {
			throw new IllegalArgumentException(getMessage("ipaddress.error.address.not.block"));
		}
		return null;
	}

	/**
	 * Removes all added nodes from the tree, after which {@link #isEmpty()} will return true
	 */
	public void clear() {
		getRoot().clear();
	}

	@Override
	public Iterator<E> iterator() {
		return new KeyIterator<E>(nodeIterator(true));
	}

	@Override
	public Iterator<E> descendingIterator() {
		return new KeyIterator<E>(nodeIterator(false));
	}

	@Override
	public int hashCode() {
		int hashCode = 0;
		Iterator<? extends BinaryTreeNode<E>> these = nodeIterator(true);
		while(these.hasNext()) {
			BinaryTreeNode<?> node = these.next();
			hashCode = 31 * hashCode + node.hashCode();
		}
	    return hashCode;
	}

	@Override
	public boolean equals(Object o) {
		if (o == this) {
			return true;
		}
		if(o instanceof AbstractTree) {
			AbstractTree<?> other = (AbstractTree<?>) o;
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
		return false;
	}

	protected boolean isInitialRoot() {
		return root.isInitialRoot();
	}
	
	/**
	 * Returns true if there are not any added nodes within this tree
	 */
	public boolean isEmpty() {
		return isInitialRoot(); // possibly faster for bounded trees than using size() == 0
		//return size() == 0; 
	}

	/**
	 * Returns a visual representation of the tree with one node per line.
	 */
	@Override
	public String toString() {
		return toString(true);
	}

	/**
	 * Returns a visual representation of the tree with one node per line, with or without the non-added keys.
	 */
	public String toString(boolean withNonAddedKeys) {
		return toString(withNonAddedKeys, true, false);
	}

	/**
	 * Returns a customized visual representation of the tree with one node per line, with or without the non-added keys.
	 */
	public String toString(boolean withNonAddedKeys, boolean withSizes, boolean withMatchingAddressCounts) {
		return getRoot().toTreeString(withNonAddedKeys, withSizes, withMatchingAddressCounts);
	}
	
	/**
	 * Copies the trie, but not the keys or values.
	 */
	@SuppressWarnings("unchecked")
	@Override
	public AbstractTree<E> clone() {
		try {
			return (AbstractTree<E>) super.clone();
		} catch (CloneNotSupportedException e) {
			return null;
		}
	}
}
