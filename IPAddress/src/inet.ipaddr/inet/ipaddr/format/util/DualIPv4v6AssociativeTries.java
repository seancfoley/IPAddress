/*
 * Copyright 2024 Sean C Foley
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
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Supplier;

import inet.ipaddr.IPAddress;
import inet.ipaddr.format.util.AddressTrie.TrieNode;
import inet.ipaddr.format.util.AssociativeAddressTrie.AssociativeTrieNode;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv4.IPv4AddressAssociativeTrie;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.ipv6.IPv6AddressAssociativeTrie;


/**
 * Combines an IPv4 with an IPv6 associative trie to map both IPv4 and IPv6 addresses and prefix blocks.
 *   
 * For a tree that is either IPv4 or IPv6, one or the other, you can just use #{@link AssociativeAddressTrie}.
 * 
 * Another alternative to this data structure is to use a single IPv6 trie, while mapping IPv4 addresses to IPv6 with the default IPv4-mapped address mapping, or some other mapping.
 * 
 * @author scfoley
 *
 */
public class DualIPv4v6AssociativeTries<V> extends BaseDualIPv4v6Tries<IPv4AddressAssociativeTrie<V>, IPv6AddressAssociativeTrie<V>> {
	
	private static final long serialVersionUID = 1L;

	private IPv6AddressAssociativeTrie<V> ipv6Trie;
	private IPv4AddressAssociativeTrie<V> ipv4Trie;
	
	public DualIPv4v6AssociativeTries() {
		this(new IPv4AddressAssociativeTrie<V>(), new IPv6AddressAssociativeTrie<V>());
	}
	
	public DualIPv4v6AssociativeTries(IPv4AddressAssociativeTrie<V> ipv4Trie, IPv6AddressAssociativeTrie<V> ipv6Trie) {
		super(ipv4Trie, ipv6Trie);
		this.ipv4Trie = ipv4Trie;
		this.ipv6Trie = ipv6Trie;
	}
	
	@Override
	public DualIPv4v6AssociativeTries<V> clone() {
		DualIPv4v6AssociativeTries<V> result = (DualIPv4v6AssociativeTries<V>) super.clone();
		result.ipv4Trie = ipv4Trie.clone();
		result.ipv6Trie = ipv6Trie.clone();
		result.assignTrackers(result.ipv4Trie, result.ipv6Trie);
		return result;
	}
	
	@Override
	public IPv4AddressAssociativeTrie<V> getIPv4Trie() { 
		return ipv4Trie;
	}
	
	@Override
	public IPv6AddressAssociativeTrie<V> getIPv6Trie() {
		return ipv6Trie;
	}
	
	@Override
	public AssociativeTrieNode<? extends IPAddress, V> elementsContaining(IPAddress addr) {
		return addressFuncOp(addr, getIPv4Trie()::elementsContaining, getIPv6Trie()::elementsContaining);
	}
	
	@Override
	public AssociativeTrieNode<? extends IPAddress, V> elementsContainedBy(IPAddress addr) {
		return addressFuncOp(addr, getIPv4Trie()::elementsContainedBy, getIPv6Trie()::elementsContainedBy);
	}
	
	@Override
	public AssociativeTrieNode<? extends IPAddress, V> removeElementsContainedBy(IPAddress addr) {
		return addressFuncOp(addr, getIPv4Trie()::removeElementsContainedBy, getIPv6Trie()::removeElementsContainedBy);
	}

	@Override
	public AssociativeTrieNode<? extends IPAddress, V> getAddedNode(IPAddress addr) {
		return addressFuncOp(addr, getIPv4Trie()::getAddedNode, getIPv6Trie()::getAddedNode);
	}

	@Override
	public AssociativeTrieNode<? extends IPAddress, V> longestPrefixMatchNode(IPAddress addr) {
		return addressFuncOp(addr, getIPv4Trie()::longestPrefixMatchNode, getIPv6Trie()::longestPrefixMatchNode);
	}
	
	@Override
	public AssociativeTrieNode<? extends IPAddress, V> addNode(IPAddress addr) {
		return addressFuncOp(addr, getIPv4Trie()::addNode, getIPv6Trie()::addNode);
	}
		
	@Override
	public AssociativeTrieNode<? extends IPAddress, V> addTrie(TrieNode<? extends IPAddress> trie) {
		return unaryOp(trie, getIPv4Trie()::addTrie, getIPv6Trie()::addTrie);
	}

	@Override
	public AssociativeTrieNode<? extends IPAddress, V> removeElementsIntersectedBy(IPAddress addr) { 
		return addressFuncOp(addr, getIPv4Trie()::removeElementsIntersectedBy, getIPv6Trie()::removeElementsIntersectedBy);
	}

	@Override
	public AssociativeTrieNode<? extends IPAddress, V> addIfNoElementsContaining(IPAddress addr) { 
		return addressFuncOp(addr, getIPv4Trie()::addIfNoElementsContaining, getIPv6Trie()::addIfNoElementsContaining);
	}

	@Override
	public AssociativeTrieNode<? extends IPAddress, V> containingFloorAddedNode(IPAddress addr) {
		return addressFuncOp(addr, getIPv4Trie()::containingFloorAddedNode, getIPv6Trie()::containingHigherAddedNode);
	}
	
	@Override
	public AssociativeTrieNode<? extends IPAddress, V> containingLowerAddedNode(IPAddress addr) {
		return addressFuncOp(addr, getIPv4Trie()::containingLowerAddedNode, getIPv6Trie()::containingHigherAddedNode);
	}

	@Override
	public AssociativeTrieNode<? extends IPAddress, V> containingCeilingAddedNode(IPAddress addr) {
		return addressFuncOp(addr, getIPv4Trie()::containingCeilingAddedNode, getIPv6Trie()::containingHigherAddedNode);
	}

	@Override
	public AssociativeTrieNode<? extends IPAddress, V> containingHigherAddedNode(IPAddress addr) {
		return addressFuncOp(addr, getIPv4Trie()::containingHigherAddedNode, getIPv6Trie()::containingHigherAddedNode);
	}

	@Override
	public AssociativeTrieNode<? extends IPAddress, V> floorAddedNode(IPAddress addr) {
		return addressFuncOp(addr, getIPv4Trie()::floorAddedNode, getIPv6Trie()::floorAddedNode);
	}
	
	@Override
	public AssociativeTrieNode<? extends IPAddress, V> lowerAddedNode(IPAddress addr) {
		return addressFuncOp(addr, getIPv4Trie()::lowerAddedNode, getIPv6Trie()::lowerAddedNode);
	}
	
	@Override
	public AssociativeTrieNode<? extends IPAddress, V> ceilingAddedNode(IPAddress addr) {
		return addressFuncOp(addr, getIPv4Trie()::ceilingAddedNode, getIPv6Trie()::ceilingAddedNode);
	}
	
	@Override
	public AssociativeTrieNode<? extends IPAddress, V> higherAddedNode(IPAddress addr) {
		return addressFuncOp(addr, getIPv4Trie()::higherAddedNode, getIPv6Trie()::higherAddedNode);
	}
	
	@Override
	public Iterator<AssociativeTrieNode<? extends IPAddress, V>> nodeIterator(boolean forward) {
		return combineNodeIterators(forward, getIPv4Trie().nodeIterator(forward), getIPv6Trie().nodeIterator(forward));
	}

	@Override
	public Iterator<AssociativeTrieNode<? extends IPAddress, V>> containingFirstIterator(boolean forwardSubNodeOrder) {
		return combineNodeIterators(forwardSubNodeOrder, getIPv4Trie().containingFirstIterator(forwardSubNodeOrder), getIPv6Trie().containingFirstIterator(forwardSubNodeOrder));
	}

	@Override
	public Iterator<AssociativeTrieNode<? extends IPAddress, V>> containedFirstIterator(boolean forwardSubNodeOrder) {
		return combineNodeIterators(forwardSubNodeOrder, getIPv4Trie().containedFirstIterator(forwardSubNodeOrder), getIPv6Trie().containedFirstIterator(forwardSubNodeOrder));
	}

	@Override
	public Iterator<AssociativeTrieNode<? extends IPAddress, V>> blockSizeNodeIterator(boolean lowerSubNodeFirst) {
		return combineBlockSizeNodeIterators(lowerSubNodeFirst, getIPv4Trie().blockSizeNodeIterator(lowerSubNodeFirst), getIPv6Trie().blockSizeNodeIterator(lowerSubNodeFirst));
	}

	@Override
	public Spliterator<AssociativeTrieNode<? extends IPAddress, V>> nodeSpliterator(boolean forward) {
		return combineNodeSpliterators(forward, getIPv4Trie().nodeSpliterator(forward), getIPv6Trie().nodeSpliterator(forward));
	}

	public AssociativeTrieNode<? extends IPAddress, V> addTrie(AssociativeTrieNode<? extends IPAddress, V> trie) {
		return DualIPv4v6Tries.unaryOp(trie, getIPv4Trie()::addTrie, getIPv6Trie()::addTrie);
	}

	public V get(IPAddress addr) {
		return DualIPv4v6Tries.addressFuncOp(addr, getIPv4Trie()::get, getIPv6Trie()::get);
	}

	public V put(IPAddress addr, V value) {
		return DualIPv4v6Tries.addressValValBiFuncOp(addr, value, getIPv4Trie()::put, getIPv6Trie()::put);
	}

	public boolean putNew(IPAddress addr, V value) {
		return DualIPv4v6Tries.addressValBiFuncOp(addr, value, getIPv4Trie()::putNew, getIPv6Trie()::putNew);
	}

	public AssociativeTrieNode<? extends IPAddress, V> putNode(IPAddress addr, V value) {
		return DualIPv4v6Tries.addressValBiFuncOp(addr, value, getIPv4Trie()::putNode, getIPv6Trie()::putNode);
	}

	public AssociativeTrieNode<? extends IPAddress, V> putTrie(AssociativeTrieNode<? extends IPAddress, V> trie) {
		return DualIPv4v6Tries.unaryOp(trie, getIPv4Trie()::putTrie, getIPv6Trie()::putTrie);
	}

	public AssociativeTrieNode<? extends IPAddress, V> remap(IPAddress addr, Function<? super V, ? extends V> remapper) {
		return addressFuncOp(addr, remapper, getIPv4Trie()::remap, getIPv6Trie()::remap);
	}

	public AssociativeTrieNode<? extends IPAddress, V> remapIfAbsent(IPAddress addr, Supplier<? extends V> remapper, boolean insertNull) {
		return addressFuncBoolOp(addr, remapper, insertNull, getIPv4Trie()::remapIfAbsent, getIPv6Trie()::remapIfAbsent);
	}

	static <T, V, F> T addressFuncOp(
			IPAddress addr, 
			F remapper, 
			BiFunction<IPv4Address, F, T> ipv4Op, 
			BiFunction<IPv6Address, F, T> ipv6Op) {
		if(addr.isIPv4()) {
			return ipv4Op.apply(addr.toIPv4(), remapper);
		} else if(addr.isIPv6()) {
			return ipv6Op.apply(addr.toIPv6(), remapper);
		} 
		return null;
	}
	
	static <T, V, F> T addressFuncBoolOp(
			IPAddress addr, 
			F remapper, 
			boolean insertNull,
			TriBoolFunction<IPv4Address, F, T> ipv4Op, 
			TriBoolFunction<IPv6Address, F, T> ipv6Op) {
		if(addr.isIPv4()) {
			return ipv4Op.apply(addr.toIPv4(), remapper, insertNull);
		} else if(addr.isIPv6()) {
			return ipv6Op.apply(addr.toIPv6(), remapper, insertNull);
		} 
		return null;
	}
	
	@FunctionalInterface
	public interface TriBoolFunction<T, U, R> {

	    /**
	     * Applies this function to the given arguments.
	     *
	     * @param t the first function argument
	     * @param u the second function argument
	     * @param b the third function argument
	     * @return the function result
	     */
	    R apply(T t, U u, boolean b);
	}
}
