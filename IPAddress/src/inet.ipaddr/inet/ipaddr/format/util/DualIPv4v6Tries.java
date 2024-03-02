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

import inet.ipaddr.IPAddress;
import inet.ipaddr.format.util.AddressTrie.TrieNode;
import inet.ipaddr.ipv4.IPv4AddressTrie;
import inet.ipaddr.ipv6.IPv6AddressTrie;

/**
 * Combines an IPv4 with an IPv6 trie to store both IPv4 and IPv6 addresses and prefix blocks.
 *   
 * For a tree that is either IPv4 or IPv6, one or the other, you can just use #{@link AddressTrie}.
 * 
 * Another alternative to this data structure is to use a single IPv6 trie, while mapping IPv4 addresses to IPv6 with the default IPv4-mapped address mapping, or some other mapping.
 * 
 * @author scfoley
 *
 */
public class DualIPv4v6Tries extends BaseDualIPv4v6Tries<IPv4AddressTrie, IPv6AddressTrie> {
	
	private static final long serialVersionUID = 1L;
	
	private IPv6AddressTrie ipv6Trie;
	private IPv4AddressTrie ipv4Trie;
	
	public DualIPv4v6Tries() {
		this(new IPv4AddressTrie(), new IPv6AddressTrie());
	}
	
	public DualIPv4v6Tries(IPv4AddressTrie ipv4Trie, IPv6AddressTrie ipv6Trie) {
		super(ipv4Trie, ipv6Trie);
		this.ipv4Trie = ipv4Trie;
		this.ipv6Trie = ipv6Trie;
	}
	
	@Override
	public IPv4AddressTrie getIPv4Trie() {
		return ipv4Trie;
	}
	
	@Override
	public IPv6AddressTrie getIPv6Trie() {
		return ipv6Trie;
	}
	
	@Override
	public DualIPv4v6Tries clone() {
		DualIPv4v6Tries result = (DualIPv4v6Tries) super.clone();
		result.ipv4Trie = ipv4Trie.clone();
		result.ipv6Trie = ipv6Trie.clone();
		result.assignTrackers(result.ipv4Trie, result.ipv6Trie);
		return result;
	}
	
	@Override
	public Iterator<TrieNode<? extends IPAddress>> nodeIterator(boolean forward) {
		return combineNodeIterators(forward, getIPv4Trie().nodeIterator(forward), getIPv6Trie().nodeIterator(forward));
	}

	@Override
	public Iterator<TrieNode<? extends IPAddress>> containingFirstIterator(boolean forwardSubNodeOrder) {
		return combineNodeIterators(forwardSubNodeOrder, getIPv4Trie().containingFirstIterator(forwardSubNodeOrder), getIPv6Trie().containingFirstIterator(forwardSubNodeOrder));
	}

	@Override
	public Iterator<TrieNode<? extends IPAddress>> containedFirstIterator(boolean forwardSubNodeOrder) {
		return combineNodeIterators(forwardSubNodeOrder, getIPv4Trie().containedFirstIterator(forwardSubNodeOrder), getIPv6Trie().containedFirstIterator(forwardSubNodeOrder));
	}
	
	@Override
	public Iterator<TrieNode<? extends IPAddress>> blockSizeNodeIterator(boolean lowerSubNodeFirst) {
		return combineBlockSizeNodeIterators(lowerSubNodeFirst, getIPv4Trie().blockSizeNodeIterator(lowerSubNodeFirst), getIPv6Trie().blockSizeNodeIterator(lowerSubNodeFirst));
	}
	
	@Override
	public Spliterator<TrieNode<? extends IPAddress>> nodeSpliterator(boolean forward) {
		return combineNodeSpliterators(forward, getIPv4Trie().nodeSpliterator(forward), getIPv6Trie().nodeSpliterator(forward));
	}
}
