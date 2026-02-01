/*
 * Copyright 2026 Sean C Foley
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
package inet.ipaddr.ipv4;

import inet.ipaddr.IPAddressContainmentTrieBase;

/**
 * IPv4AddressContainmentTrie is an IPAddressCollection of IPv4 addresses backed by an IPv4 address trie.
 * <p>
 * Sequential ranges and subnets are converted to prefix blocks in order to be inserted into the trie.
 * <p>
 * The elements of this collection are individual IPv4 addresses, unlike the IPv4AddressTrie, 
 * in which the elements are individual addresses or CIDR prefix blocks, 
 * and an address can co-exist in the trie with CIDR prefix blocks that contain the address, as separate elements.
 * This trie will change shape as addresses are added and removed to contain the minimal number of nodes to represent the addresses in the collection.
 */
public class IPv4AddressContainmentTrie extends IPAddressContainmentTrieBase<IPv4Address, IPv4AddressSeqRange> {
	
	private static final long serialVersionUID = 1L;

	@Override
	public IPv4AddressContainmentTrie clone() {
		return (IPv4AddressContainmentTrie) super.clone();
	}
}
