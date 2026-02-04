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
package inet.ipaddr;

/**
 * IPAddressContainmentTrie is an IPAddressCollection backed by an IP address trie.
 * <p>
 * Sequential ranges and subnets are converted to prefix blocks in order to be inserted into the trie.
 * <p>
 * It is one of the efficient options provided by this library implementing {@link IPAddressCollection} to maintain sets of individual IP addresses, 
 * the other being {@link IPAddressSeqRangeList}.
 * <p>
 * The elements of this collection are individual IP addresses, unlike the IPAddressTrie, 
 * in which the elements are individual addresses or CIDR prefix blocks, 
 * and an address can co-exist in the trie with CIDR prefix blocks that contain the address, as separate and distinct elements in the trie.
 * This trie will change shape as addresses are added and removed to contain the minimal number of nodes to represent the addresses in the collection.
 * <p>
 * An IPAddressContainmentTrie may contain either IPv6 addresses, or IPv4 addresses, but not both at the same time.
 * An attempt to add an address when the collection already contains an address of a different version will throw IllegalArgumentException.
 * However, once such a collection becomes empty again, it can accept either an IPv6 address or IPv4 address once more.
 */
public class IPAddressContainmentTrie extends IPAddressContainmentTrieBase<IPAddress, IPAddressSeqRange> {
	
	private static final long serialVersionUID = 1L;

	@Override
	public IPAddressContainmentTrie clone() {
		return (IPAddressContainmentTrie) super.clone();
	}
}
