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

package inet.ipaddr.ipv6;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.stream.Stream;

import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressSeqRange;
import inet.ipaddr.IPAddressSeqRangeList;
import inet.ipaddr.format.util.BigSpliterator;

public class IPv6AddressSeqRangeList extends IPAddressSeqRangeList implements Iterable<IPv6Address> {

	private static final long serialVersionUID = 1L;

	public IPv6AddressSeqRangeList() {}

	public IPv6AddressSeqRangeList(int initialCapacity) {
		super(initialCapacity);
	}

	/**
	 * Returns the list of sequential ranges in order.
	 * 
	 * @return
	 */
	@Override
	public IPv6AddressSeqRange[] getSeqRanges() {
		return ranges.toArray(new IPv6AddressSeqRange[ranges.size()]);
	}

	/**
	 * Returns a new IPAddressSeqRangeList with all the addresses not contained in this list.
	 * 
	 * @return
	 */
	@Override
	public IPv6AddressSeqRangeList complementIntoList() {
		IPv6AddressNetwork network = isEmpty() ? IPv6Address.defaultIpv6Network() : getLowerSeqRange().getLower().getNetwork();
		IPv6Address zero = network.getNetworkMask(0, false);
		IPv6Address max = network.getNetworkMask(zero.getBitCount(), false);
		IPv6AddressSeqRangeList result = new IPv6AddressSeqRangeList();
		complement(result, zero, max);
		return result;
	}

	@Override
	public IPv6AddressSeqRangeList removeIntoList(IPAddressSeqRangeList list) {
		IPv6AddressSeqRangeList result = new IPv6AddressSeqRangeList();
		super.remove(list, result);
		return result;
	}

	@Override
	public IPv6AddressSeqRangeList intersectIntoList(IPAddressSeqRangeList list) {
		IPv6AddressSeqRangeList result = new IPv6AddressSeqRangeList();
		super.intersect(list, result);
		return result;
	}

	@Override
	public IPv6AddressSeqRangeList joinIntoList(IPAddressSeqRangeList list) {
		if(list.getSeqRangeCount() == 0) {
			return clone();
		} else if(!list.getSeqRange(0).isIPv6()) {
			throw new IllegalArgumentException(getMessage("ipaddress.error.mismatched.bit.size"));
		}
		IPv6AddressSeqRangeList result = new IPv6AddressSeqRangeList();
		super.join(list, result);
		return result;
	}

	@Override
	public boolean add(IPAddress address) {
		if(!address.isIPv6()) {
			throw new IllegalArgumentException(getMessage("ipaddress.error.mismatched.bit.size"));
		} else if(ranges.size() == 0) {
			addAddressToEmptyList(address);
			return true;
		}
		return doAdd(address);
	}
	
	void addInternalToNewList(IPv6Address address) {
		addAddressToEmptyList(address);
	}

	@Override
	public boolean add(IPAddressSeqRange seqRange) {
		if(!seqRange.isIPv6()) {
			throw new IllegalArgumentException(getMessage("ipaddress.error.mismatched.bit.size"));
		} else if(ranges.size() == 0) {
			addRangeToEmptyList(seqRange);
			return true;
		}
		return doAdd(seqRange);
	}
	
	@Override
	public IPv6Address getLower() {
		return (IPv6Address) super.getLower();
	}
	
	@Override
	public IPv6Address getUpper() {
		return (IPv6Address) super.getUpper();
	}

	@Override
	public IPv6AddressSeqRange getLowerSeqRange() {
		return (IPv6AddressSeqRange) super.getLowerSeqRange();
	}

	@Override
	public IPv6AddressSeqRange getUpperSeqRange() {
		return (IPv6AddressSeqRange) super.getUpperSeqRange();
	}

	@Override
	public IPv6AddressSeqRangeList clone() {
		return (IPv6AddressSeqRangeList) super.clone();
	}
	
	@Override
	public IPv6AddressSeqRange getSeqRange(int rangeIndex) {
		return (IPv6AddressSeqRange) ranges.get(rangeIndex);
	}

	@Override
	public IPv6Address remove(long addressIndex) {
		return (IPv6Address) super.remove(addressIndex);
	}

	@Override
	public IPv6Address increment(long addressIndex) {
		return (IPv6Address) super.increment(addressIndex);
	}

	@Override
	public IPv6Address get(long addressIndex) {
		return (IPv6Address) super.get(addressIndex);
	}

	@Override
	public IPv6AddressSeqRange getContainingSeqRange(long addressIndex) {
		return (IPv6AddressSeqRange) super.getContainingSeqRange(addressIndex);
	}

	@Override
	public IPv6Address remove(BigInteger addressIndex) {
		return (IPv6Address) super.remove(addressIndex);
	}
	
	@Override
	public IPv6Address increment(BigInteger addressIndex) {
		return (IPv6Address) super.increment(addressIndex);
	}

	@Override
	public IPv6Address get(BigInteger addressIndex) {
		return (IPv6Address) super.get(addressIndex);
	}
	
	@Override
	public IPv6AddressSeqRange getContainingSeqRange(BigInteger index) {
		return (IPv6AddressSeqRange) super.getContainingSeqRange(index);
	}
	
	@Override
	public IPv6AddressSeqRange coverWithSequentialRange() {
		return (IPv6AddressSeqRange) super.coverWithSequentialRange();
	}
	
	@Override
	public IPv6Address coverWithPrefixBlock() {
		return getLower().coverWithPrefixBlock(getUpper());
	}

	@Override
	public IPv6Address[] spanWithPrefixBlocks() {
		if(ranges.size() == 0) {
			return IPv6AddressNetwork.EMPTY_ADDRESS;
		}
		return getSpanningBlocks(IPv6AddressSeqRange::spanWithPrefixBlocks, IPv6Address[]::new);
	}

	@Override
	public IPv6Address[] spanWithSequentialBlocks() {
		if(ranges.size() == 0) {
			return IPv6AddressNetwork.EMPTY_ADDRESS;
		}
		return getSpanningBlocks(IPv6AddressSeqRange::spanWithSequentialBlocks, IPv6Address[]::new);
	}
	
	@Override
	public Iterable<IPv6Address> getIterable() {
		return this;
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterable<IPv6AddressSeqRange> getSeqRangeIterable() {
		return (Iterable<IPv6AddressSeqRange>) super.getSeqRangeIterable();
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv6AddressSeqRange> seqRangeIterator() {
		return (Iterator<IPv6AddressSeqRange>) super.seqRangeIterator();
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv6Address> iterator() {
		return (Iterator<IPv6Address>) super.iterator();
	}

	@SuppressWarnings("unchecked")
	@Override
	public BigSpliterator<IPv6Address> spliterator() {
		return (BigSpliterator<IPv6Address>) super.spliterator();
	}

	@SuppressWarnings("unchecked")
	@Override
	public Stream<IPv6Address> stream() {
		return (Stream<IPv6Address>) super.stream();
	}

}
