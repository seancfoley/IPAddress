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

import java.math.BigInteger;
import java.util.Iterator;
import java.util.stream.Stream;

import inet.ipaddr.AddressValueException;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressSeqRange;
import inet.ipaddr.IPAddressSeqRangeList;
import inet.ipaddr.format.util.BigSpliterator;

public class IPv4AddressSeqRangeList extends IPAddressSeqRangeList implements Iterable<IPv4Address> {

	private static final long serialVersionUID = 1L;

	public IPv4AddressSeqRangeList() {}

	public IPv4AddressSeqRangeList(int initialCapacity) {
		super(initialCapacity);
	}

	/**
	 * Returns the list of sequential ranges in order.
	 * 
	 * @return
	 */
	@Override
	public IPv4AddressSeqRange[] getSeqRanges() {
		return ranges.toArray(new IPv4AddressSeqRange[ranges.size()]);
	}

	/**
	 * Returns a new IPAddressSeqRangeList comprising all the addresses not contained in this list.
	 * 
	 * In the case of an empty list, the default network must be used to create the list representing the entire address space.
	 * To override this behaviour, if you wish to create your own subclass instance, 
	 * override this method to handle that one case when {@link #isEmpty()} returns true.
	 * 
	 * @return
	 */
	@Override
	public IPv4AddressSeqRangeList complementIntoList() {
		IPv4AddressNetwork network = isEmpty() ? IPv4Address.defaultIpv4Network() : getLowerSeqRange().getLower().getNetwork();
		IPv4Address zero = network.getNetworkMask(0, false);
		IPv4Address max = network.getNetworkMask(zero.getBitCount(), false);
		IPv4AddressSeqRangeList result = new IPv4AddressSeqRangeList();
		complement(result, zero, max);
		return result;
	}

	@Override
	public IPv4AddressSeqRangeList removeIntoList(IPAddressSeqRangeList list) {
		IPv4AddressSeqRangeList result = new IPv4AddressSeqRangeList();
		super.remove(list, result);
		return result;
	}

	@Override
	public IPv4AddressSeqRangeList intersectIntoList(IPAddressSeqRangeList list) {
		IPv4AddressSeqRangeList result = new IPv4AddressSeqRangeList();
		super.intersect(list, result);
		return result;
	}

	@Override
	public IPv4AddressSeqRangeList joinIntoList(IPAddressSeqRangeList list) {
		if(list.getSeqRangeCount() == 0) {
			return clone();
		} else if(!list.getSeqRange(0).isIPv4()) {
			throw new IllegalArgumentException(getMessage("ipaddress.error.mismatched.bit.size"));
		}
		IPv4AddressSeqRangeList result = new IPv4AddressSeqRangeList();
		super.join(list, result);
		return result;
	}

	@Override
	public boolean add(IPAddress address) {
		if(!address.isIPv4()) {
			throw new IllegalArgumentException(getMessage("ipaddress.error.mismatched.bit.size"));
		} else if(ranges.size() == 0) {
			addAddressToEmptyList(address);
			return true;
		}
		return doAdd(address);
	}
	
	void addInternalToNewList(IPv4Address address) {
		addAddressToEmptyList(address);
	}

	@Override
	public boolean add(IPAddressSeqRange seqRange) {
		if(!seqRange.isIPv4()) {
			throw new IllegalArgumentException(getMessage("ipaddress.error.mismatched.bit.size"));
		} else if(ranges.size() == 0) {
			addRangeToEmptyList(seqRange);
			return true;
		}
		return doAdd(seqRange);
	}
	
	@Override
	public IPv4Address getLower() {
		return (IPv4Address) super.getLower();
	}
	
	@Override
	public IPv4Address getUpper() {
		return (IPv4Address) super.getUpper();
	}

	@Override
	public IPv4AddressSeqRange getLowerSeqRange() {
		return (IPv4AddressSeqRange) super.getLowerSeqRange();
	}

	@Override
	public IPv4AddressSeqRange getUpperSeqRange() {
		return (IPv4AddressSeqRange) super.getUpperSeqRange();
	}
	
	@Override
	public IPv4AddressSeqRangeList clone() {
		return (IPv4AddressSeqRangeList) super.clone();
	}

	@Override
	public IPv4AddressSeqRange getSeqRange(int rangeIndex) {
		return (IPv4AddressSeqRange) ranges.get(rangeIndex);
	}

	@Override
	public IPv4Address remove(long addressIndex) {
		return (IPv4Address) super.remove(addressIndex);
	}

	@Override
	public IPv4Address increment(long addressIndex) {
		return (IPv4Address) super.increment(addressIndex);
	}

	@Override
	public IPv4Address get(long addressIndex) {
		return (IPv4Address) super.get(addressIndex);
	}

	@Override
	public IPv4AddressSeqRange getContainingSeqRange(long addressIndex) {
		return (IPv4AddressSeqRange) super.getContainingSeqRange(addressIndex);
	}

	@Override
	public IPv4Address remove(BigInteger addressIndex) {
		if(addressIndex.compareTo(IPv4AddressSection.LONG_MAX) >= 0 || addressIndex.compareTo(IPv4AddressSection.LONG_MIN) <= 0) {
			throw new IndexOutOfBoundsException();
		}
		return remove(addressIndex.longValue());
	}

	@Override
	public IPv4Address increment(BigInteger addressIndex) {
		if(addressIndex.compareTo(IPv4AddressSection.LONG_MAX) >= 0 || addressIndex.compareTo(IPv4AddressSection.LONG_MIN) <= 0) {
			throw new AddressValueException(addressIndex);
		}
		return increment(addressIndex.longValue());
	}

	@Override
	public IPv4Address get(BigInteger addressIndex) {
		if(addressIndex.compareTo(IPv4AddressSection.LONG_MAX) >= 0 || addressIndex.compareTo(IPv4AddressSection.LONG_MIN) <= 0) {
			throw new IndexOutOfBoundsException();
		}
		return get(addressIndex.longValue());
	}
	
	@Override
	public IPv4AddressSeqRange getContainingSeqRange(BigInteger addressIndex) {
		return (IPv4AddressSeqRange) super.getContainingSeqRange(addressIndex);
	}

	@Override
	public IPv4AddressSeqRange coverWithSequentialRange() {
		return (IPv4AddressSeqRange) super.coverWithSequentialRange();
	}

	@Override
	public IPv4Address coverWithPrefixBlock() {
		return getLower().coverWithPrefixBlock(getUpper());
	}

	@Override
	public IPv4Address[] spanWithPrefixBlocks() {
		if(ranges.size() == 0) {
			return IPv4AddressNetwork.EMPTY_ADDRESS;
		}
		return getSpanningBlocks(IPv4AddressSeqRange::spanWithPrefixBlocks, IPv4Address[]::new);
	}

	@Override
	public IPv4Address[] spanWithSequentialBlocks() {
		if(ranges.size() == 0) {
			return IPv4AddressNetwork.EMPTY_ADDRESS;
		}
		return getSpanningBlocks(IPv4AddressSeqRange::spanWithSequentialBlocks, IPv4Address[]::new);
	}
	
	@Override
	public Iterable<IPv4Address> getIterable() {
		return this;
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterable<IPv4AddressSeqRange> getSeqRangeIterable() {
		return (Iterable<IPv4AddressSeqRange>) super.getSeqRangeIterable();
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv4AddressSeqRange> seqRangeIterator() {
		return (Iterator<IPv4AddressSeqRange>) super.seqRangeIterator();
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv4Address> iterator() {
		return (Iterator<IPv4Address>) super.iterator();
	}

	@SuppressWarnings("unchecked")
	@Override
	public BigSpliterator<IPv4Address> spliterator() {
		return (BigSpliterator<IPv4Address>) super.spliterator();
	}

	@SuppressWarnings("unchecked")
	@Override
	public Stream<IPv4Address> stream() {
		return (Stream<IPv4Address>) super.stream();
	}
}
