/*
 * Copyright 2016-2018 Sean C Foley
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

package inet.ipaddr.test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;

import inet.ipaddr.Address;
import inet.ipaddr.AddressComparator;
import inet.ipaddr.AddressComparator.ValueComparator;
import inet.ipaddr.AddressStringParameters.RangeParameters;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.IPAddressStringParameters;
import inet.ipaddr.MACAddressString;
import inet.ipaddr.MACAddressStringParameters;
import inet.ipaddr.format.AddressItem;
import inet.ipaddr.mac.MACAddress;


public class AddressOrderTest extends TestBase {
	
	private static final IPAddressStringParameters WILDCARD_AND_RANGE_ADDRESS_OPTIONS = ADDRESS_OPTIONS.toBuilder().allowAll(true).setRangeOptions(RangeParameters.WILDCARD_AND_RANGE).toParams();
	private static final IPAddressStringParameters WILDCARD_AND_RANGE_NO_ZONE_ADDRESS_OPTIONS = WILDCARD_AND_RANGE_ADDRESS_OPTIONS.toBuilder().getIPv6AddressParametersBuilder().allowZone(false).getParentBuilder().toParams();
	private static final IPAddressStringParameters ORDERING_OPTS = WILDCARD_AND_RANGE_NO_ZONE_ADDRESS_OPTIONS.toBuilder().allowEmpty(true).setEmptyAsLoopback(false).toParams();

	private static final MACAddressStringParameters MAC_ORDERING_OPTS = MAC_ADDRESS_OPTIONS.toBuilder().allowAll(true).setRangeOptions(RangeParameters.WILDCARD_AND_RANGE).allowEmpty(true).toParams();

	AddressOrderTest(AddressCreator creator) {
		super(creator);
	}
	
	static abstract class Ordering<T extends Ordering<T, NestedType>, NestedType extends Comparable<NestedType>> implements Comparable<T> {
		final NestedType nestedType;
		final int order;
		
		Ordering(NestedType nestedType, int order) {
			this.nestedType = nestedType;
			this.order = order;
		}
		
		@Override
		public int hashCode() {
			return nestedType.hashCode();
		}
		
		@Override
		public int compareTo(T o) {
			return nestedType.compareTo(o.nestedType);
		}
		
		@Override
		public boolean equals(Object o) {
			if(o instanceof Ordering<?, ?>) {
				Ordering<?, ?> other = (Ordering<?, ?>) o;
				return nestedType.equals(other.nestedType);
			}
			return false;
		}
		
		@Override
		public String toString() {
			return "(" + order + ") " + nestedType;
		}
		
		public String getDescription() {
			return toString();
		}
	}
	
	class IPAddressStringOrdering extends Ordering<IPAddressStringOrdering, IPAddressString> {
		
		IPAddressStringOrdering(String address, int order) {
			super(createAddress(address, ORDERING_OPTS), order);
		}
		
		@Override
		public String getDescription() {
			return nestedType.getAddress() == null ? "" : "\t\t\t (" + nestedType.getAddress().toNormalizedWildcardString() + ")";
		}
	}
	
	class MACAddressStringOrdering extends Ordering<MACAddressStringOrdering, MACAddressString> {
		
		MACAddressStringOrdering(String address, int order) {
			super(createMACAddress(address, MAC_ORDERING_OPTS), order);
		}
		
		@Override
		public String getDescription() {
			return nestedType.getAddress() == null ? "" : "\t\t\t (" + nestedType.getAddress().toNormalizedString() + ")";
		}
	}
	
	class AddressOrdering extends Ordering<AddressOrdering, AddressItem> {
		
		AddressOrdering(Address address, int order) {
			super(address, order);
		}
		
		@Override
		public String getDescription() {
			return "\t\t\t (" + nestedType.toString() + ")";
		}
	}
	
	void testOrder() {
		
		class AddressOrderingComparator implements Comparator<AddressOrdering> {
			private final AddressComparator comp;
			
			AddressOrderingComparator(AddressComparator comp) {
				this.comp = comp;
			}
			
			@Override
			public int compare(AddressOrdering o1, AddressOrdering o2) {
				return comp.compare(o1.nestedType, o2.nestedType);
			}
		}
		
		class IPAddressOrderingComparator implements Comparator<IPAddressStringOrdering> {
			private final AddressComparator comp;
			
			IPAddressOrderingComparator(AddressComparator comp) {
				this.comp = comp;
			}
			
			@Override
			public int compare(IPAddressStringOrdering o1, IPAddressStringOrdering o2) {
				IPAddress one = o1.nestedType.getAddress();
				IPAddress two = o2.nestedType.getAddress();
				if(one != null && two != null) {
					return comp.compare(one, two);
				}
				return o1.nestedType.compareTo(o2.nestedType);
			}
		}
		
		class MACOrderingComparator implements Comparator<MACAddressStringOrdering> {
			private final AddressComparator comp;
			
			MACOrderingComparator(AddressComparator comp) {
				this.comp = comp;
			}
			
			@Override
			public int compare(MACAddressStringOrdering o1, MACAddressStringOrdering o2) {
				MACAddress one = o1.nestedType.getAddress();
				MACAddress two = o2.nestedType.getAddress();
				if(one != null && two != null) {
					return comp.compare(one, two);
				}
				return o1.nestedType.compareTo(o2.nestedType);
			}
		}
		
		OrderingSupplier<AddressOrdering> ipAddressSupplier = (s, i) -> {
			IPAddress addr = createAddress(s).getAddress();
			return addr == null ? null : new AddressOrdering(addr, i);
		};

		OrderingSupplier<AddressOrdering> macAddressSupplier = (s, i) -> {
			MACAddress addr = createMACAddress(s).getAddress();
			return addr == null ? null : new AddressOrdering(addr, i);
		};
		
		OrderingSupplier<IPAddressStringOrdering> nullIPAddressSupplier = (s, i) -> null;
		OrderingSupplier<MACAddressStringOrdering> nullMACAddressSupplier = (s, i) -> null;
		
		testDefaultOrder(new ArrayList<IPAddressStringOrdering>(), IPAddressStringOrdering::new, nullIPAddressSupplier);//cannot remember if there is a reason why we do this one twice
		
		ValueComparator lowValComparator = new ValueComparator(true, false);
		
		testLowValueOrder(new ArrayList<IPAddressStringOrdering>(), new IPAddressOrderingComparator(lowValComparator), IPAddressStringOrdering::new, nullIPAddressSupplier);
		testLowValueOrder(new ArrayList<MACAddressStringOrdering>(), new MACOrderingComparator(lowValComparator), nullMACAddressSupplier, MACAddressStringOrdering::new);
		testLowValueOrder(new ArrayList<AddressOrdering>(), new AddressOrderingComparator(lowValComparator), ipAddressSupplier, macAddressSupplier);
		
		ValueComparator highValComparator = new ValueComparator(true, true);
		
		testHighValueOrder(new ArrayList<IPAddressStringOrdering>(), new IPAddressOrderingComparator(highValComparator), IPAddressStringOrdering::new, nullIPAddressSupplier);
		testHighValueOrder(new ArrayList<MACAddressStringOrdering>(), new MACOrderingComparator(highValComparator), nullMACAddressSupplier, MACAddressStringOrdering::new);
		testHighValueOrder(new ArrayList<AddressOrdering>(), new AddressOrderingComparator(highValComparator), ipAddressSupplier, macAddressSupplier);
		
		testDefaultOrder(new ArrayList<IPAddressStringOrdering>(), IPAddressStringOrdering::new, nullIPAddressSupplier);
		testDefaultOrder(new ArrayList<MACAddressStringOrdering>(), nullMACAddressSupplier, MACAddressStringOrdering::new);
		testDefaultOrder(new ArrayList<AddressOrdering>(), ipAddressSupplier, macAddressSupplier);
	}
	
	interface OrderingSupplier<T extends Ordering<T, ?>> {
		T supply(String string, int order);
	}
	
	<T extends Ordering<T, ?>> void testHighValueOrder(ArrayList<T> ordering, Comparator<T> comparator, OrderingSupplier<T> ipAddressSupplier, OrderingSupplier<T> macAddressSupplier) {
		
		//order is INVALID, EMPTY, IPV4, IPV6, PREFIX_ONLY, ALL
		int orderNumber = 0;
		
		//invalid
		String strs[] = new String[] {//these are already sorted by natural string ordering
			"/129", //invalid prefix
			"bla",
			"fo",
			"foo",
			"four",
			"xxx"
		};
		for(String s : strs) {
			ordering.add(ipAddressSupplier.supply(s, orderNumber));
			ordering.add(macAddressSupplier.supply(s, orderNumber));
			orderNumber++;
		}
		
		//empty
		ordering.add(macAddressSupplier.supply("", orderNumber));
		ordering.add(macAddressSupplier.supply("  ", orderNumber));
		ordering.add(macAddressSupplier.supply("     ", orderNumber));
		ordering.add(macAddressSupplier.supply("", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("1:0:0:0:0:0", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("1:0:0:2:3:4", orderNumber));
		ordering.add(macAddressSupplier.supply("1:00:00:2:03:4", orderNumber));
		ordering.add(macAddressSupplier.supply("1:0:0:2:3:4", orderNumber));
		ordering.add(macAddressSupplier.supply("01:00:00:02:03:04", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("1:0:0:2:3:*", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("1:0:0:2:3-4:*", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("1:0:2:1-3:4:*", orderNumber));
		orderNumber++;
		
		
		ordering.add(macAddressSupplier.supply("1:0-7f:2:3:*:*", orderNumber));
		orderNumber++;
		
		
		ordering.add(macAddressSupplier.supply("1:*:2:03:4:*", orderNumber));
		ordering.add(macAddressSupplier.supply("01:*:02:03:04:*", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("1:f0-ff:2:3:4:*", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("1:0-ff:*:*:*:8", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("0-1:*:*:*:*:*", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("a1:f0:2:3:4:*", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("ff:0:0:fe:ff:fe", orderNumber));
		orderNumber++;
		ordering.add(macAddressSupplier.supply("ff:0:0:fe:ff:ff", orderNumber));
		orderNumber++;
		ordering.add(macAddressSupplier.supply("ff:0:0:ff:ff:fe", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("*:0:0:*:*:*", orderNumber));
		ordering.add(macAddressSupplier.supply("*:0:0:*:%*:*", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("ff:0:0:ff:ff:ff", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("*:*:a:*:*:*", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("*:*:*:*:*:*", orderNumber));
		ordering.add(macAddressSupplier.supply("*:*", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("ff:ff:ff:ff:ff:ff", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("0:0:0:0:0:0:0:1", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("1:0:0:0:0:0:0:0", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("*:*:*:*:*:*:*:*", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("ff:ff:ff:ff:ff:ff:ff:ff", orderNumber));
		orderNumber++;
		
		//empty
		ordering.add(ipAddressSupplier.supply("", orderNumber));
		ordering.add(ipAddressSupplier.supply("  ", orderNumber));
		ordering.add(ipAddressSupplier.supply("     ", orderNumber));
		ordering.add(ipAddressSupplier.supply("", orderNumber));
		orderNumber++;
				
		//a bunch of address and prefixes
		
		boolean isNoAutoSubnets = prefixConfiguration.prefixedSubnetsAreExplicit();
		
		ordering.add(ipAddressSupplier.supply("1.0.0.0", orderNumber));
		orderNumber++;
		
		if(isNoAutoSubnets) {
			ordering.add(ipAddressSupplier.supply("1.002.0.0/16", orderNumber));
			ordering.add(ipAddressSupplier.supply("001.002.000.000/16", orderNumber));
			ordering.add(ipAddressSupplier.supply("1.2.000.0/15", orderNumber));
			orderNumber++;
			ordering.add(ipAddressSupplier.supply("1.002.0.*/17", orderNumber));
			orderNumber++;
		}
		
		ordering.add(ipAddressSupplier.supply("1.002.3.4", orderNumber));
		ordering.add(ipAddressSupplier.supply("1.2.003.4", orderNumber));
		ordering.add(ipAddressSupplier.supply("1.2.3.4", orderNumber));
		ordering.add(ipAddressSupplier.supply("001.002.003.004", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("1.002.3.*", orderNumber));
		ordering.add(ipAddressSupplier.supply("1.002.3.*/31", orderNumber));
		orderNumber++;
		if(!isNoAutoSubnets) {
			ordering.add(ipAddressSupplier.supply("1.002.0.*/17", orderNumber));
			orderNumber++;
			ordering.add(ipAddressSupplier.supply("1.002.0.0/16", orderNumber));
			ordering.add(ipAddressSupplier.supply("001.002.000.000/16", orderNumber));
		}
		ordering.add(ipAddressSupplier.supply("1.002.*.*/16", orderNumber));
		orderNumber++;
		
		if(!isNoAutoSubnets) {
			ordering.add(ipAddressSupplier.supply("1.2.000.0/15", orderNumber));
		}
		ordering.add(ipAddressSupplier.supply("1.2-3.*.*/15", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("255.254.255.254", orderNumber));
		orderNumber++;
		ordering.add(ipAddressSupplier.supply("255.254.255.255", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("*.*.1-3.*", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("255.255.255.254", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("*.*.*.*", orderNumber));
		ordering.add(ipAddressSupplier.supply("*.*.%*.*", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("255.255.255.255", orderNumber));
		orderNumber++;
		
		//ipv6
		
		ordering.add(ipAddressSupplier.supply("1::", orderNumber));
		if(isNoAutoSubnets) {
			ordering.add(ipAddressSupplier.supply("1::/17", orderNumber));
			ordering.add(ipAddressSupplier.supply("1::/16", orderNumber));
			ordering.add(ipAddressSupplier.supply("0001:0000::0000:0000:0000/16", orderNumber));
		}
		orderNumber++;
		
		if(isNoAutoSubnets) {
			ordering.add(ipAddressSupplier.supply("1::*/31", orderNumber));
			ordering.add(ipAddressSupplier.supply("1::*/17", orderNumber));
			orderNumber++;
			ordering.add(ipAddressSupplier.supply("1::2:2:*/111", orderNumber));
			orderNumber++;
		}
		
		ordering.add(ipAddressSupplier.supply("1::2:3:4", orderNumber));
		ordering.add(ipAddressSupplier.supply("1::2:003:4", orderNumber));
		ordering.add(ipAddressSupplier.supply("1::2:3:4", orderNumber));
		ordering.add(ipAddressSupplier.supply("0001:0000::0002:0003:0004", orderNumber));
		orderNumber++;
		
		if(!isNoAutoSubnets) {
			ordering.add(ipAddressSupplier.supply("1::2:2:*/111", orderNumber));
			orderNumber++;
		}
		
		ordering.add(ipAddressSupplier.supply("1::2:3:*/127", orderNumber));
		ordering.add(ipAddressSupplier.supply("1::2:3:*", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("1::2:1-3:4:*", orderNumber));
		orderNumber++;
		
		if(!isNoAutoSubnets) {
			ordering.add(ipAddressSupplier.supply("1::*/31", orderNumber));
			orderNumber++;
			ordering.add(ipAddressSupplier.supply("1::/17", orderNumber));
			ordering.add(ipAddressSupplier.supply("1::*/17", orderNumber));
		}
		ordering.add(ipAddressSupplier.supply("1:0:*/17", orderNumber));
		orderNumber++;
		
		if(isNoAutoSubnets) {
			ordering.add(ipAddressSupplier.supply("1:8000::/17", orderNumber));
			orderNumber++;
		} else {
			ordering.add(ipAddressSupplier.supply("1::/16", orderNumber));
			ordering.add(ipAddressSupplier.supply("0001:0000::0000:0000:0000/16", orderNumber));
		}
		
		ordering.add(ipAddressSupplier.supply("1:*/17", orderNumber));
		ordering.add(ipAddressSupplier.supply("1:*/16", orderNumber));
		orderNumber++;
		
		if(!isNoAutoSubnets) {
			ordering.add(ipAddressSupplier.supply("1:8000::/17", orderNumber));
			orderNumber++;
		}
		
		ordering.add(ipAddressSupplier.supply("2::/15", orderNumber));
		if(isNoAutoSubnets) {
			orderNumber++;
		}
		ordering.add(ipAddressSupplier.supply("2:*/15", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("a1:8000::/17", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("ffff::fffe:ffff:fffe", orderNumber));
		orderNumber++;
		ordering.add(ipAddressSupplier.supply("ffff::fffe:ffff:ffff", orderNumber));
		orderNumber++;
		ordering.add(ipAddressSupplier.supply("ffff::ffff:ffff:fffe", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("*::*:*:*", orderNumber));
		ordering.add(ipAddressSupplier.supply("*::*:%*:*", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("ffff::ffff:ffff:ffff", orderNumber));
		orderNumber++;
		
		if(isNoAutoSubnets) {
			ordering.add(ipAddressSupplier.supply("*::*:*:*:*:*/16", orderNumber));
			orderNumber++;
		}
		ordering.add(ipAddressSupplier.supply("*:*:a:*:*:*:*:*", orderNumber));
		orderNumber++;
		
		if(!isNoAutoSubnets) {
			ordering.add(ipAddressSupplier.supply("*::*:*:*:*:*/16", orderNumber));
		
			ordering.add(ipAddressSupplier.supply("*:*", orderNumber));
			ordering.add(ipAddressSupplier.supply("*:*:*:*:*:*:*:*", orderNumber));
			orderNumber++;
		}

		ordering.add(ipAddressSupplier.supply("/33", orderNumber));//interpreted as ipv6
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("/64", orderNumber));//interpreted as ipv6
		orderNumber++;
		
		if(isNoAutoSubnets) {
			ordering.add(ipAddressSupplier.supply("*:*", orderNumber));
			ordering.add(ipAddressSupplier.supply("*:*:*:*:*:*:*:*", orderNumber));
			orderNumber++;
		}
		ordering.add(ipAddressSupplier.supply("/128", orderNumber));//interpreted as ipv6
		orderNumber++;

		ordering.add(ipAddressSupplier.supply("/32", orderNumber));
		orderNumber++;
		ordering.add(ipAddressSupplier.supply("/24", orderNumber));
		orderNumber++;
		ordering.add(ipAddressSupplier.supply("/0", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("*", orderNumber));
		ordering.add(ipAddressSupplier.supply("**", orderNumber));
		ordering.add(ipAddressSupplier.supply(" *", orderNumber));
		ordering.add(ipAddressSupplier.supply("%%", orderNumber));
		orderNumber++;
		
		checkOrdering(ordering, orderNumber, comparator);
	}
	
	<T extends Ordering<T, ?>> void testLowValueOrder(ArrayList<T> ordering, Comparator<T> comparator, OrderingSupplier<T> ipAddressSupplier, OrderingSupplier<T> macAddressSupplier) {
		
		//order is INVALID, EMPTY, IPV4, IPV6, PREFIX_ONLY, ALL
		int orderNumber = 0;

		//invalid
		String strs[] = new String[] {//these are already sorted by natural string ordering
			"/129", //invalid prefix
			"bla",
			"fo",
			"foo",
			"four",
			"xxx"
		};
		for(String s : strs) {
			ordering.add(ipAddressSupplier.supply(s, orderNumber++));
			ordering.add(macAddressSupplier.supply(s, orderNumber++));
		}
		
		//empty
		ordering.add(macAddressSupplier.supply("", orderNumber));
		ordering.add(macAddressSupplier.supply("  ", orderNumber));
		ordering.add(macAddressSupplier.supply("     ", orderNumber));
		ordering.add(macAddressSupplier.supply("", orderNumber));
		orderNumber++;
				
		ordering.add(macAddressSupplier.supply("0-1:*:*:*:*:*", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("*:0:0:*:*:*", orderNumber));
		ordering.add(macAddressSupplier.supply("*:0:0:*:%*:*", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("*:*:*:*:*:*", orderNumber));
		ordering.add(macAddressSupplier.supply("*:*", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("*:*:a:*:*:*", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("1:0:0:0:0:0", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("1:0-ff:*:*:*:8", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("1:0:0:2:3:*", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("1:0:0:2:3-4:*", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("1:0:0:2:3:4", orderNumber));
		ordering.add(macAddressSupplier.supply("1:00:00:2:03:4", orderNumber));
		ordering.add(macAddressSupplier.supply("1:0:0:2:3:4", orderNumber));
		ordering.add(macAddressSupplier.supply("01:00:00:02:03:04", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("1:0:2:1-3:4:*", orderNumber));
		orderNumber++;
		
		
		ordering.add(macAddressSupplier.supply("1:0-7f:2:3:*:*", orderNumber));
		orderNumber++;
		
		
		ordering.add(macAddressSupplier.supply("1:*:2:03:4:*", orderNumber));
		ordering.add(macAddressSupplier.supply("01:*:02:03:04:*", orderNumber));
		orderNumber++;
		
		
		ordering.add(macAddressSupplier.supply("1:f0-ff:2:3:4:*", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("a1:f0:2:3:4:*", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("ff:0:0:fe:ff:fe", orderNumber));
		orderNumber++;
		ordering.add(macAddressSupplier.supply("ff:0:0:fe:ff:ff", orderNumber));
		orderNumber++;
		ordering.add(macAddressSupplier.supply("ff:0:0:ff:ff:fe", orderNumber));
		orderNumber++;
		
		
		ordering.add(macAddressSupplier.supply("ff:0:0:ff:ff:ff", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("ff:ff:ff:ff:ff:ff", orderNumber));
		orderNumber++;

		ordering.add(macAddressSupplier.supply("*:*:*:*:*:*:*:*", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("0:0:0:0:0:0:0:1", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("1:0:0:0:0:0:0:0", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("ff:ff:ff:ff:ff:ff:ff:ff", orderNumber));
		orderNumber++;

		//empty
		ordering.add(ipAddressSupplier.supply("", orderNumber));
		ordering.add(ipAddressSupplier.supply("  ", orderNumber));
		ordering.add(ipAddressSupplier.supply("     ", orderNumber));
		ordering.add(ipAddressSupplier.supply("", orderNumber));
		orderNumber++;
		
		
		
		boolean isNoAutoSubnets = prefixConfiguration.prefixedSubnetsAreExplicit();

		
		//a bunch of address and prefixes
		
		ordering.add(ipAddressSupplier.supply("*.*.*.*", orderNumber));
		ordering.add(ipAddressSupplier.supply("*.*.%*.*", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("*.*.1-3.*", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("1.0.0.0", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("1.000.0.*/17", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("1.002.0.0/16", orderNumber));
		ordering.add(ipAddressSupplier.supply("001.002.000.000/16", orderNumber));
		if(!isNoAutoSubnets) {
			ordering.add(ipAddressSupplier.supply("1.002.*.*/16", orderNumber));
			orderNumber++;
		}
		ordering.add(ipAddressSupplier.supply("1.2.000.0/15", orderNumber));
		if(isNoAutoSubnets) {
			orderNumber++;
			ordering.add(ipAddressSupplier.supply("1.002.*.*/16", orderNumber));
			orderNumber++;
		}
		ordering.add(ipAddressSupplier.supply("1.2-3.*.*/15", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("1.002.3.*", orderNumber));
		ordering.add(ipAddressSupplier.supply("1.002.3.*/31", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("1.002.3.4", orderNumber));
		ordering.add(ipAddressSupplier.supply("1.2.003.4", orderNumber));
		ordering.add(ipAddressSupplier.supply("1.2.3.4", orderNumber));
		ordering.add(ipAddressSupplier.supply("001.002.003.004", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("255.254.255.254", orderNumber));
		orderNumber++;
		ordering.add(ipAddressSupplier.supply("255.254.255.255", orderNumber));
		orderNumber++;
		ordering.add(ipAddressSupplier.supply("255.255.255.254", orderNumber));
		orderNumber++;
		ordering.add(ipAddressSupplier.supply("255.255.255.255", orderNumber));
		orderNumber++;
		
		//ipv6
		
		
		ordering.add(ipAddressSupplier.supply("*::*:*:*", orderNumber));
		ordering.add(ipAddressSupplier.supply("*::*:%*:*", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("*::*:*:*:*:*/16", orderNumber));
		if(isNoAutoSubnets) {
			orderNumber++;
		}
		ordering.add(ipAddressSupplier.supply("*:*", orderNumber));
		ordering.add(ipAddressSupplier.supply("*:*:*:*:*:*:*:*", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("*:*:a:*:*:*:*:*", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("1::", orderNumber));
		if(!isNoAutoSubnets) {
			orderNumber++;
		}
		
		ordering.add(ipAddressSupplier.supply("1::/31", orderNumber));
		if(!isNoAutoSubnets) {
			orderNumber++;
		}
		
		ordering.add(ipAddressSupplier.supply("1::/17", orderNumber));
		ordering.add(ipAddressSupplier.supply("1:0::/17", orderNumber));
		if(!isNoAutoSubnets) {
			orderNumber++;
		}
		ordering.add(ipAddressSupplier.supply("1::/16", orderNumber));
		ordering.add(ipAddressSupplier.supply("0001:0000::0000:0000:0000/16", orderNumber));
		if(isNoAutoSubnets) {
			orderNumber++;
		}
		ordering.add(ipAddressSupplier.supply("1:0::*/16", orderNumber));
		if(isNoAutoSubnets) {
			orderNumber++;
		}
		ordering.add(ipAddressSupplier.supply("1:0:*/16", orderNumber));
		if(isNoAutoSubnets) {
			orderNumber++;
		}
		ordering.add(ipAddressSupplier.supply("1:*/17", orderNumber));
		ordering.add(ipAddressSupplier.supply("1:*/16", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("1::2:2:*/111", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("1::2:3:*/127", orderNumber));
		ordering.add(ipAddressSupplier.supply("1::2:3:*", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("1::2:3:4", orderNumber));
		ordering.add(ipAddressSupplier.supply("1::2:003:4", orderNumber));
		ordering.add(ipAddressSupplier.supply("1::2:3:4", orderNumber));
		ordering.add(ipAddressSupplier.supply("0001:0000::0002:0003:0004", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("1::2:1-3:4:*", orderNumber));
		orderNumber++;

		ordering.add(ipAddressSupplier.supply("1:8000::/17", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("2::/15", orderNumber));
		if(isNoAutoSubnets) {
			orderNumber++;
		}
		ordering.add(ipAddressSupplier.supply("2::0:*/15", orderNumber));
		if(isNoAutoSubnets) {
			orderNumber++;
		}
		ordering.add(ipAddressSupplier.supply("2:0:*/15", orderNumber));
		if(isNoAutoSubnets) {
			orderNumber++;
		}
		ordering.add(ipAddressSupplier.supply("2:*/15", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("a1:8000::/17", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("ffff::fffe:ffff:fffe", orderNumber));
		orderNumber++;
		ordering.add(ipAddressSupplier.supply("ffff::fffe:ffff:ffff", orderNumber));
		orderNumber++;
		ordering.add(ipAddressSupplier.supply("ffff::ffff:ffff:fffe", orderNumber));
		orderNumber++;
		ordering.add(ipAddressSupplier.supply("ffff::ffff:ffff:ffff", orderNumber));
		orderNumber++;

		ordering.add(ipAddressSupplier.supply("/33", orderNumber));//interpreted as ipv6, ffff:ffff:8000::/33
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("ffff:ffff:ffff::", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("/64", orderNumber));//interpreted as ipv6 ffff:ffff:ffff:ffff::
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("ffff:ffff:ffff:ffff::1", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("/128", orderNumber));//interpreted as ipv6
		orderNumber++;
		
		
		ordering.add(ipAddressSupplier.supply("/32", orderNumber));
		orderNumber++;
		ordering.add(ipAddressSupplier.supply("/24", orderNumber));
		orderNumber++;
		ordering.add(ipAddressSupplier.supply("/0", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("*", orderNumber));
		ordering.add(ipAddressSupplier.supply("**", orderNumber));
		ordering.add(ipAddressSupplier.supply(" *", orderNumber));
		ordering.add(ipAddressSupplier.supply("%%", orderNumber));
		orderNumber++;
		
		checkOrdering(ordering, orderNumber, comparator);
	}

	private <T extends Ordering<T, ?>> void checkOrdering(ArrayList<T> ordering, int orderCount, Comparator<? super T> comparator) {
		//Count the number of unique ones using a hashset
//		HashSet<Ordering<? ,?>> counterSet = new HashSet<Ordering<? ,?>>();
//		counterSet.addAll(ordering);
//		
//		if(counterSet.size() < orderCount) {
//			addFailure(new Failure("mismatch of unique addresses, expected " + orderCount + " got " + counterSet.size()));
//		}
		
		//mix em up by using a hashset - we need to wrap them to ensure this set doesn't consider any of them equal
		class Wrapper {
			private final T o;
			
			Wrapper(T o) {
				this.o = o;
			}
		}
		HashSet<Wrapper> set = new HashSet<Wrapper>();
		for(T o : ordering) {
			if(o != null) {
				set.add(new Wrapper(o));
			}
		}
		ordering.clear();
		for(Wrapper w : set) {
			ordering.add(w.o);
		}
		
		if(comparator != null) {
			Collections.sort(ordering, comparator);
		} else {
			Collections.sort(ordering);
		}
		
		ArrayList<String> sorted = new ArrayList<String>(ordering.size());
		int previousOrder = -1, lastIndex = -1;
		for(int i = 0; i < ordering.size(); i++) {
			Ordering<?, ?> o = ordering.get(i);
			int currentOrder = o.order;
			int index;
			if(currentOrder == previousOrder) {
				index = lastIndex;
			} else {
				index = i + 1;
			}
			sorted.add("\n(" + index + ") " + o.nestedType + ' ' + o.getDescription());
			previousOrder = currentOrder;
			lastIndex = index;
		}
		
		boolean failedOrdering = false;
		int lastOrder = -1;
		for(int i = 0; i < ordering.size(); i++) {
			Ordering<?, ?> orderingItem = ordering.get(i);
			int order = orderingItem.order;
			if(order < lastOrder) {
				failedOrdering = true;
				addFailure(new Failure("item " + (i + 1) + ": " + orderingItem.nestedType + " is in wrong place in ordering ( order number: " + order + ", previous order number: " + lastOrder + ")"));
			}
			lastOrder = order;
		}
		
		if(failedOrdering) {
			addFailure(new Failure("ordering failed: " + sorted));
		}
		
		incrementTestCount();
	}
	
	/**
	 * The default order goes by count first, and then the count of the more significant segment followed the lower value magnitude in the same segment.
	 */
	<T extends Ordering<T, ?>> void testDefaultOrder(ArrayList<T> ordering, OrderingSupplier<T> ipAddressSupplier, OrderingSupplier<T> macAddressSupplier) {
		
		//invalid
		String strs[] = new String[] {//these are already sorted by natural string ordering
			"/129", //invalid prefix
			"bla",
			"fo",
			"foo",
			"four",
			"xxx"
		};
		
		//order is INVALID, EMPTY, IPV4, IPV6, PREFIX_ONLY, ALL
		int orderNumber = 0;

		for(String s : strs) {
			ordering.add(ipAddressSupplier.supply(s, orderNumber));
			ordering.add(macAddressSupplier.supply(s, orderNumber));
			orderNumber++;
		}
		
		//empty
		ordering.add(macAddressSupplier.supply("", orderNumber));
		ordering.add(macAddressSupplier.supply("  ", orderNumber));
		ordering.add(macAddressSupplier.supply("     ", orderNumber));
		ordering.add(macAddressSupplier.supply("", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("1:0:0:0:0:0", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("1:0:0:2:3:4", orderNumber));
		ordering.add(macAddressSupplier.supply("1:00:00:2:03:4", orderNumber));
		ordering.add(macAddressSupplier.supply("1:0:0:2:3:4", orderNumber));
		ordering.add(macAddressSupplier.supply("01:00:00:02:03:04", orderNumber));
		orderNumber++;
		
		
		ordering.add(macAddressSupplier.supply("ff:0:0:fe:ff:fe", orderNumber));
		orderNumber++;
		ordering.add(macAddressSupplier.supply("ff:0:0:fe:ff:ff", orderNumber));
		orderNumber++;
		ordering.add(macAddressSupplier.supply("ff:0:0:ff:ff:fe", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("ff:0:0:ff:ff:ff", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("ff:ff:ff:ff:ff:ff", orderNumber));
		orderNumber++;
		
		
		ordering.add(macAddressSupplier.supply("1:0:0:2:3:*", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("a1:f0:2:3:4:*", orderNumber));
		orderNumber++;
		
		
		ordering.add(macAddressSupplier.supply("1:0:0:2:3-4:*", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("1:0:2:1-3:4:*", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("1:f0-ff:2:3:4:*", orderNumber));
		orderNumber++;

		ordering.add(macAddressSupplier.supply("1:*:2:03:4:*", orderNumber));
		ordering.add(macAddressSupplier.supply("01:*:02:03:04:*", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("1:0-7f:2:3:*:*", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("1:0-ff:*:*:*:8", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("*:0:0:*:*:*", orderNumber));
		ordering.add(macAddressSupplier.supply("*:0:0:*:%*:*", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("1:*:*:*:*:*", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("*:*:a:*:*:*", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("0-1:*:*:*:*:*", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("*:*:*:*:*:*", orderNumber));
		ordering.add(macAddressSupplier.supply("*:*", orderNumber));
		orderNumber++;
		
		
		
		ordering.add(macAddressSupplier.supply("0:0:0:0:0:0:0:1", orderNumber));
		orderNumber++;
		
		ordering.add(macAddressSupplier.supply("1:0:0:0:0:0:0:0", orderNumber));
		orderNumber++;
		
		
		ordering.add(macAddressSupplier.supply("ff:ff:ff:ff:ff:ff:ff:ff", orderNumber));
		orderNumber++;
				
		ordering.add(macAddressSupplier.supply("*:*:*:*:*:*:*:*", orderNumber));
		orderNumber++;
		
		boolean isNoAutoSubnets = prefixConfiguration.prefixedSubnetsAreExplicit();

		//empty
		ordering.add(ipAddressSupplier.supply("", orderNumber));
		ordering.add(ipAddressSupplier.supply("  ", orderNumber));
		ordering.add(ipAddressSupplier.supply("     ", orderNumber));
		ordering.add(ipAddressSupplier.supply("", orderNumber));
		orderNumber++;
		
		//a bunch of address and prefixes
		ordering.add(ipAddressSupplier.supply("1.0.0.0", orderNumber));
		orderNumber++;
		
		if(isNoAutoSubnets) {
			ordering.add(ipAddressSupplier.supply("1.002.0.0/16", orderNumber));
			ordering.add(ipAddressSupplier.supply("001.002.000.000/16", orderNumber));

			ordering.add(ipAddressSupplier.supply("1.2.000.0/15", orderNumber));
			ordering.add(ipAddressSupplier.supply("1.2.0.0/15", orderNumber));
			orderNumber++;
		}
	
		ordering.add(ipAddressSupplier.supply("1.002.3.4", orderNumber));
		ordering.add(ipAddressSupplier.supply("1.2.003.4", orderNumber));
		ordering.add(ipAddressSupplier.supply("1.2.3.4", orderNumber));
		ordering.add(ipAddressSupplier.supply("001.002.003.004", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("255.254.255.254", orderNumber));
		orderNumber++;
		ordering.add(ipAddressSupplier.supply("255.254.255.255", orderNumber));
		orderNumber++;
		ordering.add(ipAddressSupplier.supply("255.255.255.254", orderNumber));
		orderNumber++;
		ordering.add(ipAddressSupplier.supply("255.255.255.255", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("1.002.3.*", orderNumber));
		ordering.add(ipAddressSupplier.supply("1.002.3.*/31", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("1.002.*.*/17", orderNumber));
		ordering.add(ipAddressSupplier.supply("1.002.*.*/16", orderNumber));
		
		if(!isNoAutoSubnets) {
			ordering.add(ipAddressSupplier.supply("1.002.0.0/16", orderNumber));
			ordering.add(ipAddressSupplier.supply("001.002.000.000/16", orderNumber));
		
			orderNumber++;
		
			ordering.add(ipAddressSupplier.supply("1.2.000.0/15", orderNumber));
			ordering.add(ipAddressSupplier.supply("1.2.0.0/15", orderNumber));
		}
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("*.*.1-3.*", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("*.*.*.*", orderNumber));
		ordering.add(ipAddressSupplier.supply("*.*.%*.*", orderNumber));
		orderNumber++;
		
		//xx ipv6 x;
		
		ordering.add(ipAddressSupplier.supply("1::", orderNumber));
		
		if(isNoAutoSubnets) {
			ordering.add(ipAddressSupplier.supply("1::/17", orderNumber));
			ordering.add(ipAddressSupplier.supply("1::/16", orderNumber));
			ordering.add(ipAddressSupplier.supply("0001::/16", orderNumber));
		}
		orderNumber++;
			
		ordering.add(ipAddressSupplier.supply("1::2:3:4", orderNumber));
		ordering.add(ipAddressSupplier.supply("1::2:003:4", orderNumber));
		ordering.add(ipAddressSupplier.supply("1::2:3:4", orderNumber));
		ordering.add(ipAddressSupplier.supply("0001:0000::0002:0003:0004", orderNumber));
		orderNumber++;
		
		if(isNoAutoSubnets) {
			ordering.add(ipAddressSupplier.supply("1:8000::/17", orderNumber));
			orderNumber++;
			ordering.add(ipAddressSupplier.supply("2::/15", orderNumber));
			orderNumber++;
			ordering.add(ipAddressSupplier.supply("a1:8000::/17", orderNumber));
			orderNumber++;
		}
		
		ordering.add(ipAddressSupplier.supply("ffff::fffe:ffff:fffe", orderNumber));
		orderNumber++;
		ordering.add(ipAddressSupplier.supply("ffff::fffe:ffff:ffff", orderNumber));
		orderNumber++;
		ordering.add(ipAddressSupplier.supply("ffff::ffff:ffff:fffe", orderNumber));
		orderNumber++;
		ordering.add(ipAddressSupplier.supply("ffff::ffff:ffff:ffff", orderNumber));
		orderNumber++;

		if(isNoAutoSubnets) {
			ordering.add(ipAddressSupplier.supply("/33", orderNumber));//interpreted as ipv6
			orderNumber++;
			ordering.add(ipAddressSupplier.supply("/64", orderNumber));//interpreted as ipv6
			orderNumber++;
		}

		ordering.add(ipAddressSupplier.supply("/128", orderNumber));//interpreted as ipv6
		orderNumber++;

		ordering.add(ipAddressSupplier.supply("1::2:3:*/127", orderNumber));
		ordering.add(ipAddressSupplier.supply("1::2:3:*", orderNumber));
		ordering.add(ipAddressSupplier.supply("1::2:3:*/111", orderNumber));
		orderNumber++;
		ordering.add(ipAddressSupplier.supply("1::2:1-3:4:*", orderNumber));
		orderNumber++;
		
		if(!isNoAutoSubnets) {
			ordering.add(ipAddressSupplier.supply("/64", orderNumber));//interpreted as ipv6
			orderNumber++;
		}
		
		ordering.add(ipAddressSupplier.supply("*::*:*:*", orderNumber));
		ordering.add(ipAddressSupplier.supply("*::*:%*:*", orderNumber));
		orderNumber++;
		
		if(!isNoAutoSubnets) {
			ordering.add(ipAddressSupplier.supply("/33", orderNumber));//interpreted as ipv6
			orderNumber++;
		}
		
		ordering.add(ipAddressSupplier.supply("1:0:*/31", orderNumber));
		orderNumber++;
		
		if(!isNoAutoSubnets) {
			ordering.add(ipAddressSupplier.supply("1::/17", orderNumber));
			orderNumber++;
			ordering.add(ipAddressSupplier.supply("1:8000::/17", orderNumber));
			orderNumber++;
			ordering.add(ipAddressSupplier.supply("a1:8000::/17", orderNumber));
			orderNumber++;
			ordering.add(ipAddressSupplier.supply("1::/16", orderNumber));
			ordering.add(ipAddressSupplier.supply("0001::/16", orderNumber));
			ordering.add(ipAddressSupplier.supply("1:*/16", orderNumber));
			orderNumber++;
		} else {
			ordering.add(ipAddressSupplier.supply("*::*:*:*:*:*/16", orderNumber));
			orderNumber++;
			ordering.add(ipAddressSupplier.supply("1:*/16", orderNumber));
			orderNumber++;
		}
		
		ordering.add(ipAddressSupplier.supply("*:*:a:*:*:*:*:*", orderNumber));
		orderNumber++;

		if(!isNoAutoSubnets) {
			ordering.add(ipAddressSupplier.supply("2::/15", orderNumber));
			orderNumber++;
			ordering.add(ipAddressSupplier.supply("*::*:*:*:*:*/16", orderNumber));
		}
		ordering.add(ipAddressSupplier.supply("*:*:*:*:*:*:*:*/16", orderNumber));
		ordering.add(ipAddressSupplier.supply("*:*", orderNumber));
		ordering.add(ipAddressSupplier.supply("*:*:*:*:*:*:*:*", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("/32", orderNumber));
		orderNumber++;
		ordering.add(ipAddressSupplier.supply("/24", orderNumber));
		orderNumber++;
		ordering.add(ipAddressSupplier.supply("/0", orderNumber));
		orderNumber++;
		
		ordering.add(ipAddressSupplier.supply("*", orderNumber));
		ordering.add(ipAddressSupplier.supply("**", orderNumber));
		ordering.add(ipAddressSupplier.supply(" *", orderNumber));
		ordering.add(ipAddressSupplier.supply("%%", orderNumber));
		orderNumber++;
		
		checkOrdering(ordering, orderNumber, null);
	}
	
	@Override
	void runTest() {
		testOrder();
	}
}
