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

package inet.ipaddr;

import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv4.IPv4Address.IPv4AddressConverter;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.ipv6.IPv6Address.IPv6AddressConverter;

/**
 * 
 * @author sfoley
 *
 */
public interface IPAddressConverter extends IPv6AddressConverter, IPv4AddressConverter {
	/**
	 * returns whether the address is IPv4 or can be converted to IPv4.  If true, {@link #toIPv4(IPAddress)} returns non-null.
	 */
	boolean isIPv4Convertible(IPAddress address);
	
	/**
	 * returns whether the address is IPv6 or can be converted to IPv6.  If true, {@link #toIPv6(IPAddress)} returns non-null.
	 */
	boolean isIPv6Convertible(IPAddress address);
	
	public static class DefaultAddressConverter implements IPAddressConverter {

		@Override
		public IPv4Address toIPv4(IPAddress address) {
			if(isIPv4Convertible(address)) {
				return address.isIPv4() ? address.toIPv4() : address.toIPv6().getEmbeddedIPv4Address();
			}
			return null;
		}

		@Override
		public IPv6Address toIPv6(IPAddress address) {
			//using IPv4-mapped matches java.net behaviour.
			return address.isIPv6() ? address.toIPv6() : address.toIPv4().getIPv4MappedAddress();
		}

		@Override
		public boolean isIPv4Convertible(IPAddress address) {
			//using IPv4-mapped matches java.net behaviour.
			return address.isIPv4() || (!address.toIPv6().hasZone() && address.toIPv6().isIPv4Mapped());
		}

		@Override
		public boolean isIPv6Convertible(IPAddress address) {
			return true;
		}
	};
}