/*
 * Copyright 2017 Sean C Foley
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

package inet.ipaddr.format.validate;

import java.io.Serializable;

import inet.ipaddr.mac.MACAddress;
import inet.ipaddr.mac.MACAddressSegment;

public class MACAddressProvider implements Serializable {

	private static final long serialVersionUID = 3L;
	
	private ParsedMACAddress parsedAddress;
	private MACAddress address;
	
	static final MACAddressProvider EMPTY_PROVIDER = new MACAddressProvider() {
		
		private static final long serialVersionUID = 3L;

		@Override
		public MACAddress getAddress() {
			return null;
		}
	};
	
	private static final MACAddress ALL_MAC_ADDRESSES = new MACAddress(new MACAddressSegment[] {
		MACAddressSegment.ALL_RANGE_SEGMENT,
		MACAddressSegment.ALL_RANGE_SEGMENT,
		MACAddressSegment.ALL_RANGE_SEGMENT,
		MACAddressSegment.ALL_RANGE_SEGMENT,
		MACAddressSegment.ALL_RANGE_SEGMENT,
		MACAddressSegment.ALL_RANGE_SEGMENT
	});
	
	static final MACAddressProvider ALL_MAC = new MACAddressProvider() {

		private static final long serialVersionUID = 3L;

		@Override
		public MACAddress getAddress() {
			return ALL_MAC_ADDRESSES;
		}
	};
	
	private static final MACAddress ALL_EUI_64_ADDRESSES = new MACAddress(new MACAddressSegment[] {
		MACAddressSegment.ALL_RANGE_SEGMENT,
		MACAddressSegment.ALL_RANGE_SEGMENT,
		MACAddressSegment.ALL_RANGE_SEGMENT,
		MACAddressSegment.ALL_RANGE_SEGMENT,
		MACAddressSegment.ALL_RANGE_SEGMENT,
		MACAddressSegment.ALL_RANGE_SEGMENT,
		MACAddressSegment.ALL_RANGE_SEGMENT,
		MACAddressSegment.ALL_RANGE_SEGMENT
	});
	
	static final MACAddressProvider ALL_EUI_64 = new MACAddressProvider() {

		private static final long serialVersionUID = 3L;

		@Override
		public MACAddress getAddress() {
			return ALL_EUI_64_ADDRESSES;
		}
	};
	
	private MACAddressProvider() {}
	
	public MACAddressProvider(ParsedMACAddress parsedAddress) {
		this.parsedAddress = parsedAddress;
	}
	
	public MACAddressProvider(MACAddress address) {
		this.address = address;
	}

	public MACAddress getAddress() {
		if(parsedAddress != null) {
			synchronized(this) {
				if(parsedAddress != null) {
					address = parsedAddress.createAddress();
					parsedAddress = null;
				}
			}
		}
		return address;
	}
	
	@Override
	public String toString() {
		return String.valueOf(getAddress());
	}
}
