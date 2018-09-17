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

package inet.ipaddr.format.validate;

import java.io.Serializable;
import java.util.Arrays;

import inet.ipaddr.MACAddressStringParameters;
import inet.ipaddr.MACAddressStringParameters.AddressSize;
import inet.ipaddr.mac.MACAddress;
import inet.ipaddr.mac.MACAddressNetwork;
import inet.ipaddr.mac.MACAddressNetwork.MACAddressCreator;
import inet.ipaddr.mac.MACAddressSection;
import inet.ipaddr.mac.MACAddressSegment;

public interface MACAddressProvider extends Serializable {

	@SuppressWarnings("serial")
	static final MACAddressProvider EMPTY_PROVIDER = new MACAddressProvider() {
		
		@Override
		public MACAddress getAddress() {
			return null;
		}
		
		@Override
		public String toString() {
			return "null";
		}
	};
	
	static final class ParsedMACAddressProvider implements MACAddressProvider {
		
		private static final long serialVersionUID = 4L;
		
		private ParsedMACAddress parsedAddress;
		private MACAddress address;
		
		public ParsedMACAddressProvider(MACAddress address) {
			this.address = address;
		}

		@Override
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
	
	MACAddress getAddress();
	
	public static MACAddressProvider getAllProvider(MACAddressStringParameters validationOptions) {
		MACAddressNetwork network = validationOptions.getNetwork();
		AddressSize allAddresses = validationOptions.addressSize;
		MACAddressCreator creator = network.getAddressCreator();
		MACAddressSegment allRangeSegment = creator.createRangeSegment(0, MACAddress.MAX_VALUE_PER_SEGMENT);
		MACAddressSegment segments[] = creator.createSegmentArray(allAddresses == AddressSize.EUI64 ? 
			MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT :
			MACAddress.MEDIA_ACCESS_CONTROL_SEGMENT_COUNT);
		Arrays.fill(segments, allRangeSegment);
		return new MACAddressProvider() {

			private static final long serialVersionUID = 4L;

			@Override
			public MACAddress getAddress() {
				ParsedAddressCreator<MACAddress, MACAddressSection, MACAddressSection, MACAddressSegment> parsedCreator = creator;
				MACAddressSection section = parsedCreator.createSectionInternal(segments);
				return creator.createAddress(section);
			}
			
			@Override
			public String toString() {
				return String.valueOf(getAddress());
			}
		};
	}
}
