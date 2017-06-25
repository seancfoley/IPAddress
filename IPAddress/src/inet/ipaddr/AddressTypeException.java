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

package inet.ipaddr;

import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.format.AddressDivisionBase;
import inet.ipaddr.format.IPAddressDivision;

/**
 * Represents situations when an address, address section, address segment, or address string represents a valid type or format but 
 * that type does not match the required type or format for a given operation.
 * 
 * @author sfoley
 *
 */
public class AddressTypeException extends RuntimeException {
	
	private static final long serialVersionUID = 3L;
	
	private static String errorMessage = getMessage("ipaddress.address.error");
	
	static String getMessage(String key) {
		return AddressStringException.getMessage(key);
	}
	
	public AddressTypeException(Address one, String key) {
		super(one + ", " + errorMessage + " " + getMessage(key));
	}
	
	public AddressTypeException(AddressSection one, String key) {
		super(one + ", " + errorMessage + " " + getMessage(key));
	}
	
	public AddressTypeException(CharSequence one, String key) {
		super(one + ", " + errorMessage + " " + getMessage(key));
	}
	
	public AddressTypeException(long lower, long upper, String key) {
		super(lower + "-" + upper + ", " + errorMessage + " " + getMessage(key));
	}
	
	public AddressTypeException(IPAddressSection one, int prefixLength, String key) {
		super(one + " /" + prefixLength + ", " + errorMessage + " " + getMessage(key));
	}
	
	public AddressTypeException(IPAddressDivision one, int prefixLength, String key) {
		super(one + " /" + prefixLength + ", " + errorMessage + " " + getMessage(key));
	}
	
	public AddressTypeException(AddressDivisionBase one, String key) {
		super(one + " , " + errorMessage + " " + getMessage(key));
	}
	
	public AddressTypeException(int prefixLength, IPVersion version, String key) {
		super(version + " /" + prefixLength + ", " + errorMessage + " " + getMessage(key));
	}
	
	public AddressTypeException(int prefixLength, String key) {
		super(prefixLength + ", " + errorMessage + " " + getMessage(key));
	}
	
	public AddressTypeException(CharSequence prefixLength, IPVersion version, String key, Throwable cause) {
		super(version + " /" + prefixLength + ", " + errorMessage + " " + getMessage(key), cause);
	}
	
	public AddressTypeException(AddressDivisionBase one, int oneIndex, AddressDivisionBase two, int twoIndex, String key) {
		super((oneIndex + 1) + ":" + one + ", " + (twoIndex + 1) + ":" + two + ", " + errorMessage + " " + getMessage(key));
	}
	
	public AddressTypeException(AddressSegment one, AddressSegment two, String key) {
		super(one + ", " + two + ", " + errorMessage + " " + getMessage(key));
	}
	
	public AddressTypeException(AddressSection one, AddressSection two, String key) {
		super(one + ", " + two + ", " + errorMessage + " " + getMessage(key));
	}
}
