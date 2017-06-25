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
import inet.ipaddr.format.IPAddressDivision;

/**
 * Represents situations when an object represents a valid type or format but that type does not match the required type or format for a given operation.
 * 
 * @author sfoley
 *
 */
public class IPAddressTypeException extends RuntimeException {
	
	private static final long serialVersionUID = 1L;
	
	private static String errorMessage = getMessage("ipaddress.address.error");
	
	static String getMessage(String key) {
		return IPAddressStringException.getMessage(key);
	}
	
	public IPAddressTypeException(IPAddress one, String key) {
		super(one + ", " + errorMessage + " " + getMessage(key));
	}
	
	public IPAddressTypeException(IPAddressSection one, String key) {
		super(one + ", " + errorMessage + " " + getMessage(key));
	}
	
	public IPAddressTypeException(String one, String key) {
		super(one + ", " + errorMessage + " " + getMessage(key));
	}
	
	public IPAddressTypeException(long lower, long upper, String key) {
		super(lower + "-" + upper + ", " + errorMessage + " " + getMessage(key));
	}
	
	public IPAddressTypeException(IPAddressSection one, int prefixLength, String key) {
		super(one + " /" + prefixLength + ", " + errorMessage + " " + getMessage(key));
	}
	
	public IPAddressTypeException(IPAddressDivision one, int prefixLength, String key) {
		super(one + " /" + prefixLength + ", " + errorMessage + " " + getMessage(key));
	}
	
	public IPAddressTypeException(IPAddressDivision one, String key) {
		super(one + " , " + errorMessage + " " + getMessage(key));
	}
	
	public IPAddressTypeException(int prefixLength, IPVersion version, String key) {
		super(version + " /" + prefixLength + ", " + errorMessage + " " + getMessage(key));
	}
	
	public IPAddressTypeException(int prefixLength, String key) {
		super(prefixLength + ", " + errorMessage + " " + getMessage(key));
	}
	
	public IPAddressTypeException(CharSequence prefixLength, IPVersion version, String key, Throwable cause) {
		super(version + " /" + prefixLength + ", " + errorMessage + " " + getMessage(key), cause);
	}
	
	public IPAddressTypeException(IPAddressSegment one, int oneIndex, IPAddressSegment two, int twoIndex, String key) {
		super((oneIndex + 1) + ":" + one + ", " + (twoIndex + 1) + ":" + two + ", " + errorMessage + " " + getMessage(key));
	}
	
	public IPAddressTypeException(IPAddressSegment one, IPAddressSegment two, String key) {
		super(one + ", " + two + ", " + errorMessage + " " + getMessage(key));
	}
	
	public IPAddressTypeException(IPAddressSection one, IPAddressSection two, String key) {
		super(one + ", " + two + ", " + errorMessage + " " + getMessage(key));
	}
}
