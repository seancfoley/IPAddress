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

import inet.ipaddr.format.AddressItem;

/**
 * Represents situations when an address, address section, address segment, or address string represents a valid type or format but 
 * that type does not match the required type or format for a given operation.
 * 
 * All such occurrences occur only from subnet addresses and sections.
 * 
 * Examples include:
 * <ul>
 * <li>producing non-segmented hex, octal or base 85 strings from a subnet with a range that cannot be represented as a single range of values,
 * </li><li>masking multiple addresses in a way that produces a non-contiguous range of values in a segment,
 * </li><li>reversing values that are not reversible,
 * </li><li>producing new formats for which the range of values are incompatible with the new segments 
 * (EUI-64, IPv4 inet_aton formats, IPv4 embedded within IPv6, dotted MAC addresses from standard mac addresses, reverse DNS strings),
 * or
 * </li><li>using a subnet for an operation that requires a single address, such as with @link {@link IPAddress#toCanonicalHostName()}.
 * </li></ul>
 * These issues cannot occur with single-valued address objects.  In most cases, these issues cannot occur when using a standard prefix block subnet.
 * 
 * @author sfoley
 *
 */
public class IncompatibleAddressException extends RuntimeException {
	
	private static final long serialVersionUID = 4L;
	
	private static String errorMessage = getMessage("ipaddress.address.error");
	
	static String getMessage(String key) {
		return AddressStringException.getMessage(key);
	}
	
	public IncompatibleAddressException(AddressItem one, String key) {
		super(one + ", " + errorMessage + " " + getMessage(key));
	}
	
	public IncompatibleAddressException(CharSequence one, String key) {
		super(one + ", " + errorMessage + " " + getMessage(key));
	}
	
	public IncompatibleAddressException(long lower, long upper, String key) {
		super(lower + "-" + upper + ", " + errorMessage + " " + getMessage(key));
	}
	
	public IncompatibleAddressException(AddressItem one, int prefixLength, String key) {
		super(one + " /" + prefixLength + ", " + errorMessage + " " + getMessage(key));
	}
	
	public IncompatibleAddressException(AddressItem one, int oneIndex, AddressItem two, int twoIndex, String key) {
		super((oneIndex + 1) + ":" + one + ", " + (twoIndex + 1) + ":" + two + ", " + errorMessage + " " + getMessage(key));
	}
	
	public IncompatibleAddressException(AddressItem one, AddressItem two, String key) {
		super(one + ", " + two + ", " + errorMessage + " " + getMessage(key));
	}
}
