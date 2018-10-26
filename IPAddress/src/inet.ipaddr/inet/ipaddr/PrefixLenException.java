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

import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.format.AddressItem;

public class PrefixLenException extends AddressValueException {

	private static final long serialVersionUID = 1L;
	
	static String getMessage(String key) {
		return AddressStringException.getMessage(key);
	}

	public PrefixLenException(int prefixLength) {
		super(errorMessage + " " + getMessage("ipaddress.error.prefixSize"));
	}
	
	public PrefixLenException(AddressItem one, int prefixLength) {
		super(one + ", " + errorMessage + " " + getMessage("ipaddress.error.prefixSize"));
	}
	
	public PrefixLenException(int prefixLength, IPVersion version) {
		super(version + " /" + prefixLength + ", " + errorMessage + " " + getMessage("ipaddress.error.prefixSize"));
	}
	
	public PrefixLenException(CharSequence prefixLength, IPVersion version, Throwable cause) {
		super(version + " /" + prefixLength + ", " + errorMessage + " " + getMessage("ipaddress.error.invalidCIDRPrefix"), cause);
	}
}
