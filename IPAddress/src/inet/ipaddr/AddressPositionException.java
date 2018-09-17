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
 * IPv6 and MAC address sections are not position-independent, which means they have a designated location within a full address.
 * <p>
 * This exception is thrown in places where the designated position is invalid, 
 * such as constructing an address from a section not located at position 0, which is the default position for sections.
 * <p>
 * However, in most operations such as replace and append, the position of the replacement or appended section is ignored and so this exception does not apply.
 * <p>
 * IPv4 sections are position independent, so this exception does not apply to IPv4.
 * 
 * @author sfoley
 *
 */
public class AddressPositionException extends AddressValueException {

	private static final long serialVersionUID = 1L;
	
	static String getMessage(String key) {
		return AddressStringException.getMessage(key);
	}

	public AddressPositionException(int position) {
		super(position + ", " + errorMessage + " " + getMessage("ipaddress.error.invalid.position"));
	}
	
	public AddressPositionException(AddressItem item, int position) {
		super(item + ", " + position + ", " + errorMessage + " " + getMessage("ipaddress.error.invalid.position"));
	}
	
	public AddressPositionException(AddressItem item, int position, int otherPosition) {
		super(item + ", " + position + ", " + otherPosition + ", " + errorMessage + " " + getMessage("ipaddress.error.invalid.position"));
	}
}
