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

import java.math.BigInteger;

import inet.ipaddr.format.AddressItem;

/**
 * Thrown when an address or address component would be too large or small,
 * when a prefix length is too large or small, or when prefixes across segments are inconsistent.
 * <p>
 * These exceptions are thrown when constructing new address components.  
 * They are not thrown when parsing strings to construct new address components, in which case {@link AddressStringException} is used instead.
 * 
 * @author sfoley
 *
 */
public class AddressValueException extends RuntimeException {

	private static final long serialVersionUID = 1L;
	
	static String errorMessage = getMessage("ipaddress.address.error");
	
	static String getMessage(String key) {
		return AddressStringException.getMessage(key);
	}
	
	public AddressValueException(long value) {
		super(value + ", " + errorMessage + " " + getMessage("ipaddress.error.exceeds.size"));
	}
	
	public AddressValueException(String key, long value) {
		super(value + ", " + errorMessage + " " + getMessage(key));
	}
	
	public AddressValueException(BigInteger value) {
		super(value + ", " + errorMessage + " " + getMessage("ipaddress.error.exceeds.size"));
	}
	
	public AddressValueException(AddressItem one, AddressItem two, int count) {
		super(count + ", " + one + ", " + two + ", " + errorMessage + " " + getMessage("ipaddress.error.exceeds.size"));
	}
	
	public AddressValueException(AddressItem one, AddressItem two) {
		super(one + ", " + two + ", " + errorMessage + " " + getMessage("ipaddress.error.exceeds.size"));
	}
	
	public AddressValueException(AddressItem one, String key) {
		super(one + ", "  + errorMessage + " " + getMessage(key));
	}
	
	AddressValueException(String message) {
        super(message);
    }

    AddressValueException(String message, Throwable cause) {
        super(message, cause);
    }
}
