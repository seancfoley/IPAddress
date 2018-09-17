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

/**
 * 
 * @author sfoley
 *
 */
public class AddressStringException extends HostIdentifierException {

	private static final long serialVersionUID = 4L;
	
	private static final String errorMessage = getMessage("ipaddress.address.error");
	
	public AddressStringException(CharSequence str, String key, Throwable cause) {
		super(str, errorMessage, key, cause);
	}
	
	public AddressStringException(CharSequence str, String key) {
		super(str, errorMessage, key);
	}
	
	public AddressStringException(CharSequence str, String key, int characterIndex) {
		super(str.toString() + ' ' + errorMessage + ' ' + getMessage(key) + ' ' + characterIndex);
	}
	
	public AddressStringException(CharSequence str, int characterIndex) {
		this(str, characterIndex, false);
	}
	
	public AddressStringException(CharSequence str, int characterIndex, boolean combo) {
		super(str.toString() + ' ' + errorMessage + ' ' + 
				getMessage(combo ? "ipaddress.error.invalid.character.combination.at.index" : "ipaddress.error.invalid.character.at.index") + ' ' + characterIndex);
	}
	
	public AddressStringException(String key) {
		super(errorMessage, key);
	}
}
