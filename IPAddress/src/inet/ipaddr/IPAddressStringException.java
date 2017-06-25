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

/**
 * 
 * @author sfoley
 *
 */
public class IPAddressStringException extends HostIdentifierException {

	private static final long serialVersionUID = 1L;
	
	private static String errorMessage = getMessage("ipaddress.address.error");
	
	public IPAddressStringException(String str, String key, Throwable cause) {
		super(str, errorMessage, key, cause);
	}
	
	public IPAddressStringException(String str, String key) {
		super(str, errorMessage, key);
	}
	
	public IPAddressStringException(String str, int characterIndex, boolean combo) {
		super(str + ' ' + errorMessage + ' ' + 
				getMessage(combo ? "ipaddress.error.invalid.character.combination.at.index" : "ipaddress.error.invalid.character.at.index") + ' ' + characterIndex);
	}
	
	public IPAddressStringException(String key) {
		super(errorMessage, key);
	}
}
