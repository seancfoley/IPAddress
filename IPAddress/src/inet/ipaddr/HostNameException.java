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
public class HostNameException extends HostIdentifierException {

	private static final long serialVersionUID = 4L;
	
	private static String errorMessage = getMessage("ipaddress.host.error");
	
	public HostNameException(String host, int index) {
		super(host + " " + errorMessage + " " + getMessage("ipaddress.host.error.invalid.character.at.index") + ' ' + index);
	}
	
	public HostNameException(String host, int index, Throwable cause) {
		super(host + " " + errorMessage + " " + getMessage("ipaddress.host.error.invalid.character.at.index") + ' ' + index, cause);
	}
	
	public HostNameException(String host, String key) {
		super(host, errorMessage, key);
	}
	
	public HostNameException(String host, AddressStringException e, String key) {
		super(host, errorMessage, key, e);
	}
}
