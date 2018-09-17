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

import java.util.MissingResourceException;
import java.util.ResourceBundle;

/**
 * 
 * @author sfoley
 *
 */
public class HostIdentifierException extends Exception {

	private static final long serialVersionUID = 4L;

	static ResourceBundle bundle;
	
	static {
		String propertyFileName = "IPAddressResources";
		String name = HostIdentifierException.class.getPackage().getName() + '.' + propertyFileName;
		try {
			bundle = ResourceBundle.getBundle(name);
		} catch (MissingResourceException e) {
			System.err.println("bundle " + name + " is missing");
		}
	}
	
	public HostIdentifierException(CharSequence str, String errorMessage, String key, Throwable cause) {
		super(str.toString() + ' ' + errorMessage + ' ' + getMessage(key), cause);
	}
	
	public HostIdentifierException(CharSequence str, String errorMessage, String key) {
		super(str.toString() + ' ' + errorMessage + ' ' + getMessage(key));
	}
	
	public HostIdentifierException(CharSequence message) {
		super(message.toString());
	}
	
	public HostIdentifierException(CharSequence message, Throwable cause) {
		super(message.toString(), cause);
	}
	
	public HostIdentifierException(CharSequence errorMessage, String key) {
		super(errorMessage.toString() + ' ' + getMessage(key));
	}

	static String getMessage(String key) {
		if(bundle != null) {
			try {
				return bundle.getString(key);
				
			} catch (MissingResourceException e1) {}
		}
		return key;
	}
}
