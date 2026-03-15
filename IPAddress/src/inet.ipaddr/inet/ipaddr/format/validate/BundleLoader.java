/*
 * Copyright 2026 Sean C Foley
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
package inet.ipaddr.format.validate;

import java.util.MissingResourceException;
import java.util.ResourceBundle;

import inet.ipaddr.HostIdentifierException;

public class BundleLoader {

	static ResourceBundle bundle;

	public static ResourceBundle loadBundle() {
		if(bundle == null) {
			Class<?> clazz = HostIdentifierException.class;
			Package pack = clazz.getPackage();
			String packagePrefix;
			if(pack == null) {
				String className = clazz.getName();
				int lastDelimiterIndex = className.lastIndexOf('.');
				if(lastDelimiterIndex <= 0 || lastDelimiterIndex >= className.length() - 1) {
					packagePrefix = "inet.ipaddr.";
				} else {
					packagePrefix = className.substring(0, lastDelimiterIndex + 1);
				}
			} else {
				packagePrefix = pack.getName() + '.';
			}
			String propertyFileName = "IPAddressResources";
			String name = packagePrefix + propertyFileName;
			try {
				bundle = ResourceBundle.getBundle(name);
			} catch (MissingResourceException e) {
				System.err.println("bundle " + name + " is missing");
			}
		}
		return bundle;
	}
}
