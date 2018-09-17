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

import java.io.IOException;
import java.io.Serializable;

/**
 * A string that is used to identify a network host.
 * 
 * @author sfoley
 *
 */
public interface HostIdentifierString extends Serializable {
	
	static final char SEGMENT_VALUE_DELIMITER = ',';
	
	/**
	 * provides a normalized String representation for the host identified by this HostIdentifierString instance
	 *  
	 * @return the normalized string
	 */
	String toNormalizedString();
	
	void validate() throws HostIdentifierException;
	
	Address getAddress();
	
	Address toAddress() throws IOException, HostIdentifierException;
}
