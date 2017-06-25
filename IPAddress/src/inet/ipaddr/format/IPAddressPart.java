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

package inet.ipaddr.format;

import java.io.Serializable;

/**
 * A generic part of an IP address.  It is divided into a series of combinations of individual address divisions ({@link IPAddressDivision}),
 * each of those being a combination of one or more IP address segments.
 * The number of such series is the division count.
 * 
 * @author sfoley
 *
 */
public interface IPAddressPart extends Serializable {
	
	IPAddressDivision getDivision(int index);
	
	int getDivisionCount();
	
	int getByteCount();
	
	/**
	 * Returns the network prefix, which is 16 for an address like 1.2.0.0/16
	 * If there is no prefix length, returns null.
	 * @return the prefix length
	 */
	Integer getNetworkPrefixLength();
	
	/**
	 * whether this is a pat of more than one address.  In other words, it is the same part of many potential addresses.
	 */
	boolean isMultiple();
	
	default int getPrefixStringLength() {//TODO xxx move to seg grouping class xxx
		Integer networkPrefixLength = getNetworkPrefixLength();
		if(networkPrefixLength != null) {
			return IPAddressDivision.toUnsignedStringLength(networkPrefixLength, 10) + 1;
		}
		return 0;
	}
}


