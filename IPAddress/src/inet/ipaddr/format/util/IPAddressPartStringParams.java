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

package inet.ipaddr.format.util;

import inet.ipaddr.IPAddress;
import inet.ipaddr.format.IPAddressPart;

/**
 * Each AddressPartStringParams has settings to write exactly one IP address part string.
 * 
 * @author sfoley
 */
public abstract class IPAddressPartStringParams<T extends IPAddressPart> implements Cloneable {
	
	protected IPAddressPartStringParams() {}
	
	protected abstract StringBuilder append(StringBuilder builder, T addr);
	
	protected abstract int getStringLength(T addr);
	
	/**
	 * 
	 * @param addr
	 * @return the string produced by these params
	 */
	public abstract String toString(T addr);
	
	/**
	 * 
	 * @param addr
	 * @return the number of segment separators in the string produced by these params
	 */
	public abstract int getTrailingSeparatorCount(T addr);
	
	public abstract char getTrailingSegmentSeparator();

	@SuppressWarnings("unchecked")
	@Override
	public IPAddressPartStringParams<T> clone() {
		try {
			return (IPAddressPartStringParams<T>) super.clone();
		} catch(CloneNotSupportedException e) {}
		return null;
	}
	
	protected void appendPrefixIndicator(StringBuilder builder, T addr) {
		Integer networkPrefixLength = addr.getNetworkPrefixLength();
		if(networkPrefixLength != null ) {
			builder.append(IPAddress.PREFIX_LEN_SEPARATOR).append(networkPrefixLength);
		}
	}
	
	//TODO disable eventually
	public void checkLengths(int length, StringBuilder builder) {
		boolean calcMatch = length == builder.length();
		boolean capMatch = length == builder.capacity();
		totalCount++;
		if(calcMatch) {
			calcMatchCount++;
		}
		if(capMatch) {
			capMatchCount++;
		}
		if(!calcMatch) {
			System.out.println(builder);
		}
		if(!capMatch) {
			System.out.println(builder);
		}
		if(!calcMatch || !capMatch) {
			System.out.println(" calculated length misses: " + (totalCount - calcMatchCount) + " capacity misses: " +  (totalCount - capMatchCount) + " total: " + totalCount);
		}
	}
	
	static int calcMatchCount;
	static int capMatchCount;
	static int totalCount;
}
