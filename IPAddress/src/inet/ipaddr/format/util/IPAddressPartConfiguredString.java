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

package inet.ipaddr.format.util;

import inet.ipaddr.format.string.IPAddressStringDivisionSeries;
import inet.ipaddr.format.util.sql.IPAddressSQLTranslator;
import inet.ipaddr.format.util.sql.SQLStringMatcher;

/**
 * Pairs a part of an IP address along with an instance of a parameter class to define a specific string.
 * 
 * @author sfoley
 *
 * @param <T> the type of the address part from which this configurable string was derived
 * @param <P> the type of the params used to generate the string
 */
public class IPAddressPartConfiguredString<T extends IPAddressStringDivisionSeries, P extends IPAddressStringWriter<T>> {
	
	public final T addr;
	public final P stringParams;
	protected String string;
	
	public IPAddressPartConfiguredString(T addr, P stringParams) {
		this.stringParams = stringParams;
		this.addr = addr;
	}
	
	public int getTrailingSeparatorCount() {
		return stringParams.getTrailingSeparatorCount(addr);
	}
	
	public char getTrailingSegmentSeparator() {
		return stringParams.getTrailingSegmentSeparator();
	}
	
	/**
	 * Provides an object that can build SQL clauses to match this string representation.
	 * 
	 * This method can be overridden for other IP address types to match in their own ways.
	 * 
	 * @param isEntireAddress
	 * @param translator
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public <S extends IPAddressPartConfiguredString<T, P>> SQLStringMatcher<T, P, S> getNetworkStringMatcher(boolean isEntireAddress, IPAddressSQLTranslator translator) {
		return new SQLStringMatcher<T, P, S>((S) this, isEntireAddress, translator);
	}
	
	public String getString() {
		if(string == null) {
			string = stringParams.toString(addr);
		}
		return string;
	}
	
	@Override
	public String toString() {
		return getString();
	}
}