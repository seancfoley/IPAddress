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

package inet.ipaddr.format.util.sql;

import inet.ipaddr.format.string.IPAddressStringDivisionSeries;
import inet.ipaddr.format.util.IPAddressPartConfiguredString;
import inet.ipaddr.format.util.IPAddressStringWriter;

/**
 * This class is intended to match part of an address when it is written with a given string.
 * 
 * Note that a given address part can be written many ways.  
 * Also note that some of these representations can represent more than one address section.
 * 
 * @author sfoley
 *
 */
public class SQLStringMatcher<T extends IPAddressStringDivisionSeries, P extends IPAddressStringWriter<T>, S extends IPAddressPartConfiguredString<T, P>> {
	protected final S networkString;
	private final boolean isEntireAddress;
	private final IPAddressSQLTranslator translator;

	public SQLStringMatcher(S networkString, boolean isEntireAddress, IPAddressSQLTranslator translator) {
		this.networkString = networkString;
		this.translator = translator;
		this.isEntireAddress = isEntireAddress;
		translator.setNetwork(networkString.getString());
	}
	
	/**
	 * Get an SQL condition to match this address section representation
	 * 
	 * @param builder
	 * @param columnName
	 * @return the condition
	 */
	public StringBuilder getSQLCondition(StringBuilder builder, String columnName) {
		String string = networkString.getString();
		if(isEntireAddress) {
			matchString(builder, columnName, string);
		} else {
			matchSubString(
					builder,
					columnName,
					networkString.getTrailingSegmentSeparator(),
					networkString.getTrailingSeparatorCount() + 1,
					string);
		}
		return builder;
	}
	
	protected void matchString(StringBuilder builder, String expression, String match) {
		translator.matchString(builder, expression, match);
	}
	
	protected void matchSubString(StringBuilder builder, String expression, char separator, int separatorCount, String match) {
		translator.matchSubString(builder, expression, separator, separatorCount, match);
	}
	
	protected void matchSeparatorCount(StringBuilder builder, String expression, char separator, int separatorCount) {
		translator.matchSeparatorCount(builder, expression, separator, separatorCount);
	}
	
	protected void boundSeparatorCount(StringBuilder builder, String expression, char separator, int separatorCount) {
		translator.boundSeparatorCount(builder, expression, separator, separatorCount);
	}

	@Override
	public String toString() {
		return getSQLCondition(new StringBuilder(), "COLUMN").toString();
	}
}