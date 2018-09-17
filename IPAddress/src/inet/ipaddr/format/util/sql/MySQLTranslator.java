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

/**
 * 
 * @author sfoley
 *
 */
public class MySQLTranslator implements IPAddressSQLTranslator {

	@Override
	public void setNetwork(String networkString) {}
	
	@Override
	public StringBuilder matchString(StringBuilder builder, String expression, String match) {
		return builder.append(expression).append(" = '").append(match).append("'");
	}

	@Override
	public StringBuilder matchSubString(StringBuilder builder, String expression,
			char separator, int separatorCount, String match) {
		return builder.append("substring_index(").append(expression).
			append(",'").append(separator).append("',").append(separatorCount).append(") = ").
			append('\'').append(match).append('\'');
	}

	@Override
	public StringBuilder matchSeparatorCount(StringBuilder builder,
			String expression, char separator, int separatorCount) {
		return compareSeparatorCount(builder, expression, separator, "=", separatorCount);
	}

	@Override
	public StringBuilder boundSeparatorCount(StringBuilder builder,
			String expression, char separator, int separatorCount) {
		return compareSeparatorCount(builder, expression, separator, "<=", separatorCount);
	}
	
	private StringBuilder compareSeparatorCount(StringBuilder builder, String expression, char separator, String operator, int separatorCount) {
		return builder.append("LENGTH (").append(expression).
			append(") - LENGTH(REPLACE(").append(expression).append(", '").
			append(separator).append("', '')) ").append(operator).append(" ").append(separatorCount);
	}
}