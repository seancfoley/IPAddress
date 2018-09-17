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

package inet.ipaddr.format.string;

import inet.ipaddr.format.util.AddressSegmentParams;

public interface IPAddressStringDivision extends AddressStringDivision {

	int getBitCount();

	Integer getDivisionPrefixLength();

	/**
	 * Returns whether the division range includes all possible values
	 */
	boolean isFullRange();

	/**
	 * Returns whether the division range includes the block of values for its prefix length
	 */
	boolean isPrefixBlock();

	/**
	 * Returns whether the division range matches the block of values for its prefix length
	 */
	boolean isSinglePrefixBlock();

	/**
	 * Produces a string to represent the segment of the form a-b where the value b has been adjusted for the prefix, anything beyond the prefix length being zero.
	 * 
	 * @return if the supplied appendable is null, returns the length of the string that would have been appended, otherwise returns 0
	 */
	int getPrefixAdjustedRangeString(int segmentIndex, AddressSegmentParams params, StringBuilder appendable);
}
