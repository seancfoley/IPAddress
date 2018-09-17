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

public interface AddressStringDivision {
	
	/**
	 * Returns true if the possible values of this division fall below the given boundary value.
	 */
	boolean isBoundedBy(int value);

	/**
	 * Returns the count of digits of the value, or if a range, the larger value in the range
	 * 
	 * @param radix
	 * @return
	 */
	int getDigitCount(int radix);
	
	/**
	 * Returns the count of digits of the largest possible value
	 * 
	 * @param radix
	 * @return
	 */
	int getMaxDigitCount(int radix);
	
	/**
	 * Configures a segment string according to the given params and the given segment index.
	 * Appends the string to appendable.
	 * <p>
	 * If appendable is null, simply returns the length of the string that would have been appended.
	 * <p>
	 * Prefix length of this segment is not accounted for in this method when creating this string.
	 * 
	 * @param segmentIndex
	 * @param params
	 * @param appendable
	 * @return
	 */
	int getStandardString(int segmentIndex, AddressSegmentParams params, StringBuilder appendable);
	
	/**
	 * Configures a segment string according to the given params and the given segment index, but using only the lower value of the segment range,
	 * if there is a range.
	 * <p>
	 * If appendable is null, simply returns the length of the string that would have been appended.
	 * 
	 * @param segmentIndex
	 * @param params
	 * @param appendable
	 * @return
	 */
	int getLowerStandardString(int segmentIndex, AddressSegmentParams params, StringBuilder appendable);
}
