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

import inet.ipaddr.format.standard.AddressDivisionGrouping.StringOptions.Wildcards;

/**
 * Each segment params has settings to write exactly one type of IP address part string segment.
 */
public interface AddressSegmentParams {
	
	Wildcards getWildcards();
	
	boolean preferWildcards();
	
	/**
	 * returns -1 for as many leading zeros as needed to write the max number of characters per segment, 
	 * or 0, 1, 2, 3 to indicate the number of leading zeros
	 */
	int getLeadingZeros(int segmentIndex);
	
	String getSegmentStrPrefix();
	
	int getRadix();
	
	boolean isUppercase();
	
	boolean isSplitDigits();
	
	Character getSplitDigitSeparator();
	
	boolean isReverseSplitDigits();
	
}