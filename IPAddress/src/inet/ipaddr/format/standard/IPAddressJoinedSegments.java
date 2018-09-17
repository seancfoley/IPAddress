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

package inet.ipaddr.format.standard;

import inet.ipaddr.AddressValueException;
import inet.ipaddr.format.AddressDivisionBase;

/**
 * A combination of two or more IP address segments.
 * 
 * @author sfoley
 *
 */
public abstract class IPAddressJoinedSegments extends IPAddressDivision {
	
	private static final long serialVersionUID = 4L;

	protected final int joinedCount;
	protected final long value; //the lower value
	protected final long upperValue; //the upper value of a CIDR or other type of range, if not a range it is the same as value
	
	public IPAddressJoinedSegments(int joinedCount, int value) {
		if(value < 0) {
			throw new AddressValueException(value);
		} else if(joinedCount <= 0) {
			throw new AddressValueException(joinedCount);
		}
		this.value = this.upperValue = value;
		this.joinedCount = joinedCount;
	}

	public IPAddressJoinedSegments(int joinedCount, long value, Integer segmentPrefixLength) {
		this(joinedCount, value, value, segmentPrefixLength);
	}

	public IPAddressJoinedSegments(int joinedCount, long lower, long upper, Integer segmentPrefixLength) {
		super(segmentPrefixLength);
		if(lower < 0 || upper < 0) {
			throw new AddressValueException(lower < 0 ? lower : upper);
		} else if(joinedCount <= 0) {
			throw new AddressValueException(joinedCount);
		}
		if(lower > upper) {
			long tmp = lower;
			lower = upper;
			upper = tmp;
		}
		this.value = lower;
		this.upperValue = upper;
		this.joinedCount = joinedCount;
	}
	
	public int getJoinedCount() {
		return joinedCount;
	}

	@Override
	public long getDivisionValue() {
		return value;
	}

	@Override
	public long getUpperDivisionValue() {
		return upperValue;
	}
	
	protected abstract int getBitsPerSegment();

	@Override
	public int getBitCount() {
		return (joinedCount + 1) * getBitsPerSegment();
	}

	@Override
	public int getMaxDigitCount() {
		return getDigitCount(getMaxValue(), getDefaultTextualRadix());
	}

	@Override
	protected boolean isSameValues(AddressDivisionBase other) {
		if(other instanceof IPAddressJoinedSegments) {
			return isSameValues((IPAddressJoinedSegments) other);
		}
		return false;
	}
	
	protected boolean isSameValues(IPAddressJoinedSegments otherSegment) {
		//note that it is the range of values that matters, the prefix bits do not
		return  value == otherSegment.value && upperValue == otherSegment.upperValue;
	}

	@Override
	public boolean equals(Object other) {
		if(other == this) {
			return true;
		}
		if(other instanceof IPAddressJoinedSegments) {
			IPAddressJoinedSegments otherSegments = (IPAddressJoinedSegments) other;
			return getBitCount() == otherSegments.getBitCount() && otherSegments.isSameValues(this);
		}
		return false;
	}
	
	@Override
	public int hashCode() {
		return (int) (value | (upperValue << getBitCount()));
	}
}
