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

import inet.ipaddr.AddressValueException;

/**
 * An address division for mac
 * 
 * @author sfoley
 *
 */
public class AddressBitsDivision extends AddressDivision {

	private static final long serialVersionUID = 4L;

	protected final int value; //the lower value
	protected final int upperValue; //the upper value of a range, if not a range it is the same as value
	private final int bitCount;
	private final int defaultRadix;
	
	public AddressBitsDivision(int value, int bitCount, int defaultRadix) {
		if(value < 0) {
			throw new AddressValueException(value);
		}
		this.value = this.upperValue = value;
		this.bitCount = bitCount;
		this.defaultRadix = defaultRadix;
	}

	public AddressBitsDivision(int lower, int upper, int bitCount, int defaultRadix) {
		if(lower < 0 || upper < 0) {
			throw new AddressValueException(lower < 0 ? lower : upper);
		}
		if(lower > upper) {
			int tmp = lower;
			lower = upper;
			upper = tmp;
		}
		this.value = lower;
		this.upperValue = upper;
		this.bitCount = bitCount;
		this.defaultRadix = defaultRadix;
	}

	@Override
	public long getLowerValue() {
		return value;
	}

	@Override
	public long getUpperValue() {
		return upperValue;
	}
	
	@Override
	protected byte[] getBytesImpl(boolean low) {
		return low ? new byte[] {
						(byte) (value >> 8),
						(byte) (0xff & value)} : 
					new byte[] {
						(byte) (upperValue >> 8),
						(byte) (0xff & upperValue)};
	}

	@Override
	public int getBitCount() {
		return bitCount;
	}

	@Override
	public int getMaxDigitCount() {
		return (getBitCount() + 3) >> 2;//every 4 bits is another digit
	}

	@Override
	protected boolean isSameValues(AddressDivision other) {
		if(other instanceof AddressBitsDivision) {
			return isSameValues((AddressBitsDivision) other);
		}
		return false;
	}
	
	protected boolean isSameValues(AddressBitsDivision otherSegment) {
		//note that it is the range of values that matters, the prefix bits do not
		return  value == otherSegment.value && upperValue == otherSegment.upperValue;
	}
	
	@Override
	public boolean equals(Object other) {
		if(other == this) {
			return true;
		}
		if(other instanceof AddressBitsDivision) {
			AddressBitsDivision otherSegments = (AddressBitsDivision) other;
			return isSameValues(otherSegments);
		}
		return false;
	}
	
	@Override
	public int hashCode() {
		return (int) (value | (upperValue << getBitCount()));
	}

	@Override
	public int getDefaultTextualRadix() {
		return defaultRadix;
	}
}
