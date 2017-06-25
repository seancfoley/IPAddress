package inet.ipaddr.format;

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

public class IPAddressBitsDivision extends IPAddressDivision {

	private static final long serialVersionUID = 3L;

	private final int bitCount, defaultRadix, maxDigitCount;
	private final long value, upperValue;
	private final long bitsMask;
	
	public IPAddressBitsDivision(long value, long upperValue, int bitCount, int defaultRadix) {
		this(value, upperValue, bitCount, defaultRadix, null);
	}

	public IPAddressBitsDivision(long value, long upperValue, int bitCount, int defaultRadix, Integer networkPrefixLength) {
		super(networkPrefixLength);
		this.bitCount = bitCount;
		this.value = value;
		this.upperValue = upperValue;
		this.defaultRadix = defaultRadix;
		bitsMask = ~(~0L << bitCount);
		this.maxDigitCount = getMaxDigitCount(defaultRadix, bitCount, bitsMask);
	}

	@Override
	public int getBitCount() {
		return bitCount;
	}

	@Override
	protected long getDivisionNetworkMask(int bits) {
		int bitShift = bitCount - bits;
		return bitsMask & (~0L << bitShift);
	}

	@Override
	protected long getDivisionHostMask(int bits) {
		int bitShift = bitCount - bits;
		return ~(~0L << bitShift);
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
	protected boolean isSameValues(AddressDivision other) {
		if(other instanceof IPAddressBitsDivision) {
			return isSameValues((IPAddressBitsDivision) other);
		}
		return false;
	}
	
	protected boolean isSameValues(IPAddressBitsDivision otherSegment) {
		//note that it is the range of values that matters, the prefix bits do not
		return  value == otherSegment.value && upperValue == otherSegment.upperValue && bitCount == otherSegment.bitCount;
	}

	@Override
	public int getDefaultTextualRadix() {
		return defaultRadix;
	}

	@Override
	public int getMaxDigitCount() {
		return maxDigitCount;
	}

}
