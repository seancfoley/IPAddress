package inet.ipaddr.format.standard;

import inet.ipaddr.AddressValueException;
import inet.ipaddr.IPAddressNetwork;
import inet.ipaddr.format.AddressDivisionBase;

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

public class IPAddressBitsDivision extends IPAddressDivision {

	private static final long serialVersionUID = 4L;

	private final int bitCount, defaultRadix, maxDigitCount;
	private final long value, upperValue;
	private final long bitsMask;
	
	public IPAddressBitsDivision(long value, long upperValue, int bitCount, int defaultRadix) {
		this(value, upperValue, bitCount, defaultRadix, null, null);
	}

	public IPAddressBitsDivision(long value, long upperValue, int bitCount, int defaultRadix, IPAddressNetwork<?, ?, ?, ?, ?> network, Integer networkPrefixLength) {
		super(networkPrefixLength == null ? null : Math.min(bitCount, networkPrefixLength));
		this.bitCount = bitCount;
		if(value < 0 || upperValue < 0) {
			throw new AddressValueException(value < 0 ? value : upperValue);
		}
		if(value > upperValue) {
			long tmp = value;
			value = upperValue;
			upperValue = tmp;
		}
		long fullMask = ~0L << bitCount; // 11110000  with bitCount zeros
		long max = ~fullMask;
		if(upperValue > max) {
			throw new AddressValueException(upperValue);
		}
		networkPrefixLength = getDivisionPrefixLength();
		if(networkPrefixLength != null && networkPrefixLength < bitCount && network.getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
			long mask = ~0 << (bitCount - networkPrefixLength);
			this.value = value & mask;
			this.upperValue = upperValue | ~mask;
		} else {
			this.value = value;
			this.upperValue = upperValue;
		}
		this.defaultRadix = defaultRadix;
		bitsMask = max;
		maxDigitCount = getMaxDigitCount(defaultRadix, bitCount, max);
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
	public long getDivisionValue() {
		return value;
	}

	@Override
	public long getUpperDivisionValue() {
		return upperValue;
	}

	@Override
	protected boolean isSameValues(AddressDivisionBase other) {
		if(other instanceof IPAddressBitsDivision) {
			return isSameValues((IPAddressBitsDivision) other);
		}
		return false;
	}
	
	protected boolean isSameValues(IPAddressBitsDivision otherSegment) {
		//note that it is the range of values that matters, the prefix bits do not
		return  value == otherSegment.value && upperValue == otherSegment.upperValue;
	}
	
	@Override
	public boolean equals(Object other) {
		if(other == this) {
			return true;
		}
		if(other instanceof IPAddressBitsDivision) {
			IPAddressBitsDivision otherSegments = (IPAddressBitsDivision) other;
			return getBitCount() == otherSegments.getBitCount() && otherSegments.isSameValues(this);
		}
		return false;
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
