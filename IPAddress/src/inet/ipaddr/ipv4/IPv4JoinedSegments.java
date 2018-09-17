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

package inet.ipaddr.ipv4;

import inet.ipaddr.AddressValueException;
import inet.ipaddr.PrefixLenException;
import inet.ipaddr.format.AddressDivisionBase;
import inet.ipaddr.format.standard.IPAddressJoinedSegments;

/**
 * 
 * @author sfoley
 *
 */
public class IPv4JoinedSegments extends IPAddressJoinedSegments {
	
	private static final long serialVersionUID = 4L;
	private static int MAX_CHARS[] = new int[IPv4Address.SEGMENT_COUNT - 1];
	
	public IPv4JoinedSegments(int joinedCount, int value) {
		super(joinedCount, value);
		if(joinedCount >= IPv4Address.SEGMENT_COUNT) {
			throw new AddressValueException(joinedCount);
		}
	}

	public IPv4JoinedSegments(int joinedCount, long value, Integer segmentPrefixLength) {
		super(joinedCount, value, segmentPrefixLength);
		if(joinedCount >= IPv4Address.SEGMENT_COUNT) {
			throw new AddressValueException(joinedCount);
		} else if(segmentPrefixLength != null && segmentPrefixLength > IPv4Address.BIT_COUNT) {
			throw new PrefixLenException(segmentPrefixLength);
		} else {
			checkMax(value);
		} 
	}

	public IPv4JoinedSegments(int joinedCount, long lower, long upper, Integer segmentPrefixLength) {
		super(joinedCount, lower, upper, segmentPrefixLength);
		if(joinedCount >= IPv4Address.SEGMENT_COUNT) {
			throw new AddressValueException(joinedCount);
		} else if(segmentPrefixLength != null && segmentPrefixLength > IPv4Address.BIT_COUNT) {
			throw new PrefixLenException(segmentPrefixLength);
		}  else {
			checkMax(getUpperDivisionValue());
		}
	}
	
	private void checkMax(long val) {
		long max = 0;
		switch(joinedCount) {
		case 0:
			max = 255;
			break;
		case 1:
			max = 65535;
			break;
		case 2:
			max = 16777215;
			break;
		case 3:
			max = 4294967295L;
			break;
		}
		if(value > max) {
			throw new AddressValueException(value);
		}
	}

	@Override
	public int getMaxDigitCount() {
		int result = MAX_CHARS[joinedCount - 1];
		if(result == 0) {
			result = MAX_CHARS[joinedCount - 1] = super.getMaxDigitCount();
		}
		return result;
	}

	@Override
	protected long getDivisionNetworkMask(int bits) {
		int totalBits = IPv4Address.BITS_PER_SEGMENT * (joinedCount + 1);
		long fullMask = ~(~0L << totalBits); //totalBits must be 6 digits at most for this shift to work per the java spec (so it must be less than 2^6 = 64)
		long networkMask = fullMask & (fullMask << (totalBits - bits));
		return networkMask;
	}

	@Override
	protected long getDivisionHostMask(int bits) {
		int totalBits = IPv4Address.BITS_PER_SEGMENT * (joinedCount + 1);
		long hostMask = ~(~0L << (totalBits - bits));
		return hostMask;
	}

	@Override
	protected int getBitsPerSegment() {
		return IPv4Address.BITS_PER_SEGMENT;
	}

	@Override
	public int getDefaultTextualRadix() {
		return IPv4Address.DEFAULT_TEXTUAL_RADIX;
	}

	@Override
	public boolean equals(Object o) {
		if(this == o) {
			return true;
		}
		if(o instanceof IPv4JoinedSegments) {
			// keep in mind, we do not allow this class to represent a single segment, so no need to worry about matching IPv4AddressSegment
			IPv4JoinedSegments other = (IPv4JoinedSegments) o;
			return joinedCount == other.joinedCount && other.isSameValues(this);
		}
		return false;
	}

	@Override
	protected boolean isSameValues(AddressDivisionBase other) {
		// keep in mind, we do not allow this class to represent a single segment, so no need to worry about matching IPv4AddressSegment
		return other instanceof IPv4JoinedSegments && super.isSameValues(other);
	}
}
