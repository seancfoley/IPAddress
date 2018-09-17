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

package inet.ipaddr.format.large;

import java.math.BigInteger;

import inet.ipaddr.IPAddressNetwork;
import inet.ipaddr.InconsistentPrefixException;
import inet.ipaddr.PrefixLenException;
import inet.ipaddr.format.AddressDivisionGroupingBase;
import inet.ipaddr.format.IPAddressDivisionSeries;

public class IPAddressLargeDivisionGrouping extends AddressDivisionGroupingBase implements IPAddressDivisionSeries {

	private static final long serialVersionUID = 1L;

	private IPAddressNetwork<?, ?, ?, ?, ?> network;
	
	public IPAddressLargeDivisionGrouping(IPAddressLargeDivision divisions[], IPAddressNetwork<?, ?, ?, ?, ?> network) {
		super(divisions);
		this.network = network;
		int totalPrefixBits = 0;
		for(int i = 0; i < divisions.length; i++) {
			IPAddressLargeDivision division = divisions[i];
			/**
			 * Across an address prefixes are:
			 * (null):...:(null):(1 to x):(0):...:(0)
			 */
			Integer divPrefix = division.getDivisionPrefixLength();
			if(divPrefix != null) {
				cachedPrefixLength = cacheBits(totalPrefixBits + divPrefix);
				for(++i; i < divisions.length; i++) {
					division = divisions[i];
					divPrefix = division.getDivisionPrefixLength();
					if(divPrefix == null || divPrefix != 0) {
						throw new InconsistentPrefixException(divisions[i - 1], division, divPrefix);
					}
				}
				return;
			}
			totalPrefixBits += division.getBitCount();
		}
		cachedPrefixLength = NO_PREFIX_LENGTH;
	}
	
	@Override
	public IPAddressNetwork<?, ?, ?, ?, ?> getNetwork() {
		return network;
	}

	@Override
	public IPAddressLargeDivision getDivision(int index) {
		return (IPAddressLargeDivision) super.getDivision(index);
	}

	@Override
	public boolean containsPrefixBlock(int prefixLength) {
		return containsPrefixBlock(this, prefixLength);
	}

	@Override
	public boolean containsSinglePrefixBlock(int prefixLength) throws PrefixLenException {
		return containsSinglePrefixBlock(this, prefixLength);
	}

	@Override
	public Integer getPrefixLengthForSingleBlock() {
		return getPrefixLengthForSingleBlock(this);
	}

	@Override
	public Integer getPrefixLength() {
		return getNetworkPrefixLength();
	}

	@Override
	public Integer getNetworkPrefixLength() {
		Integer ret = cachedPrefixLength;
		if(ret == null) {
			Integer result = calculatePrefix(this);
			if(result != null) {
				return cachedPrefixLength = result;
			}
			cachedPrefixLength = NO_PREFIX_LENGTH;
			return null;
		}
		if(ret.intValue() == NO_PREFIX_LENGTH.intValue()) {
			return null;
		}
		return ret;
	}

	@Override
	protected byte[] getBytesImpl(boolean low) {
		byte bytes[] = new byte[(getBitCount() + 7) >> 3];
		int byteCount = bytes.length;
		int divCount = getDivisionCount();
		for(int k = divCount - 1, byteIndex = byteCount - 1, bitIndex = 8; k >= 0; k--) {
			IPAddressLargeDivision div = getDivision(k);
			BigInteger divValue = low ? div.getValue() : div.getUpperValue();
			int divBits = div.getBitCount();
			//write out this entire segment
			while(divBits > 0) {
				BigInteger bits = divValue.shiftLeft(8 - bitIndex);
				bytes[byteIndex] |= bits.byteValue();
				divValue = divValue.shiftRight(bitIndex);
				if(divBits < bitIndex) {
					bitIndex -= divBits;
					break;
				} else {
					divBits -= bitIndex;
					bitIndex = 8;
					byteIndex--;
				}
			}
		}
		return bytes;
	}
	
	@Override
	protected boolean isSameGrouping(AddressDivisionGroupingBase other) {
		return other instanceof IPAddressLargeDivisionGrouping && super.isSameGrouping(other);
	}

	@Override
	public boolean equals(Object o) {
		if(o == this) {
			return true;
		}
		if(o instanceof IPAddressLargeDivisionGrouping) {
			IPAddressLargeDivisionGrouping other = (IPAddressLargeDivisionGrouping) o;
			// we call isSameGrouping on the other object to defer to subclasses
			return other.isSameGrouping(this);
		}
		return false;
	}
}
