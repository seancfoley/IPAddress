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

package inet.ipaddr.format.validate;

import java.io.Serializable;

import inet.ipaddr.Address;
import inet.ipaddr.AddressSection;
import inet.ipaddr.AddressSegment;
import inet.ipaddr.HostIdentifierString;

/**
 * Has methods for creating addresses, segments and sections that are available to the parser.
 * 
 * @author sfoley
 *
 * @param <T>
 * @param <R>
 * @param <E>
 * @param <S>
 */
public abstract class ParsedAddressCreator<T extends Address, R extends AddressSection, E extends AddressSection, S extends AddressSegment> implements Serializable {
	
	private static final long serialVersionUID = 4L;
	
	public void clearCaches() {
		for(int i = 0; i < Validator.MASK_CACHE.length; i++) {
			Validator.MASK_CACHE[i] = null;
		}
	}

	public abstract S[] createSegmentArray(int length);

	public abstract S createSegment(int lower, int upper, Integer segmentPrefixLength);

	/* 
	 * These methods (with "Internal" in the name) are for internal use only.  
	 * The originating IPAddressString or Host is cached inside the created address.
	 * Also, byte arrays are not cloned, they are used by the resulting address.
	 * Also, segment arrays are not cloned, they is used by the resulting address or address section.
	 */
	protected abstract S createSegmentInternal(int value, Integer segmentPrefixLength, CharSequence addressStr, int originalVal, boolean isStandardString, int lowerStringStartIndex, int lowerStringEndIndex);
	
	protected abstract S createSegmentInternal(int lower, int upper, Integer segmentPrefixLength, CharSequence addressStr, int originalLower, int originalUpper, boolean isStandardString, boolean isStandardRangeString, int lowerStringStartIndex, int lowerStringEndIndex, int upperStringEndIndex);

	protected abstract R createSectionInternal(S segments[]);
	
	protected abstract R createPrefixedSectionInternal(S segments[], Integer prefix);
	
	protected R createSectionInternal(S segments[], E embeddedSection) {
		return createSectionInternal(segments);
	}
	
	protected R createSectionInternal(S segments[], E embeddedSection, Integer prefix) {
		return createPrefixedSectionInternal(segments, prefix);
	}
	
	protected abstract T createAddressInternal(byte bytes[], CharSequence zone);
	
	protected abstract T createAddressInternal(R section, HostIdentifierString from);
	
	protected abstract T createAddressInternal(R section, CharSequence zone, HostIdentifierString from);
	
	protected T createAddressInternal(S segments[], HostIdentifierString from, Integer prefix) {
		return createAddressInternal(createPrefixedSectionInternal(segments, prefix), from);
	}
	
	protected T createAddressInternal(S segments[], CharSequence zone, HostIdentifierString from, Integer prefix) {
		return createAddressInternal(createPrefixedSectionInternal(segments, prefix), zone, from);
	}
}
