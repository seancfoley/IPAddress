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

package inet.ipaddr.format.validate;

import inet.ipaddr.HostName;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressSection;
import inet.ipaddr.IPAddressSegment;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.ipv4.IPv4AddressSection;

/**
 * Has methods for creating addresses, segments and sections that are available only to the parser
 * 
 * @author sfoley
 *
 * @param <T>
 * @param <R>
 * @param <S>
 */
public abstract class ParsedAddressCreator<T extends IPAddress, R extends IPAddressSection, S extends IPAddressSegment> {
	
	public abstract S[] createSegmentArray(int length);

	public abstract S createSegment(int lower, int upper, Integer segmentPrefixLength);

	/* 
	 * These methods are for internal use only.  
	 * The originating IPAddressString or Host is cached inside the created address.
	 * Also, byte arrays are not cloned, they are used by the resulting address.
	 * Also, segment arrays are not cloned, they is used by the resulting address or address section.
	 */
	
	protected abstract S createSegmentInternal(int value, Integer segmentPrefixLength, String addressStr, int originalVal, boolean isStandardString, int lowerStringStartIndex, int lowerStringEndIndex);
	
	protected abstract S createSegmentInternal(int lower, int upper, Integer segmentPrefixLength, String addressStr, int originalLower, int originalUpper, boolean isStandardString, boolean isStandardRangeString, int lowerStringStartIndex, int lowerStringEndIndex, int upperStringEndIndex);


	protected abstract R createSectionInternal(byte bytes[], Integer prefix);
	
	protected abstract R createSectionInternal(S segments[]);
	
	protected abstract R createSectionInternal(S segments[], IPv4AddressSection mixedPart);
	
	
	protected abstract T createAddressInternal(R section, String zone, IPAddressString fromString, HostName fromHost);

	protected T createAddressInternal(byte bytes[], Integer prefix, String zone, HostName fromHost) {
		return createAddressInternal(createSectionInternal(bytes, prefix), zone, null, fromHost);
	}
	
	protected T createAddressInternal(S segments[], String zone, IPAddressString fromString, HostName fromHost) {
		return createAddressInternal(createSectionInternal(segments), zone, fromString, fromHost);
	}
}