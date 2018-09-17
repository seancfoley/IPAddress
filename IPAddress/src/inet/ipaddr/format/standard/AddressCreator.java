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

import inet.ipaddr.Address;
import inet.ipaddr.AddressNetwork;
import inet.ipaddr.AddressNetwork.AddressSegmentCreator;
import inet.ipaddr.AddressSection;
import inet.ipaddr.AddressSegment;
import inet.ipaddr.format.validate.ParsedAddressCreator;

/**
 * Has methods for creating addresses, segments and sections that are available to the parser.
 * 
 * @author sfoley
 *
 * @param <T> the address type
 * @param <R> the section type
 * @param <E> the embedded section type (ie IPv4 in a mixed IPv6/IPv4)
 * @param <S> the segment type
 */
public abstract class AddressCreator<T extends Address, R extends AddressSection, E extends AddressSection, S extends AddressSegment> extends ParsedAddressCreator<T, R, E, S>  implements AddressSegmentCreator<S> {

	private static final long serialVersionUID = 4L;

	public abstract AddressNetwork<S> getNetwork();
	
	protected abstract T createAddressInternal(S segments[]);

	protected abstract T createAddressInternal(S segments[], Integer prefix);
	
	protected abstract T createAddressInternal(S segments[], Integer prefix, boolean singleOnly);
	
	protected abstract R createSectionInternal(byte bytes[], int segmentCount, Integer prefix, boolean singleOnly);
	
	@Override
	protected abstract R createSectionInternal(S segments[]);
	
	protected abstract R createPrefixedSectionInternal(S segments[], Integer prefix, boolean singleOnly);
	
	protected abstract R createSectionInternal(S segments[], int startIndex, boolean extended);
	
	public abstract T createAddress(R section);
}
