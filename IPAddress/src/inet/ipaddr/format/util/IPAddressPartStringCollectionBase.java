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

import inet.ipaddr.format.string.IPAddressStringDivisionSeries;

/**
 * 
 * @author sfoley
 *
 * @param <T> the type of the address part from which this collection was derived
 * @param <P> the type of the params used to generate each string
 * @param <S> the type of the configurable strings, each of which pairs an IPAddressPart and a {@link IPAddressStringWriter} to produce a string.
 */
abstract class IPAddressPartStringCollectionBase<
		T extends IPAddressStringDivisionSeries,
		P extends IPAddressStringWriter<?>,
		S extends IPAddressPartConfiguredString<?, ?>> implements Iterable<S> { 
	
	protected abstract int size();
	
	public String[] toStrings() {
		String strings[] = new String[size()];
		int i = 0;
		for(IPAddressPartConfiguredString<?, ?> createdString : this) {
			strings[i++] = createdString.getString();
		}
		return strings;
	}
}
