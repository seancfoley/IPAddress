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

public class IPAddressStringDivisionGrouping extends AddressStringDivisionGrouping implements IPAddressStringDivisionSeries {

	private static final long serialVersionUID = 3L;

	private final Integer prefixLength;
	
	public IPAddressStringDivisionGrouping(AddressDivisionBase divisions[], Integer prefixLength) {
		super(divisions);
		this.prefixLength = prefixLength;
	}

	@Override
	public boolean isPrefixed() {
		return prefixLength != null;
	}

	@Override
	public Integer getPrefixLength() {
		return prefixLength;
	}
}
