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

import inet.ipaddr.IPAddressNetwork;

public class IPAddressStringDivisionGrouping extends AddressStringDivisionGrouping implements IPAddressStringDivisionSeries {

	private static final long serialVersionUID = 4L;

	private IPAddressNetwork<?, ?, ?, ?, ?> network;
	private final Integer prefixLength;
	
	public IPAddressStringDivisionGrouping(IPAddressStringDivision divisions[], IPAddressNetwork<?, ?, ?, ?, ?> network, Integer prefixLength) {
		super(divisions);
		this.prefixLength = prefixLength;
		this.network = network;
	}
	
	@Override
	public IPAddressNetwork<?, ?, ?, ?, ?> getNetwork() {
		return network;
	}
	
	@Override
	public IPAddressStringDivision getDivision(int index) {
		return (IPAddressStringDivision) divisions[index];
	}

	@Override
	public boolean isPrefixed() {
		return prefixLength != null;
	}

	@Override
	public Integer getPrefixLength() {
		return prefixLength;
	}
	
	@Override
	public boolean isPrefixBlock() {
		Integer networkPrefixLength = getPrefixLength();
		if(networkPrefixLength == null) {
			return false;
		}
		if(network.getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
			return true;
		}
		int divCount = getDivisionCount();
		for(int i = 0; i < divCount; i++) {
			IPAddressStringDivision div = getDivision(i);
			Integer segmentPrefixLength = div.getDivisionPrefixLength();
			if(segmentPrefixLength != null) {
				if(!div.isPrefixBlock(segmentPrefixLength)) {
					return false;
				}
				for(++i; i < divCount; i++) {
					div = getDivision(i);
					if(!div.isFullRange()) {
						return false;
					}
				}
			}
		}
		return true;
	}
}
