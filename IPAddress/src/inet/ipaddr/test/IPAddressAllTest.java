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

package inet.ipaddr.test;

import inet.ipaddr.IPAddressString;
import inet.ipaddr.IPAddressStringParameters;

public class IPAddressAllTest extends IPAddressRangeTest {
	
	private static final IPAddressStringParameters DEFAULT_OPTIONS = new IPAddressStringParameters.Builder().toParams();
	
	IPAddressAllTest(AddressCreator creator) {
		super(creator);
	}
	
	@Override
	protected IPAddressString createInetAtonAddress(String x) {
		return createAddress(x);
	}
	
	@Override
	protected IPAddressString createAddress(String x) {
		return createAddress(x, DEFAULT_OPTIONS);
	}

	@Override
	boolean isLenient() {
		return true;
	}
	
	@Override
	void runTest() {
		super.runTest();
	}
}
