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

package inet.ipaddr.format;

import java.util.Iterator;

import inet.ipaddr.format.AddressItem;


public interface AddressItemRange extends AddressItem {
	/**
	 * If this instance represents multiple address items, returns the one with the lowest numeric value.
	 * 
	 * @return
	 */
	AddressItem getLower();
	
	/**
	 * If this instance represents multiple address items, returns the one with the highest numeric value.
	 * 
	 * @return
	 */
	AddressItem getUpper();
	
	/**
	 * Useful for using an instance in a "for-each loop".  Otherwise just call {@link #iterator()} directly.
	 * @return
	 */
	Iterable<? extends AddressItem> getIterable();

	/**
	 * Iterates through the individual elements of this address item.
	 * <p>
	 * Call {@link #isMultiple()} to determine if this instance represents multiple, or {@link #getCount()} for the count.
	 * 
	 * @return
	 */
	Iterator<? extends AddressItem> iterator();
}
