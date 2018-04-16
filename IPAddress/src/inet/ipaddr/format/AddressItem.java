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

import java.io.Serializable;
import java.math.BigInteger;

/**
 * Represents any part of an address, whether divided into the standard arrangement of AddressComponent objects, or whether an alternative arrangement using AddressDivision objects.
 * <p>
 * The basic difference between the AddressComponent hierarchy and the AddressDivision hierarchy is that <br>
 * AddressComponent hierarchy uses<br>
 * <ul><li>standardized/typical arrangement (ie for ipv4, 4 equal segments of 1 byte each, for ipv6, 8 equal segments of 2 bytes each, for mac, 6 or 8 equal segments of 1 byte each)</li>
 * <li>equal size segments</li>
 * <li>segments divided along byte boundaries</li></ul>
 * <p>
 * AddressDivision allows alternative arrangements, such as inet_aton style of presenting ipv4 in fewer divisions, 
 * or base 85 for ipv6 which does not even use a base that is a power of 2 (and hence so subdivisions possibly using bit boundaries), 
 * or the aaa-bbb-ccc-ddd mac format with which segments are not divided along byte boundaries
 * <p>
 * Parsing creates objects in the AddressComponent hierarchy, which can then be used to create alternative arrangements using {@link AddressDivisionGrouping} or {@link AddressStringDivisionSeries}
 * <p>
 * @author sfoley
 *
 */
public interface AddressItem extends Serializable {

	/**
	 * The count of possible distinct values for this AddressComponent.  If not multiple, this is 1.
	 * 
	 * For instance, if this is the ip address series subnet 0::/64, then the count is 2 to the power of 64.
	 * 
	 * If this is a the segment 3-7, then the count is 5.
	 * 
	 * @return
	 */
	BigInteger getCount();

	/**
	 * @return the number of bits comprising this address item
	 */
	int getBitCount();
	
	/**
	 * Whether this represents multiple potential values (eg a prefixed address or a segment representing a range of values)
	 */
	boolean isMultiple();
	
	/**
	 * 
	 * @return the bytes of the smallest address item represented by this address item
	 */
	byte[] getBytes();
	
	/**
	 * Copies the bytes of the smallest address item represented by this address item into the supplied array,
	 * and returns that array.
	 * 
	 * If the supplied array is null or of insufficient size, a new array is created and returned.
	 * 
	 * @return the bytes of the smallest address represented by this address item.
	 */
	byte[] getBytes(byte bytes[]);
	
	/**
	 * Copies the bytes of the smallest address item represented by this address item into the supplied array starting at the given index,
	 * and returns that array.
	 * 
	 * If the supplied array is null or of insufficient size, a new array is created and returned, with the rest of the array contents the same as the original.
	 * 
	 * @return the bytes of the smallest address represented by this address item.
	 */
	byte[] getBytes(byte bytes[], int index);
	
	/**
	 * 
	 * @return the bytes of the largest address item represented by this address item
	 */
	byte[] getUpperBytes();
	
	/**
	 * Copies the bytes of the largest address item represented by this address item into the supplied array,
	 * and returns that array.
	 * 
	 * If the supplied array is null or of insufficient size, a new array is created and returned, with the rest of the array contents the same as the original.
	 * 
	 * @return the bytes of the largest address represented by this address item.
	 */
	byte[] getUpperBytes(byte bytes[]);
	
	/**
	 * Copies the bytes of the largest address item represented by this address item into the supplied array at the given index,
	 * and returns that array.
	 * 
	 * If the supplied array is null or of insufficient size, a new array is created and returned.
	 * 
	 * @return the bytes of the largest address represented by this address item.
	 */
	byte[] getUpperBytes(byte bytes[], int index);
	
	/**
	 * @return whether this item matches the value of zero
	 */
	boolean isZero();
	
	/**
	 * @return whether this item includes the value of zero within its range
	 */
	boolean includesZero();
	
	/**
	 * @return whether this item matches the maximum possible value
	 */
	boolean isMax();
	
	/**
	 * @return whether this item includes the maximum possible value within its range
	 */
	boolean includesMax();
	
	/**
	 * @return whether this address item represents all possible values attainable by an address item of this type,
	 * or in other words, both includesZero() and includesMax() return true
	 */
	boolean isFullRange();
}
