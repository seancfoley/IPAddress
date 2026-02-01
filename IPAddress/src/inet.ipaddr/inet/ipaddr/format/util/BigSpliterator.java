/*
 * Copyright 2026 Sean C Foley
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

import java.math.BigInteger;
import java.util.Spliterator;

public interface BigSpliterator<T> extends Spliterator<T> {
	/**
	 * Returns an exact count of the number of elements that would be
     * encountered by a {@link #forEachRemaining} traversal.
	 * @return
	 */
	BigInteger getSize();
	
	
	@Override
	BigSpliterator<T> trySplit();
}
