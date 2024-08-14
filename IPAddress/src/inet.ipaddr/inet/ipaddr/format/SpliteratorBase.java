/*
 * Copyright 2019 Sean C Foley
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
import java.util.NoSuchElementException;
import java.util.function.Consumer;

import inet.ipaddr.format.util.AddressComponentRangeSpliterator;

/**
 * SpliteratorBase provides the iterating functionality for the spliterators in this library.
 * <p>
 * 
 * @author seancfoley
 *
 */
abstract class SpliteratorBase<S extends AddressComponentRange, T> implements AddressComponentRangeSpliterator<S, T> {

	protected long iteratedCountL;
	protected boolean inForEach;
	
	boolean tryAdvance(Iterator<T> iterator, Consumer<? super T> action) {
		T next;
		try {
			next = iterator.next();
			iteratedCountL++;
		} catch(NoSuchElementException e) {
			// note: should never reach here thanks to bounds checking
			return false;
		}
		action.accept(next);
		return true;
	}

	void forEachRemaining(Iterator<T> iterator, Consumer<? super T> action, long bound) {
		while(iteratedCountL < bound) {
			T next;
			try {
				next = iterator.next();
				iteratedCountL++;
			} catch(NoSuchElementException e) {
				// note: should never reach here thanks to bounds checking
				return;
			}
			action.accept(next);
		}
		
    }

	@Override
	public int characteristics() {
		return CONCURRENT | NONNULL | SORTED | ORDERED | DISTINCT | SIZED | SUBSIZED;
	}

	@Override
	public String toString() {
		return "spliterator for " + getAddressItem();
	}
}
