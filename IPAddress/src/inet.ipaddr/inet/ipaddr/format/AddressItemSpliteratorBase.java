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

import java.math.BigInteger;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.function.Consumer;

/**
 * AddressItemSpliteratorBase provides the iterating functionality for the spliterators in this library.
 * <p>
 * 
 * @author seancfoley
 *
 * @param <T>
 */
abstract class AddressItemSpliteratorBase<S extends AddressComponentRange, T> extends SpliteratorBase<S, T> {
	
	private static final BigInteger INT_MAX = BigInteger.valueOf(Integer.MAX_VALUE);

	// whether an iterator is big does not change once iteration has started.
	protected boolean isBig;

	// used by big iterators
	protected BigInteger iteratedCountB = BigInteger.ZERO;
	protected long iteratedCountI; // only used transiently during a forEachRemaining call

	@Override
	boolean tryAdvance(Iterator<T> iterator, Consumer<? super T> action) {
		if(isBig) {
			T next;
			try {
				next = iterator.next();
				iteratedCountB = iteratedCountB.add(BigInteger.ONE);
			} catch(NoSuchElementException e) {
				return false;
			}
			action.accept(next);
			return true;
		}
		return super.tryAdvance(iterator, action);
	}
	
	void forEachRemaining(Iterator<T> iterator, Consumer<? super T> action, BigInteger bound) {
		T next;
		boolean noIntBound;
		int intBound;
		if(iteratedCountB.signum() > 0) {
			bound = bound.subtract(iteratedCountB);
		}
		if(bound.compareTo(INT_MAX) >= 0) {
			noIntBound = true;
			intBound = 0;
		} else {
			noIntBound = false;
			intBound = bound.intValue();
		}
		try {
			while(noIntBound || iteratedCountI < intBound) {
				try {
					next = iterator.next();
					if(++iteratedCountI == Integer.MAX_VALUE) {
						iteratedCountI = 0;
						iteratedCountB = iteratedCountB.add(INT_MAX);
						bound = bound.subtract(INT_MAX);
						if(bound.compareTo(INT_MAX) < 0) {
							noIntBound = false;
							intBound = bound.intValue();
						}
					}
				} catch(NoSuchElementException e) {
					// note: should never reach here thanks to bounds checking
					break;
				}
				action.accept(next);
			}
		} finally {
			if(iteratedCountI != 0) {
				iteratedCountB = iteratedCountB.add(BigInteger.valueOf(iteratedCountI));
				iteratedCountI = 0;
			}
		}
    }
}
