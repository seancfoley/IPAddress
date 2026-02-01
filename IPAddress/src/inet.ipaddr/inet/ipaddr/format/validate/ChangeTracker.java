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
package inet.ipaddr.format.validate;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.ConcurrentModificationException;

/**
 * ChangeTracker is a helper class for collections that have iterators, spliterators and streams, 
 * tracking whether changes take places on a collection while iterating, spliterating, or streaming through the collection.
 * 
 * @author scfoley
 *
 */
public class ChangeTracker implements Serializable {

	private static final long serialVersionUID = 1L;

	/**
	 * Change represents a change that has taken place on the collection being tracked.
	 * 
	 * @author scfoley
	 *
	 */
	public static class Change implements Cloneable, Serializable {

		private static final long serialVersionUID = 1L;

		boolean shared;

		private BigInteger big = BigInteger.ZERO;
		private int small;

		public void increment() {
			if(++small == 0) {
				big = big.add(BigInteger.ONE);
			}
		}

		@Override
		public boolean equals(Object o) {
			return o instanceof Change && equalsChange((Change) o);
		}

		public boolean equalsChange(Change change) {
			return small == change.small && big.equals(change.big);
		}

		@Override
		public Change clone() {
			try {
				return (Change) super.clone();
			} catch (CloneNotSupportedException cannotHappen) {
				return null;
			}
		}

		@Override
		public String toString() {
			return big + " " + small;
		}
	}

	private Change currentChange = new Change();

	/**
	 * Throws ConcurrentModificationException if a change has taken place, indicated by a call to {@link #changed()}, since the given change.
	 * 
	 * @param change
	 * @throws ConcurrentModificationException
	 */
	public void changedSince(Change change) throws ConcurrentModificationException {
		if(isChangedSince(change)) {
			throw new ConcurrentModificationException();
		}
	}

	/**
	 * Returns whether a change has taken place, indicated by a call to {@link #changed()}, since the given change.
	 * @param otherChange
	 * @return
	 */
	public boolean isChangedSince(Change otherChange) {
		return !currentChange.equalsChange(otherChange);
	}

	/**
	 * Returns the current change, indicating the changes are being tracked.
	 * 
	 * @return
	 */
	public Change getCurrent() {
		Change change = this.currentChange;
		change.shared = true;
		return change;
	}

	/**
	 * Indicates that a change has taken place.
	 */
	public void changed() {
		Change change = this.currentChange;
		if(change.shared) {
			change = change.clone();
			change.shared = false;
			change.increment();
			this.currentChange = change;
		} // else nobody is watching the current change, so no need to do anything
	}

	@Override
	public String toString() {
		return "current change: " + currentChange;
	}
}
