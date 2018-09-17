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

import java.util.ArrayList;
import java.util.Iterator;

import inet.ipaddr.format.string.IPAddressStringDivisionSeries;

public abstract class IPAddressPartStringSubCollection<
		T extends IPAddressStringDivisionSeries,
		P extends IPAddressStringWriter<T>,
		S extends IPAddressPartConfiguredString<T, P>> extends IPAddressPartStringCollectionBase<T, P, S> {
	public final T part;
	protected ArrayList<P> params = new ArrayList<P>();
	
	protected IPAddressPartStringSubCollection(T part) {
		this.part = part;
	}
	
	void add(P stringParams) {
		params.add(stringParams);
	}
	
	public P[] getParams(P array[]) {
		return params.toArray(array);
	}
	
	public int getParamCount() {
		return params.size();
	}

	@Override
	public int size() {
		return params.size();
	}
	
	protected abstract class IPAddressConfigurableStringIterator implements Iterator<S> {
		protected Iterator<P> iterator = params.iterator();
		
		@Override
		public boolean hasNext() {
			return iterator.hasNext();
		}

		@Override
		public void remove() {
			iterator.remove();
		}
	}
}