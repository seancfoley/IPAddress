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

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

import inet.ipaddr.IPAddressSection.IPStringBuilderOptions;
import inet.ipaddr.format.string.AddressStringDivision;
import inet.ipaddr.format.string.IPAddressStringDivisionSeries;

/**
 * 
 * @author sfoley
 *
 */
public class IPAddressPartStringCollection extends IPAddressPartStringCollectionBase<IPAddressStringDivisionSeries, IPAddressStringWriter<?>, IPAddressPartConfiguredString<?, ?>> {
	
	private final List<IPAddressPartStringSubCollection<?, ?, ? extends IPAddressPartConfiguredString<?, ?>>> collections = 
			new ArrayList<IPAddressPartStringSubCollection<?, ?, ? extends IPAddressPartConfiguredString<?, ?>>>();
	
	protected IPAddressPartStringCollection(){}
	
	protected void add(IPAddressPartStringSubCollection<?, ?, ? extends IPAddressPartConfiguredString<?, ?>> collection) {
		this.collections.add(collection);
	}
	
	protected void addAll(IPAddressPartStringCollection collections) {
		this.collections.addAll(collections.collections);
	}
	
	public int getPartCount() {
		return collections.size();
	}
	
	public IPAddressStringDivisionSeries getPart(int index) {
		return this.getSubCollection(index).part;
	}
	
	public IPAddressStringDivisionSeries[] getParts(IPAddressStringDivisionSeries[] array) {
		int size = getPartCount();
		IPAddressStringDivisionSeries result[];
		if (array.length < size) {
			result = (IPAddressStringDivisionSeries[]) Array.newInstance(array.getClass().getComponentType(), size);
		} else {
			result = array;
		}
		int i = 0;
		for(IPAddressPartStringSubCollection<?, ?, ?> coll : collections) {
			result[i++] = coll.part;
		}
		return result;
	}
	
	public IPAddressPartStringSubCollection<?,?,?> getSubCollection(IPAddressStringDivisionSeries part) {
		for(IPAddressPartStringSubCollection<?,?,?> sub : collections) {
			if(sub.part.equals(part)) {
				return sub;
			}
		}
		return null;
	}
	
	public IPAddressPartStringSubCollection<?,?,?> getSubCollection(int index) {
		return collections.get(index);
	}
	
	@Override
	public int size() {
		int size = 0;
		for(IPAddressPartStringSubCollection<?, ?, ?> collection : collections) {
			size += collection.size();
		}
		return size;
	}

	@Override
	public Iterator<IPAddressPartConfiguredString<?, ?>> iterator() {
		return new Iterator<IPAddressPartConfiguredString<?, ?>>() {
			private int i;
			private Iterator<? extends IPAddressPartConfiguredString<?, ?>> currentIterator;
			
			@Override
			public boolean hasNext() {
				while(true) {
					if(currentIterator == null) {
						if(i < collections.size()) {
							currentIterator = collections.get(i++).iterator();
						} else {
							return false;
						}
					}
					if(currentIterator.hasNext()) {
						return true;
					}
					currentIterator = null;
				}
			}

			@Override
			public IPAddressPartConfiguredString<?, ?> next() {
				if(hasNext()) {
					return currentIterator.next();
				}
				throw new NoSuchElementException();
			}

			@Override
			public void remove() {
				if(currentIterator == null) {
					throw new IllegalStateException();
				}
				currentIterator.remove();
			}
		};
	}
	
	/**
	 * 
	 * @author sfoley
	 *
	 * @param <T> the type of the address part from which this builder was derived
	 * @param <P> the type of the params used to generate each string
	 * @param <S> the type of the configurable strings, each of which pairs an IPAddressPart and a IPAddressPartStringParams to produce a string.
	 * @param <C> the type of the collection produced by this builder
	 * @param <O> the type of the options used by this builder to control which strings are produced
	 */
	protected static abstract class AddressPartStringBuilder< 
			T extends IPAddressStringDivisionSeries,
			P extends IPAddressStringWriter<T>,
			S extends IPAddressPartConfiguredString<T, P>,
			C extends IPAddressPartStringSubCollection<T, P, S>,
			O extends IPStringBuilderOptions> {
		
		//for each base, indicates the number of leading zeros that can be added for each segment
		//so leadingZeros[16][1] indicates the leading zeros that can be added to the segment at index 1 when using base 16
		protected static int MAX_BASE = 16;
		private int leadingZeros[][];
		protected final T addressSection;
		protected final O options;
		protected final C collection;
		private boolean done;
		
		protected AddressPartStringBuilder(T addressSection, O options, C collection) {
			this.addressSection = addressSection;
			this.options = options;
			this.collection = collection;
		}
		
		public C getVariations() {
			if(!done) {
				synchronized(this) {
					if(!done) {
						done = true;
						addAllVariations();
					}
				}
			}
			return collection;
		}
		
		protected abstract void addAllVariations();
		
		protected void addStringParam(P stringParams) {
			collection.add(stringParams);
		}
		
		protected boolean isExpandable(int radix) {
			return isExpandable(radix, addressSection);
		}
		
		protected boolean isExpandableOutsideRange(int radix, int segmentIndex, int count) {
			return isExpandableOutsideRange(radix, addressSection, segmentIndex, count);
		}

		private static boolean isExpandable(int radix, IPAddressStringDivisionSeries part) {
			return isExpandableOutsideRange(radix, part, -1, 0);
		}
		
		private static boolean isExpandableOutsideRange(int radix, IPAddressStringDivisionSeries part, int segmentIndex, int count) {
			int nextSegmentIndex = segmentIndex + count;
			for(int i = 0; i < part.getDivisionCount(); i++) {
				if(i >= segmentIndex && i < nextSegmentIndex) {
					continue;
				}
				AddressStringDivision div = part.getDivision(i);
				int digitCount = div.getDigitCount(radix);
				int maxDigitCount = div.getMaxDigitCount(radix);
				if(digitCount < maxDigitCount) {
					return true;
				}
			}
			return false;
		}
		
		protected int[] getExpandableSegments(int radix) {
			int result[];
			if(leadingZeros == null) {
				leadingZeros = new int[MAX_BASE + 1][];
				leadingZeros[radix] = result = getExpandableSegments(radix, addressSection);
			} else {
				if((result = leadingZeros[radix]) == null) {
					leadingZeros[radix] = result = getExpandableSegments(radix, addressSection);
				}
			}
			return result;
		}
		
		protected static int[] getExpandableSegments(int radix, IPAddressStringDivisionSeries part) {
			int count = part.getDivisionCount();
			int expandables[] = new int[count];
			for(int i = 0; i < count; i++) {
				AddressStringDivision div = part.getDivision(i);
				int digitCount = div.getDigitCount(radix);
				int maxDigitCount = div.getMaxDigitCount(radix);
				if(digitCount < maxDigitCount) {
					expandables[i] = maxDigitCount - digitCount;
				} else {
					expandables[i] = 0;
				}
			}
			return expandables;
		}
	}
}
