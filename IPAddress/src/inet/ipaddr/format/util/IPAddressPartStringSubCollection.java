package inet.ipaddr.format.util;

import java.util.ArrayList;
import java.util.Iterator;

import inet.ipaddr.format.IPAddressPart;

public abstract class IPAddressPartStringSubCollection<
		T extends IPAddressPart,
		P extends IPAddressPartStringParams<T>,
		S extends IPAddressPartConfiguredString<T, P>> extends AddressPartStringCollection<T, P, S> {
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