package inet.ipaddr.format.util;

import inet.ipaddr.format.IPAddressPart;

/**
 * 
 * @author sfoley
 *
 * @param <T> the type of the address part from which this collection was derived
 * @param <P> the type of the params used to generate each string
 * @param <S> the type of the configurable strings, each of which pairs an IPAddressPart and a {@link IPAddressPartStringParams} to produce a string.
 */
abstract class AddressPartStringCollection<
		T extends IPAddressPart,
		P extends IPAddressPartStringParams<?>,
		S extends IPAddressPartConfiguredString<?, ?>> implements Iterable<S> { 
	
	protected abstract int size();
	
	public String[] toStrings() {
		String strings[] = new String[size()];
		int i = 0;
		for(IPAddressPartConfiguredString<?, ?> createdString : this) {
			strings[i++] = createdString.getString();
		}
		return strings;
	}
}
