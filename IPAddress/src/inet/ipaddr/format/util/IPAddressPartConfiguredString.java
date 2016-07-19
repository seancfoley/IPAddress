package inet.ipaddr.format.util;

import inet.ipaddr.format.IPAddressPart;
import inet.ipaddr.format.util.sql.IPAddressSQLTranslator;
import inet.ipaddr.format.util.sql.SQLStringMatcher;

/**
 * Pairs a part of an IP address along with an instance of a parameter class to define a specific string.
 * 
 * @author sfoley
 *
 * @param <T> the type of the address part from which this configurable string was derived
 * @param <P> the type of the params used to generate the string
 */
public class IPAddressPartConfiguredString<T extends IPAddressPart, P extends IPAddressPartStringParams<T>> {
	
	public final T addr;
	public final P stringParams;
	protected String string;
	
	public IPAddressPartConfiguredString(T addr, P stringParams) {
		this.stringParams = stringParams;
		this.addr = addr;
	}
	
	public int getTrailingSeparatorCount() {
		return stringParams.getTrailingSeparatorCount(addr);
	}
	
	public char getTrailingSegmentSeparator() {
		return stringParams.getTrailingSegmentSeparator();
	}
	
	/**
	 * Provides an object that can build SQL clauses to match this string representation.
	 * 
	 * This method can be overridden for other IP address types to match in their own ways.
	 * 
	 * @param isEntireAddress
	 * @param translator
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public <S extends IPAddressPartConfiguredString<T, P>> SQLStringMatcher<T, P, S> getNetworkStringMatcher(boolean isEntireAddress, IPAddressSQLTranslator translator) {
		return new SQLStringMatcher<T, P, S>((S) this, isEntireAddress, translator);
	}
	
	public String getString() {
		if(string == null) {
			string = stringParams.toString(addr);
		}
		return string;
	}
	
	@Override
	public String toString() {
		return getString();
	}
}