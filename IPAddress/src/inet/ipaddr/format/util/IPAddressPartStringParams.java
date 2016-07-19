package inet.ipaddr.format.util;

import inet.ipaddr.format.IPAddressPart;

/**
 * Each AddressPartStringParams has settings to write exactly one IP address part string.
 * 
 * @author sfoley
 */
public abstract class IPAddressPartStringParams<T extends IPAddressPart> implements Cloneable {
	
	protected IPAddressPartStringParams() {}
	
	protected abstract StringBuilder append(StringBuilder builder, T addr);
	
	/**
	 * 
	 * @param addr
	 * @return the string produced by these params
	 */
	public abstract String toString(T addr);
	
	/**
	 * 
	 * @param addr
	 * @return the number of segment separators in the string produced by these params
	 */
	public abstract int getTrailingSeparatorCount(T addr);
	
	public abstract char getTrailingSegmentSeparator();
	

	@SuppressWarnings("unchecked")
	@Override
	public IPAddressPartStringParams<T> clone() {
		try {
			return (IPAddressPartStringParams<T>) super.clone();
		} catch(CloneNotSupportedException e) {}
		return null;
	}
}
