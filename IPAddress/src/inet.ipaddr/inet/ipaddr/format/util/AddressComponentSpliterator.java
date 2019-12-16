package inet.ipaddr.format.util;

import inet.ipaddr.format.AddressComponentRange;

/**
 * AddressComponentSpliterator is an AddressComponentRangeSpliterator for address components where 
 * the type of the item producing the spliterator matches the type of the item traversed.
 * 
 * @author seancfoley
 *
 * @param <T>
 */
public interface AddressComponentSpliterator<T extends AddressComponentRange> extends AddressComponentRangeSpliterator<T, T> {
	
	@Override
	AddressComponentSpliterator<T> trySplit();
}
