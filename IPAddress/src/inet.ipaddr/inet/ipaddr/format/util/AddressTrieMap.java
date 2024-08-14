/*
 * Copyright 2020-2024 Sean C Foley
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

import java.io.Serializable;
import java.util.AbstractMap;
import java.util.AbstractSet;
import java.util.Collection;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.Queue;
import java.util.Spliterator;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Function;

import inet.ipaddr.Address;
import inet.ipaddr.format.util.AddressTrie.AddressBounds;
import inet.ipaddr.format.util.AddressTrieSet.Range;
import inet.ipaddr.format.util.AssociativeAddressTrie.AssociativeTrieNode;

/**
 * Wraps a {@link inet.ipaddr.format.util.AssociativeAddressTrie} to view it as a Java Collections Framework map, 
 * implementing the {@link java.util.Map}, {@link java.util.SortedMap}, and {@link java.util.NavigableMap} interfaces.
 * <p>
 * Like {@link java.util.TreeMap}, this map is backed by a binary tree and implements the same interfaces that {@link java.util.TreeMap} does.  
 * But there are some significant differences between the two binary tree implementations.
 * <p>
 * A trie is naturally balanced and can only reach a depth corresponding to the number of bits in the keys, 
 * which is 32 for IPv4 and 128 for IPv6 tries.  The TreeMap is balanced using red-black balancing.
 * <p>
 * The {@link inet.ipaddr.format.util.AssociativeAddressTrie} allows you to modify the map entries using {@link java.util.Map.Entry#setValue(Object)},
 * while {@link java.util.TreeMap} does not.  The entries provided by the {@link java.util.TreeMap} are copies of the original nodes,
 * so that the original nodes can be re-purposed.  The nodes are not exposed.
 * <p>
 * In the {@link inet.ipaddr.format.util.AssociativeAddressTrie} nodes are not re-purposed, and in fact they are also exposed.  
 * This enables navigation through the nodes.
 * The node hierarchy has a special meaning, there is only one hierarchy for any given set of addresses, 
 * since it is determined by prefix block subnet containment.  The hierarchy enables certain address-specific containment-based operations,
 * such as subnet deletion or containment checks. 
 * <p>
 * In the trie map, when doing lookups and some other operations, only parts of the address keys are examined at each node in the binary tree search, 
 * rather than comparisons of the whole key, as with {@link java.util.TreeMap}.  
 * The trie map supports only the one comparison representing subnet containment, which is based on bit values and prefix length.
 * The TreeMap is a general-purpose map supporting any natural ordering or Comparator.
 * <p>
 * With the trie map, only addresses that are either individual address or prefix block subnets of the same type and version can be added to the trie,
 * see {@link inet.ipaddr.format.util.AddressTrie.AddressComparator} for a comparator for the ordering.
 * <p>
 * Should you wish to store, in a map, address instances that are not individual address or prefix block subnets,
 * you can use {@link java.util.TreeMap} or any other Java collections framework map to store addresses of any type,
 * or addresses of different versions or types in the same map,
 * since all address items in this library are comparable with a natural ordering.  
 * There are additional orderings provided by this library as well, see {@link inet.ipaddr.AddressComparator}.
 * 
 * 
 * 
 * @author scfoley
 *
 * @param <K> the address type
 * @param <V> the type of the mapped values
 */
public class AddressTrieMap<K extends Address, V> extends AbstractMap<K, V> implements NavigableMap<K, V>, Cloneable, Serializable {

	private static final long serialVersionUID = 1L;

	private AssociativeAddressTrie<K, V> trie; // the backing trie
	private final boolean isReverse;
	private final Range<K> bounds;

	private EntrySet<K,V> entrySet; // cached
	private AddressTrieSet<K> keySet; // cached
	private AddressTrieMap<K, V> descending; // cached

	public AddressTrieMap(AssociativeAddressTrie<K, V> trie) {
		this.trie = trie;
		this.isReverse = false;
		this.bounds = null;
		if(trie.map == null) {
			trie.map = this;
		}
	}

	public AddressTrieMap(AssociativeAddressTrie<K, V> trie, Map<? extends K, ? extends V> map) {
		this.trie = trie;
		this.isReverse = false;
		this.bounds = null;
		if(trie.map == null) {
			trie.map = this;
		}
		putAll(map);
	}

	AddressTrieMap(AssociativeAddressTrie<K, V> trie, Range<K> bounds, boolean isReverse) {
		this.trie = trie;
		this.bounds = bounds;
		this.isReverse = isReverse;
		if(trie.map == null && !isReverse && bounds == null) {
			trie.map = this;
		}
	}

	boolean isBounded() {
		return bounds != null;
	}

	@Override
	public AddressTrieMap<K, V> descendingMap() {
		AddressTrieMap<K, V> desc = descending;
		if(desc == null) {
			Range<K> reverseBounds = isBounded() ?  bounds.reverse() : null;
			desc = new AddressTrieMap<K, V>(trie, reverseBounds, !isReverse);
			descending = desc;
			desc.descending = this;
		}
		return desc;
	}

	@Override
	public AddressTrieSet<K> descendingKeySet() {
		return descendingMap().keySet();
	}

	/**
	 * Return a trie representing this map.
	 * <p>
	 * If this map has a restricted range, see {@link #hasRestrictedRange()}, 
	 * this generates a new trie corresponding to the map with only the nodes pertaining to the restricted range sub-map.
	 * Otherwise this returns the original backing trie for this map.
	 * <p>
	 * When a new trie is generated, the original backing trie for this map remains the same, it is not changed to the new trie.
	 * <p>
	 * The returned trie will always have the same natural trie ordering,
	 * even if this map has the reverse ordering.
	 * 
	 */
	public AssociativeAddressTrie<K, V> asTrie() {
		if(isBounded()) {
			return trie.clone();
		}
		if(!isReverse) {
			trie.map = this;// in case we constructed the set first, we put a reference back to us
		}
		return trie;
	}

	/**
	 * Returns whether this map is the result of a call to {@link #headMap(Address)}, {@link #tailMap(Address)},
	 * {@link #subMap(Address, Address)} or any of the other methods with the same names.
	 * 
	 * @return
	 */
	public boolean hasRestrictedRange() {
		return isBounded();
	}

	/**
	 * Returns the range if this map has a restricted range, see {@link #hasRestrictedRange()}.  Otherwise returns null.
	 * 
	 * @return
	 */
	public Range<K> getRange() {
		return bounds;
	}

	public static class EntrySet<K extends Address, V> extends AbstractSet<Entry<K,V>> implements Serializable {

		private static final long serialVersionUID = 1L;

		AssociativeAddressTrie<K, V> trie;
		private final boolean isReverse;

		EntrySet(AssociativeAddressTrie<K, V> trie, boolean isReverse) {
			this.trie = trie;
			this.isReverse = isReverse;
		}

		@SuppressWarnings("unchecked")
		@Override
		public Iterator<Entry<K,V>> iterator() {
			Iterator<? extends Entry<K, V>> result = trie.nodeIterator(!isReverse);
			return (Iterator<Entry<K, V>>) result;
		}

		/**
		 * Returns an iterator that visits containing subnet blocks before their contained addresses and subnet blocks.
		 * <p>
		 */
		@SuppressWarnings("unchecked")
		public Iterator<Entry<K,V>> containingFirstIterator() {
			Iterator<? extends Entry<K, V>> it = trie.containingFirstIterator(!isReverse);
			return (Iterator<Entry<K, V>>) it;
		}

		/**
		 * Returns an iterator that visits contained addresses and subnet blocks before their containing subnet blocks.
		 * @return
		 */
		@SuppressWarnings("unchecked")
		public Iterator<Entry<K,V>> containedFirstIterator() {
			Iterator<? extends Entry<K, V>> it = trie.containedFirstIterator(!isReverse);
			return (Iterator<Entry<K, V>>) it;
		}

		/**
		 * Iterates from largest prefix blocks to smallest to individual addresses.
		 * 
		 * @return
		 */	
		@SuppressWarnings("unchecked")
		public Iterator<Entry<K,V>> blockSizeIterator() {
			Iterator<? extends Entry<K, V>> iterator = trie.blockSizeNodeIterator(!isReverse);
			return (Iterator<Entry<K, V>>) iterator;
		}

		@SuppressWarnings("unchecked")
		@Override
		public Spliterator<Entry<K,V>> spliterator() {
			Spliterator<? extends Entry<K, V>> result = trie.nodeSpliterator(!isReverse);
			return (Spliterator<Entry<K, V>>) result;
		}

		@Override
		public int size() {
			return trie.size();
		}

		@Override
		public boolean isEmpty() {
			return trie.isEmpty();
	    }

		@SuppressWarnings("unchecked")
		@Override
		public boolean contains(Object o) {
			if (!(o instanceof Entry)) {
				return false;
			}
			Entry<K,?> entry = (Entry<K,?>) o;
			Entry<K,V> existingNode = trie.getAddedNode(entry.getKey());
			return existingNode != null && Objects.equals(existingNode.getValue(), entry.getValue());
		}

		@SuppressWarnings("unchecked")
		@Override
		public boolean remove(Object o) {
			if (!(o instanceof Entry)) {
				return false;
			}
			Entry<K,?> entry = (Entry<K,?>) o; 
			AssociativeTrieNode<K, V> existingNode = trie.getAddedNode(entry.getKey());
			if(existingNode != null && Objects.equals(existingNode.getValue(), entry.getValue())) {
				existingNode.remove();
				return true;
			}
			return false;
		}

		@Override
		public void clear() {
			trie.clear();
		}

		@Override
		public int hashCode() {
			return trie.hashCode();
		}

		@Override
		public boolean equals(Object o) {
			if(o instanceof AddressTrieMap.EntrySet) {
				EntrySet<?,?> other = (EntrySet<?,?>) o;
				return trie.equals(other.trie);
			} 
			return super.equals(o);
		}

		@Override
		public boolean removeAll(Collection<?> collection) {
			if(collection instanceof List || collection instanceof Queue || collection.size() < size()) {
				boolean result = false;
				for (Object object : collection) {
					if(remove(object)) {
						result = true;
					}
				}
				return result;
			}
			return removeIf(collection::contains);
	    }
	}

	@Override
	public AddressTrieSet<K> keySet() {
		AddressTrieSet<K> set = keySet;
		if(set == null) {
			set = new AddressTrieSet<K>(trie, bounds, isReverse);
			keySet = set;
		}
		return set;
	}

	@Override
	public AddressTrieSet<K> navigableKeySet() {
		return keySet();
	}

	@Override
	public EntrySet<K,V> entrySet() {
		EntrySet<K,V> set = entrySet;
		if(set == null) {
			set = new EntrySet<K,V>(trie, isReverse);
			entrySet = set;
		}
		return set;
	}

	@Override
	public V merge(K key, V suppliedValue,
            BiFunction<? super V, ? super V, ? extends V> remappingFunction) {
		if(suppliedValue == null) {
			throw new NullPointerException();
		}
		AssociativeTrieNode<K, V> node = trie.remap(key, existingValue -> {
			V newValue =  (existingValue == null) ? suppliedValue : remappingFunction.apply(existingValue, suppliedValue);
			return newValue;
		});
		if(node != null) {
			return node.getValue();
		}
		return null;
	}

	@Override
	public V compute(K key, BiFunction<? super K, ? super V, ? extends V> remappingFunction) {
		AssociativeTrieNode<K, V> node = trie.remap(key, existingValue -> {
			V newValue = remappingFunction.apply(key, existingValue);
			return newValue;
		});
		if(node != null) {
			return node.getValue();
		}
		return null;
	}

	@Override
	public V computeIfAbsent(K key, Function<? super K, ? extends V> remappingFunction) {
		AssociativeTrieNode<K, V> node = trie.remapIfAbsent(key, () -> remappingFunction.apply(key), false);
		if(node != null) {
			return node.getValue();
		}
		return null;
	}

	@Override
	public V putIfAbsent(K key, V value) {
		return trie.remapIfAbsent(key, () -> value, true).getValue();
	}

	@Override
	public V computeIfPresent(K key, BiFunction<? super K, ? super V, ? extends V> remappingFunction) {
		AssociativeTrieNode<K,V> node = getNode(key);
		if(node != null) {
			V prevValue = node.getValue();
			if(prevValue != null) {
				 V newValue = remappingFunction.apply(key, prevValue);
				 if (newValue != null) {
	                node.setValue(newValue);
	            } else {
	            	node.remove();
	            }
				return newValue;
			}
		}
		return null;
	}

	@SuppressWarnings("unchecked")
	@Override
	public boolean containsKey(Object key) {
		return trie.contains((K) key);
	}

	@Override
	public boolean containsValue(Object value) {
		Iterator<? extends AssociativeTrieNode<K, V>> iterator = trie.nodeIterator(true);
		while (iterator.hasNext()) {
			AssociativeTrieNode<K, V> node = iterator.next();
			if (value.equals(node.getValue())) {
				return true;
			}
		}
		return false;
	}

	@SuppressWarnings("unchecked")
	@Override
	public V get(Object key) {
		return trie.get((K) key);
	}

	/**
	 * Maps the given single address or prefix block subnet to the given value in the map.
	 * <p>
	 * If the given address is not a single address nor prefix block, then this method throws IllegalArgumentException. 
	 * <p>
	 * See {@link AssociativeAddressTrie}
	 */
	@Override
	public V put(K key, V value) {
		return trie.put(key, value);
	}

	@SuppressWarnings("unchecked")
	@Override
	public V remove(Object key) {
		AssociativeTrieNode<K,V> node = getNode((K) key);
		if(node != null) {
			V result = node.getValue();
			node.remove();
			return result;
		}
		return null;
	}

	private AssociativeTrieNode<K,V> getNode(K key) {
		return (AssociativeTrieNode<K, V>) trie.getAddedNode(key);
	}

	@SuppressWarnings("unchecked")
	@Override
	public V getOrDefault(Object key, V defaultValue) {
		AssociativeTrieNode<K,V> node = getNode((K) key);
		return node == null ? defaultValue : node.getValue();
	}

	@Override
	public void forEach(BiConsumer<? super K, ? super V> action) {
		Iterator<? extends AssociativeTrieNode<K,V>> iterator = trie.nodeIterator(!isReverse);
		if(iterator.hasNext()) {
			AssociativeTrieNode<K,V> next = iterator.next();
			action.accept(next.getKey(), next.getValue());
			while(iterator.hasNext()) {
				next = iterator.next();
				action.accept(next.getKey(), next.getValue());
			}
		} else if(action == null) {
			throw new NullPointerException();
		}
	}

	@Override
	public void replaceAll(BiFunction<? super K, ? super V, ? extends V> function) {
		Iterator<? extends AssociativeTrieNode<K,V>> iterator = trie.nodeIterator(!isReverse);
		if(iterator.hasNext()) {
			AssociativeTrieNode<K,V> next = iterator.next();
			next.setValue(function.apply(next.getKey(), next.getValue()));
			while(iterator.hasNext()) {
				next = iterator.next();
				next.setValue(function.apply(next.getKey(), next.getValue()));
			}
		} else if(function == null) {
			throw new NullPointerException();
		}
	}

	@SuppressWarnings("unchecked")
	@Override
	public boolean remove(Object key, Object value) {
		AssociativeTrieNode<K,V> node = getNode((K) key);
		if(node != null) {
			V prevValue = node.getValue();
			if(Objects.equals(value, prevValue)) {
				node.remove();
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean replace(K key, V oldValue, V newValue) {
		AssociativeTrieNode<K,V> node = getNode(key);
		if(node != null) {
			V prevValue = node.getValue();
			if(Objects.equals(oldValue, prevValue)) {
				node.setValue(newValue);
				return true;
			}
		}
		return false;
	}

	@Override
	public V replace(K key, V value) {
		AssociativeTrieNode<K,V> node = getNode(key);
		if(node != null) {
			V prevValue = node.getValue();
			node.setValue(value);
			return prevValue;
		}
		return null;
	}

	/**
     * Returns the number of mappings in this map.  
     * This is a constant time operation, unless the map has a restricted range, see {@link #hasRestrictedRange()},
     * in which case it is a linear time operation proportional to the number of mappings.
     * 
     * @return the number of elements in this map
     */
	@Override
	public int size() {
		return trie.size();
	}

	@Override
	public boolean isEmpty() {
		return trie.isEmpty();
    }

	@Override
	public void clear() {
    	trie.clear();
	}

	@Override
	public int hashCode() {
		return trie.hashCode();
	}

	private AddressTrieMap<K,V> toSubMap(K fromKey, boolean fromInclusive, K toKey, boolean toInclusive) {
		if(isReverse) {
			K tmp = fromKey;
			boolean tmpInc = fromInclusive;
			fromKey = toKey;
			fromInclusive = toInclusive;
			toKey = tmp;
			toInclusive = tmpInc;
		}
		AddressBounds<K> bounds = trie.bounds, newBounds;
		if(bounds == null) {
			newBounds = AddressBounds.createNewBounds(fromKey, fromInclusive, toKey, toInclusive, trie.getComparator());
		} else {
			newBounds = bounds.restrict(fromKey, fromInclusive, toKey, toInclusive);
			
		}
		if(newBounds == null) {
			return this;
		}
		Range<K> newRange = new Range<K>(newBounds, isReverse);
		return new AddressTrieMap<K,V>(trie.createSubTrie(newBounds), newRange, isReverse);
	}

	@Override
	public AddressTrieMap<K,V> subMap(K fromKey, K toKey) {
		return subMap(fromKey, true, toKey, false);
	}
	
	@Override
	public AddressTrieMap<K, V> subMap(K fromKey, boolean fromInclusive, K toKey, boolean toInclusive) {
		if(fromKey == null || toKey == null) {
			throw new NullPointerException();
		}
		return toSubMap(fromKey, fromInclusive, toKey, toInclusive);
	}

	@Override
	public AddressTrieMap<K,V> headMap(K toKey) {
		return headMap(toKey, false);
	}

	@Override
	public AddressTrieMap<K, V> headMap(K toKey, boolean inclusive) {
		if(toKey == null) {
			throw new NullPointerException();
		}
		return toSubMap(null, true, toKey, inclusive);
	}

	@Override
	public AddressTrieMap<K,V> tailMap(K fromKey) {
		return tailMap(fromKey, true);
	}

	@Override
	public AddressTrieMap<K, V> tailMap(K fromKey, boolean inclusive) {
		if(fromKey == null) {
			throw new NullPointerException();
		}
		return toSubMap(fromKey, inclusive, null, false);
	}

	@Override
	public Entry<K, V> firstEntry() {
		return isReverse ? trie.lastAddedNode() : trie.firstAddedNode();
	}

	@Override
	public K firstKey() {
		return keySet().first();
	}

	@Override
	public Entry<K, V> lastEntry() {
		return isReverse ? trie.firstAddedNode()  : trie.lastAddedNode();
	}

	@Override
	public K lastKey() {
		return keySet().last();
	}

	@Override
	public Entry<K, V> lowerEntry(K key) {
		return isReverse ? trie.higherAddedNode(key) : trie.lowerAddedNode(key);
	}

	@Override
	public K lowerKey(K key) {
		return keySet().lower(key);
	}

	@Override
	public Entry<K, V> floorEntry(K key) {
		return isReverse ? trie.ceilingAddedNode(key) : trie.floorAddedNode(key);
	}

	@Override
	public K floorKey(K key) {
		return keySet().floor(key);
	}

	@Override
	public Entry<K, V> ceilingEntry(K key) {
		return isReverse ? trie.floorAddedNode(key) : trie.ceilingAddedNode(key);
	}

	@Override
	public K ceilingKey(K key) {
		return keySet().ceiling(key);
	}

	@Override
	public Entry<K, V> higherEntry(K key) {
		return isReverse ? trie.lowerAddedNode(key) : trie.higherAddedNode(key);
	}

	@Override
	public K higherKey(K key) {
		return keySet().higher(key);
	}

	@Override
	public Entry<K, V> pollFirstEntry() {
		AssociativeTrieNode<K,V> first = isReverse ? trie.lastAddedNode() : trie.firstAddedNode();
    	if(first == null) {
    		return null;
    	}
    	first.remove();
    	return first;
	}

	@Override
	public Entry<K, V> pollLastEntry() {
		AssociativeTrieNode<K,V> last = isReverse ? trie.firstAddedNode() : trie.lastAddedNode();
    	if(last == null) {
    		return null;
    	}
    	last.remove();
    	return last;
	}

	@Override
	public boolean equals(Object o) {
		if(o instanceof AddressTrieMap<?,?>) {
			AddressTrieMap<?,?> other = (AddressTrieMap<?,?>) o;
			// note that isReverse is ignored, intentionally
			// two maps are equal if they have the same mappings
			return trie.equals(other.trie);
		} 
		return super.equals(o);
	}

	/**
	 * Clones the map along with the backing trie.  If the map had a restricted range, the clone does not.
	 */
	@SuppressWarnings("unchecked")
	@Override
	public AddressTrieMap<K,V> clone() {
		try {
			AddressTrieMap<K,V> clone = (AddressTrieMap<K,V>) super.clone();
			clone.trie = trie.clone();
			// cloning a trie eliminates the bounds, we we put them back
			clone.trie.bounds = trie.bounds; //can share because bounds are immutable
			clone.keySet = null;
			clone.entrySet = null;
			clone.descending = null;
			return clone;
		} catch (CloneNotSupportedException cannotHappen) {
			return null;
		}
	}

	@Override
	public Comparator<K> comparator() {
		return isReverse ? AddressTrie.reverseComparator() : AddressTrie.comparator();
	}

	public String toTrieString() {
		return trie.toString();
	}

	/**
	 * Returns a sub-map consisting of the mappings in the map with address keys contained by the given address
	 * The sub-map will have a restricted range matching the range of the given subnet or address.
	 * <p>
	 * If the sub-map would be the same size as this map, then this map is returned.
	 * The sub-map will the same backing trie as this map.
	 * 
	 * @param addr
	 * @return
	 */
	public AddressTrieMap<K,V> subMapFromKeysContainedBy(K addr) {
		AssociativeAddressTrie<K,V> newTrie = trie.elementsContainedByToSubTrie(addr);
		if(trie == newTrie) {
			return this;
		}
		if(newTrie.bounds == null) {
			return new AddressTrieMap<K,V>(newTrie, null, isReverse);
		}
		Range<K> newRange = new Range<K>(newTrie.bounds, isReverse);
		return new AddressTrieMap<K,V>(newTrie, newRange, isReverse);
	}

	/**
	 * Returns a sub-map consisting of the mappings in the map with address keys that contain the given address.
	 * The sub-map will have the same restricted range (if any) as this sub-map.
	 * <p>
	 * If the sub-map would be the same size as this map, then this map is returned.
	 * Otherwise, the sub-map is backed by a new trie.
	 
	 * @param addr
	 * @return
	 */
	public AddressTrieMap<K,V> subMapFromKeysContaining(K addr) {
		AssociativeAddressTrie<K,V> newTrie = trie.elementsContainingToTrie(addr);
		if(trie == newTrie) {
			return this;
		}
		if(newTrie.bounds == null) {
			return new AddressTrieMap<K,V>(newTrie, null, isReverse);
		}
		Range<K> newRange = new Range<K>(newTrie.bounds, isReverse);
		return new AddressTrieMap<K,V>(newTrie, newRange, isReverse);
	}

	/**
	 * Returns true if a subnet or address key in the map contains the given subnet or address.
	 * 
	 * @param addr
	 * @return
	 */
	public boolean keyContains(K addr) {
		return trie.elementContainsBounds(addr);
	}
	
	/**
	 * Returns the map entry corresponding to the key with the longest prefix match with the given address.
	 * @param addr
	 * @return
	 */
	public Entry<K,V> longestPrefixMatchEntry(K addr) {
		return trie.smallestElementContainingBounds(addr);
	}
}
