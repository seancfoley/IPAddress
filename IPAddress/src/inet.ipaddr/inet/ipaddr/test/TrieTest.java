package inet.ipaddr.test;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.PrintStream;
import java.util.AbstractSet;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.ConcurrentModificationException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.NavigableSet;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Set;
import java.util.SortedSet;
import java.util.Spliterator;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.IntFunction;
import java.util.function.Supplier;
import java.util.function.ToIntFunction;

import inet.ipaddr.Address;
import inet.ipaddr.AddressNetwork.PrefixConfiguration;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.IPAddressStringParameters;
import inet.ipaddr.MACAddressString;
import inet.ipaddr.MACAddressStringParameters;
import inet.ipaddr.format.util.AddressTrie;
import inet.ipaddr.format.util.AddressTrie.TrieNode;
import inet.ipaddr.format.util.AddressTrieMap;
import inet.ipaddr.format.util.AddressTrieMap.EntrySet;
import inet.ipaddr.format.util.AddressTrieSet;
import inet.ipaddr.format.util.AssociativeAddressTrie;
import inet.ipaddr.format.util.AssociativeAddressTrie.AssociativeTrieNode;
import inet.ipaddr.format.util.BinaryTreeNode;
import inet.ipaddr.format.util.BinaryTreeNode.CachingIterator;
import inet.ipaddr.format.util.Partition;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv4.IPv4AddressAssociativeTrie;
import inet.ipaddr.ipv4.IPv4AddressTrie;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.ipv6.IPv6AddressAssociativeTrie;
import inet.ipaddr.ipv6.IPv6AddressTrie;
import inet.ipaddr.mac.MACAddress;
import inet.ipaddr.mac.MACAddressAssociativeTrie;
import inet.ipaddr.mac.MACAddressTrie;
import inet.ipaddr.test.TestRunner.EfficientByteArrayInputStream;
import inet.ipaddr.test.TestRunner.EfficientByteArrayOuputStream;

public class TrieTest extends TestBase {

	private static final IPAddressStringParameters DEFAULT_OPTIONS = new IPAddressStringParameters.Builder().toParams();
	private static final MACAddressStringParameters DEFAULT_MAC_OPTIONS = new MACAddressStringParameters.Builder().toParams();
	
	public TrieTest(AddressCreator creator) {
		super(creator);
	}
	
	@Override
	protected IPAddressString createInetAtonAddress(String x) {
		return createAddress(x);
	}
	
	@Override
	protected IPAddressString createAddress(String x) {
		return createAddress(x, DEFAULT_OPTIONS);
	}
	
	@Override
	protected MACAddressString createMACAddress(String x) {
		return createMACAddress(x, DEFAULT_MAC_OPTIONS);
	}

	static class Strings {
		String addrs[];
		String treeString;
		String addedNodeString;
		
		Strings(String addrs[], String treeString, String addedNodeString) {
			this.addrs = addrs;
			this.treeString = treeString;
			this.addedNodeString = addedNodeString;
		}
	}
	
	Strings one = new Strings(
			new String[] {"1::ffff:2:3:5",
			"1::ffff:2:3:4",
			"1::ffff:2:3:6",
			"1::ffff:2:3:12",
			"1::ffff:aa:3:4",
			"1::ff:aa:3:4",
			"1::ff:aa:3:12",
			"bb::ffff:2:3:6",
			"bb::ffff:2:3:12",
			"bb::ffff:2:3:22",
			"bb::ffff:2:3:32",
			"bb::ffff:2:3:42",
			"bb::ffff:2:3:43", 
		},
"\n" +	
"○ ::/0 (13)\n" +
"└─○ ::/8 (13)\n" +
"  ├─○ 1::/64 (7)\n" +
"  │ ├─○ 1::ff:aa:3:0/123 (2)\n" +
"  │ │ ├─● 1::ff:aa:3:4 (1)\n" +
"  │ │ └─● 1::ff:aa:3:12 (1)\n" +
"  │ └─○ 1::ffff:0:0:0/88 (5)\n" +
"  │   ├─○ 1::ffff:2:3:0/123 (4)\n" +
"  │   │ ├─○ 1::ffff:2:3:4/126 (3)\n" +
"  │   │ │ ├─○ 1::ffff:2:3:4/127 (2)\n" +
"  │   │ │ │ ├─● 1::ffff:2:3:4 (1)\n" +
"  │   │ │ │ └─● 1::ffff:2:3:5 (1)\n" +
"  │   │ │ └─● 1::ffff:2:3:6 (1)\n" +
"  │   │ └─● 1::ffff:2:3:12 (1)\n" +
"  │   └─● 1::ffff:aa:3:4 (1)\n" +
"  └─○ bb::ffff:2:3:0/121 (6)\n" +
"    ├─○ bb::ffff:2:3:0/122 (4)\n" +
"    │ ├─○ bb::ffff:2:3:0/123 (2)\n" +
"    │ │ ├─● bb::ffff:2:3:6 (1)\n" +
"    │ │ └─● bb::ffff:2:3:12 (1)\n" +
"    │ └─○ bb::ffff:2:3:20/123 (2)\n" +
"    │   ├─● bb::ffff:2:3:22 (1)\n" +
"    │   └─● bb::ffff:2:3:32 (1)\n" +
"    └─○ bb::ffff:2:3:42/127 (2)\n" +
"      ├─● bb::ffff:2:3:42 (1)\n" +
"      └─● bb::ffff:2:3:43 (1)\n",

"\n" +	
"○ ::/0\n" +
"├─● 1::ff:aa:3:4\n" +
"├─● 1::ff:aa:3:12\n" +
"├─● 1::ffff:2:3:4\n" +
"├─● 1::ffff:2:3:5\n" +
"├─● 1::ffff:2:3:6\n" +
"├─● 1::ffff:2:3:12\n" +
"├─● 1::ffff:aa:3:4\n" +
"├─● bb::ffff:2:3:6\n" +
"├─● bb::ffff:2:3:12\n" +
"├─● bb::ffff:2:3:22\n" +
"├─● bb::ffff:2:3:32\n" +
"├─● bb::ffff:2:3:42\n" +
"└─● bb::ffff:2:3:43\n");


	Strings two = new Strings(
			new String[] {"ff80::/8",
				"ff80:8000::/16",
				"ff80:8000::/24",
				"ff80:8000::/32",
				"ff80:8000:c000::/34",
				"ff80:8000:c800::/36",
				"ff80:8000:cc00::/38",
				"ff80:8000:cc00::/40",
			},
"\n" +
"○ ::/0 (8)\n" +
"└─○ ff80::/16 (8)\n" +
"  ├─● ff80:: (1)\n" +
"  └─● ff80:8000::/24 (7)\n" +
"    └─● ff80:8000::/32 (6)\n" +
"      ├─● ff80:8000:: (1)\n" +
"      └─● ff80:8000:c000::/34 (4)\n" +
"        └─○ ff80:8000:c800::/37 (3)\n" +
"          ├─● ff80:8000:c800:: (1)\n" +
"          └─● ff80:8000:cc00::/38 (2)\n" +
"            └─● ff80:8000:cc00::/40 (1)\n",

"\n" +	
"○ ::/0\n" +
"├─● ff80::\n" +
"└─● ff80:8000::/24\n" +
"  └─● ff80:8000::/32\n" +
"    ├─● ff80:8000::\n" +
"    └─● ff80:8000:c000::/34\n" +
"      ├─● ff80:8000:c800::\n" +
"      └─● ff80:8000:cc00::/38\n" +
"        └─● ff80:8000:cc00::/40\n");


	static String testIPAddressTries[][] = {{
				"1.2.3.4",
				"1.2.3.5",
				"1.2.3.6",
				"1.2.3.3",
				"1.2.3.255",
				"2.2.3.5",
				"2.2.3.128",
				"2.2.3.0/24",
				"2.2.4.0/24",
				"2.2.7.0/24",
				"2.2.4.3",
				"1::ffff:2:3:5",
				"1::ffff:2:3:4",
				"1::ffff:2:3:6",
				"1::ffff:2:3:12",
				"1::ffff:aa:3:4",
				"1::ff:aa:3:4",
				"1::ff:aa:3:12",
				"bb::ffff:2:3:6",
				"bb::ffff:2:3:12",
				"bb::ffff:2:3:22",
				"bb::ffff:2:3:32",
				"bb::ffff:2:3:42",
				"bb::ffff:2:3:43", 
			}, {
				"0.0.0.0/8",
				"0.0.0.0/16",
				"0.0.0.0/24",
				"0.0.0.0"
			}, {
				"1.2.3.4"
			}, {
			}, {
				"128.0.0.0"
			}, {
				"0.0.0.0"
			}, {
				"0.0.0.0/0",
				"128.0.0.0/8",
				"128.128.0.0/16",
				"128.128.128.0/24",
				"128.128.128.128"
			}, {
				"0.0.0.0/0",
				"0.0.0.0/8",
				"0.128.0.0/16",
				"0.128.0.0/24",
				"0.128.0.128"
			}, {
				"128.0.0.0/8",
				"128.128.0.0/16",
				"128.128.128.0/24",
				"128.128.128.128"
			}, {
				"0.0.0.0/8",
				"0.128.0.0/16",
				"0.128.0.0/24",
				"0.128.0.128"
			}, {
				"ff80::/8",
				"ff80:8000::/16",
				"ff80:8000::/24",
				"ff80:8000::/32",
				"ff80:8000:c000::/34",
				"ff80:8000:c800::/36",
				"ff80:8000:cc00::/38",
				"ff80:8000:cc00::/40",
			}, {
				"0.0.0.0/0",
				"128.0.0.0/8",
				"128.0.0.0/16",
				"128.0.128.0/24",
				"128.0.128.0"
			}, {
				"0.0.0.0/0",
				"0.0.0.0/8",
				"0.0.0.0/16",
				"0.0.0.0/24",
				"0.0.0.0"
			}, 
			{
				"1.2.3.0",
				"1.2.3.0/31", // consecutive
				"1.2.3.1",
				"1.2.3.0/30",
				"1.2.3.2",
			},
	};
	
	static String testMACTries[][] = {{
				"a:b:c:d:e:f",
				"f:e:c:d:b:a",
				"a:b:c:*:*:*",
				"a:b:c:d:*:*",
				"a:b:c:e:f:*",
			}, {
				"a:b:c:d:e:f",
			}, {
				"a:b:c:d:*:*",
			}, {
			}, {
				"a:a:a:b:c:d:e:f",
				"a:a:f:e:c:d:b:a",
				"a:a:a:b:c:*:*:*",
				"a:a:a:b:c:d:*:*",
				"a:a:a:b:c:b:*:*",
				"a:a:a:b:c:e:f:*",
			}, {
				"*:*:*:*:*:*",
			},
	};
	
	
	void testString(Strings strs) {
		IPv6AddressTrie ipv6Tree = new IPv6AddressTrie();
		createSampleTree(ipv6Tree, strs.addrs);
		String treeStr = ipv6Tree.toString();
		if(!treeStr.contentEquals(strs.treeString)) {
			addFailure("trie string not right, got " + treeStr + " instead of expected " + strs.treeString, ipv6Tree);
		}
		String addedString = ipv6Tree.toAddedNodesTreeString();
		if(!addedString.contentEquals(strs.addedNodeString)) {
			addFailure("trie string not right, got " + addedString + " instead of expected " + strs.addedNodeString, ipv6Tree);
		}
	}
	
	static void testRemove(TestBase testBase, String addrs[]) {
		IPv6AddressTrie ipv6Tree = new IPv6AddressTrie();
		IPv4AddressTrie ipv4Tree = new IPv4AddressTrie();
		
		testRemove(testBase, ipv6Tree, addrs, addrStr -> testBase.createAddress(addrStr).getAddress().toIPv6());
		testRemove(testBase, ipv4Tree, addrs, addrStr -> testBase.createAddress(addrStr).getAddress().toIPv4());
		
		// reverse the address order
		String addrs2[] = addrs.clone();
		for(int i = 0; i < (addrs2.length >> 1); i++) {
			String tmp = addrs2[i];
			addrs2[i] = addrs2[addrs2.length - i - 1];
			addrs2[addrs2.length - i - 1] = tmp;
		}
		
		// both trees should be empty now
		testRemove(testBase, ipv6Tree, addrs, addrStr -> testBase.createAddress(addrStr).getAddress().toIPv6());
		testRemove(testBase, ipv4Tree, addrs, addrStr -> testBase.createAddress(addrStr).getAddress().toIPv4());
	}
	
	static void testRemoveMAC(TestBase testBase, String addrs[]) {
		MACAddressTrie macTree = new MACAddressTrie();
		
		testRemove(testBase, macTree, addrs, addrStr -> testBase.createMACAddress(addrStr).getAddress());
		
		// reverse the address order
		String addrs2[] = addrs.clone();
		for(int i = 0; i < (addrs2.length >> 1); i++) {
			String tmp = addrs2[i];
			addrs2[i] = addrs2[addrs2.length - i - 1];
			addrs2[addrs2.length - i - 1] = tmp;
		}
		
		// tree should be empty now
		testRemove(testBase, macTree, addrs, addrStr -> testBase.createMACAddress(addrStr).getAddress());
		testBase.incrementTestCount();
	}
	
	static <E extends Address> void testRemove(TestBase testBase, 
			AddressTrie<E> tree, String addrs[], Function<String, E> converter) {
		int count = 0;
		ArrayList<E> list = new ArrayList<>(addrs.length);
		HashSet<E> dupChecker = new HashSet<>();
		for(String str : addrs) {
			E addr = converter.apply(str);
			if(addr != null) {
				if(!dupChecker.contains(addr)) {
					dupChecker.add(addr);
					list.add(addr);
					count++;
					tree.add(addr);
				}
			}
		}
		testRemove(testBase, tree, count, list);
	}
	
	static <E extends Address> List<E> collect(String addrs[], Function<String, E> converter) {
		ArrayList<E> list = new ArrayList<>(addrs.length);
		HashSet<E> dupChecker = new HashSet<>();
		for(String str : addrs) {
			E addr = converter.apply(str);
			if(addr != null) {
				if(!dupChecker.contains(addr)) {
					dupChecker.add(addr);
					list.add(addr);
				}
			}
		}
		return list;
	}
	
	static <E extends Address> void testRemove(TestBase testBase, 
			AddressTrie<E> tree, int count, List<E> addrs) {
		AddressTrie<E> tree2 = tree.clone();
		AddressTrie<E> tree3 = tree2.clone();
		AddressTrie<E> tree4 = tree2.clone();
		AddressTrie<E> tree5 = tree4.clone();
		AddressTrie<E> tree6 = tree4.clone();
		tree5.clear();
		tree5.addTrie(tree4.getRoot());
		int nodeSize4 = tree4.nodeSize();
		if(tree4.size() != count) {
			addFailure(testBase, "trie size not right, got " + tree4.size() + " instead of expected " + count, tree4);
		}
		tree4.clear();
		if(tree4.size() != 0) {
			addFailure(testBase, "trie size not zero, got " + tree4.size() + " after clearing trie", tree4);
		}
		if(tree4.nodeSize() != 1) {
			addFailure(testBase, "node size not 1, got " + tree4.nodeSize() + " after clearing trie", tree4);
		}
		if(tree5.size() != count) {
		//if(tree5.size() != count || tree5.size() == 0) {
			addFailure(testBase, "trie size not right, got " + tree5.size() + " instead of expected " + count, tree5);
		}
		if(tree5.nodeSize() != nodeSize4) {
			addFailure(testBase, "trie size not right, got " + tree5.size() + " instead of expected " + nodeSize4, tree5);
		}
		int origSize = tree.size();
		int origNodeSize = tree.nodeSize();
		int size = origSize;
		int nodeSize = origNodeSize;
		Iterator<? extends BinaryTreeNode<E>> iterator = tree.nodeIterator(true);
		while(iterator.hasNext()) {
			BinaryTreeNode<E> node = iterator.next();
			iterator.remove();
			int newSize = tree.size();
			if(size - 1 != newSize) {
				addFailure(testBase, "trie size mismatch, expected " + (size - 1) + " got " + newSize + " when removing node " + node, tree);
			}
			size = newSize;
			newSize = tree.nodeSize();
			if(newSize > nodeSize) {
				addFailure(testBase, "node size mismatch, expected smaller than " + nodeSize + " got " + newSize + " when removing node " + node, tree);
			}
			nodeSize = newSize;
		}
		
		if(tree.size() != 0 || !tree.isEmpty()) {
			addFailure(testBase, "trie size not zero, got " + tree.size() + " after clearing trie", tree);
		}
		if(tree.nodeSize() != 1) {
			addFailure(testBase, "node size not 1, got " + tree.nodeSize() + " after clearing trie", tree);
		}
		
		size = origSize;
		nodeSize = origNodeSize;
		
		
		// now remove by order from array addrs[]
		for(E addr : addrs) {
			if(addr != null) {
				tree2.remove(addr);
				int newSize = tree2.size();
				if(size - 1 != newSize) {
					addFailure(testBase, "trie size mismatch, expected " + (size - 1) + " got " + newSize, tree2);
				}
				size = newSize;
				newSize = tree2.nodeSize();
				if(newSize > nodeSize) {
					addFailure(testBase, "node size mismatch, expected smaller than " + nodeSize + " got " + newSize, tree2);
				}
				nodeSize = newSize;
			}	
		}
		
		
		
		if(tree2.size() != 0 || !tree2.isEmpty()) {
			addFailure(testBase, "trie size not zero, got " + tree2.size() + " after clearing trie", tree2);
		}
		if(tree2.nodeSize() != 1) {
			addFailure(testBase, "node size not 1, got " + tree2.nodeSize() + " after clearing trie", tree2);
		}
		// now remove full subtrees at once
		int addressesRemoved = 0;
		
		for(E addr : addrs) {
			if(addr != null) {
				TrieNode<E> node = tree3.getAddedNode(addr);
				int nodeCountToBeRemoved = 0;
				if(node != null) {
					nodeCountToBeRemoved = 1;
					TrieNode<E> lowerNode = node.getLowerSubNode();
					if(lowerNode != null) {
						nodeCountToBeRemoved += lowerNode.size();
					}
					TrieNode<E> upperNode = node.getUpperSubNode();
					if(upperNode != null) {
						nodeCountToBeRemoved += upperNode.size();
					}
					
				}
				int preRemovalSize = tree3.size();
				
				tree3.removeElementsContainedBy(addr);
				addressesRemoved++;
				
				// we cannot check for smaller tree or node size because many elements might have been already erased
				int newSize = tree3.size();
				if(newSize != preRemovalSize - nodeCountToBeRemoved) {
					addFailure(testBase, "removal size mismatch, expected to remove " + nodeCountToBeRemoved + " but removed " + (preRemovalSize - newSize), tree3);
				}
				if(newSize > origSize - addressesRemoved) {
					addFailure(testBase, "trie size mismatch, expected smaller than " + (origSize - addressesRemoved) + " got " + newSize, tree3);
				}
				newSize = tree3.nodeSize();
				if(newSize > origNodeSize - addressesRemoved && newSize > 1) {
					addFailure(testBase, "node size mismatch, expected smaller than " + (origSize - addressesRemoved) + " got " + newSize, tree3);
				}
			}	
		}
		if(tree3.size() != 0 || !tree3.isEmpty()) {
			addFailure(testBase, "trie size not zero, got " + tree3.size() + " after clearing trie", tree3);
		}
		if(tree3.nodeSize() != 1) {
			addFailure(testBase, "node size not 1, got " + tree3.nodeSize() + " after clearing trie", tree3);
		}
		
		tree6.asSet().removeAll(tree6.asSet().clone());
		if(tree6.size() != 0 || !tree6.isEmpty() || tree6.asSet().size() != 0 || !tree6.asSet().isEmpty()) {
			addFailure(testBase, "trie size not zero, got " + tree6.size() + " after clearing trie with removeAll", tree6);
		}
		
		testBase.incrementTestCount();
	}
	
	static <R extends AddressTrie<T>, T extends Address> void addFailure(TestBase testBase, String str, R trie) {
		testBase.addFailure(new Failure(str, trie));
	}
	
	static void partitionTest(TestBase testBase) {
		String addrs = "1.2.1-15.*";
		IPv4AddressTrie trie = new IPv4AddressTrie();
		IPv4Address addr = testBase.createAddress(addrs).getAddress().toIPv4();
		partitionForTrie(testBase, trie, addr);
	}
	
	static <T extends IPAddress> void partitionForTrie(TestBase testBase, AddressTrie<T> trie, T subnet) {
		Partition.partitionWithSingleBlockSize(subnet).predicateForEach(trie::add);
		if(trie.size() != 15) {
			addFailure(testBase, "partition size unexpected " + trie.size() + ", expected " + 15, trie);
		}
		Map<T, TrieNode<T>> all = Partition.partitionWithSingleBlockSize(subnet).applyForEach(trie::getAddedNode);
		if(all.size() != 15) {
			addFailure(testBase, "map size unexpected " + trie.size() + ", expected " + 15, trie);
		}
		HashMap<T, TrieNode<T>> all2 = new HashMap<>();
		Partition.partitionWithSingleBlockSize(subnet).forEach(addr -> {
			TrieNode<T> node = trie.getAddedNode(addr);
			all2.put(addr, node);
		});
		if(!all.equals(all2)) {
			addFailure(testBase, "maps not equal " + all + " and " + all2, trie);
		}
		trie.clear();
		Partition.partitionWithSpanningBlocks(subnet).predicateForEach(trie::add);
		if(trie.size() != 4) {
			addFailure(testBase,"partition size unexpected " + trie.size() + ", expected " + 4, trie);
		}
		trie.clear();
		Partition.partitionWithSingleBlockSize(subnet).predicateForEach(trie::add);
		Partition.partitionWithSpanningBlocks(subnet).predicateForEach(trie::add);
		if(trie.size() != 18) {
			addFailure(testBase,"partition size unexpected " + trie.size() + ", expected " + 18, trie);
		}
		boolean allAreThere = Partition.partitionWithSingleBlockSize(subnet).predicateForEach(trie::contains);
		boolean allAreThere2 = Partition.partitionWithSpanningBlocks(subnet).predicateForEach(trie::contains);
		if(!(allAreThere && allAreThere2)) {
			addFailure(testBase,"partition contains check failing", trie);
		}
		testBase.incrementTestCount();
	}

	static <R extends AddressTrie<T>, T extends Address> void testIterationContainment(TestBase testBase, R tree) {
		testIterationContainment(testBase, tree, AddressTrie::blockSizeCachingAllNodeIterator, false);
		testIterationContainment(testBase, tree, trie -> trie.containingFirstAllNodeIterator(true), false /* added only */);
		testIterationContainment(testBase, tree, trie -> trie.containingFirstAllNodeIterator(false), false /* added only */);
		testIterationContainment(testBase, tree, trie -> trie.containingFirstIterator(true), true /* added only */);
		testIterationContainment(testBase, tree, trie -> trie.containingFirstIterator(false), true /* added only */);
	}
	
	static <R extends AddressTrie<T>, T extends Address> void testIterationContainment(
			TestBase testBase, 
			R trie, 
			Function<R, CachingIterator<? extends TrieNode<T>, T, Integer>> iteratorFunc,
			boolean addedNodesOnly) {
		CachingIterator<? extends TrieNode<T>, T, Integer> iterator = iteratorFunc.apply(trie);
		while(iterator.hasNext()) {
			BinaryTreeNode<T> next = iterator.next();
			T nextAddr = next.getKey();
			Integer parentPrefix = null;
			BinaryTreeNode<T> parent = next.getParent();
			boolean skipCheck = false;
			if(parent != null) {
				parentPrefix = parent.getKey().getPrefixLength();
				if(addedNodesOnly) {
					if(!parent.isAdded()) {
						skipCheck = true;
					} else {
						parentPrefix = parent.getKey().getPrefixLength();
					}
//					while(parent != null && !parent.isAdded()) {
//						parent = parent.getParent();
//					}
//					if(parent == null) {
//						parentPrefix = null;
//					} else {
//						parentPrefix = parent.getKey().getPrefixLength();
//					}
				}
			}
			Integer cached = iterator.getCached();
			if(!skipCheck && !Objects.equals(cached, parentPrefix)) {
				addFailure(testBase, "mismatched prefix for " + next + ", cached is " + iterator.getCached() + " and expected value is " + parentPrefix, trie);
			}
			Integer prefLen = nextAddr.getPrefixLength();
			iterator.cacheWithLowerSubNode(prefLen);
			iterator.cacheWithUpperSubNode(prefLen);

		}
		testBase.incrementTestCount();
	}
	
	static <R extends AddressTrie<T>, T extends Address> void testIterate(TestBase testBase, R tree) {
		
		testIterate(testBase, tree, trie -> trie.blockSizeNodeIterator(true), AddressTrie::size, true);
		testIterate(testBase, tree, trie -> trie.blockSizeAllNodeIterator(true), AddressTrie::nodeSize, true);
		testIterate(testBase, tree, trie -> trie.blockSizeNodeIterator(false), AddressTrie::size, true);
		testIterate(testBase, tree, trie -> trie.blockSizeAllNodeIterator(false), AddressTrie::nodeSize, true);
		
		testIterate(testBase, tree, AddressTrie::blockSizeCachingAllNodeIterator, AddressTrie::nodeSize, true);
		
		testIterate(testBase, tree, trie -> trie.nodeIterator(true), AddressTrie::size, true);
		testIterate(testBase, tree, trie -> trie.allNodeIterator(true), AddressTrie::nodeSize, true);
		testIterate(testBase, tree, trie -> trie.nodeIterator(false), AddressTrie::size, true);
		testIterate(testBase, tree, trie -> trie.allNodeIterator(false), AddressTrie::nodeSize, true);
		
		testIterate(testBase, tree, trie -> trie.containedFirstIterator(true), AddressTrie::size, true);
		testIterate(testBase, tree, trie -> trie.containedFirstAllNodeIterator(true), AddressTrie::nodeSize, false);
		testIterate(testBase, tree, trie -> trie.containedFirstIterator(false), AddressTrie::size, true);
		testIterate(testBase, tree, trie -> trie.containedFirstAllNodeIterator(false), AddressTrie::nodeSize, false);
		
		testIterate(testBase, tree, trie -> trie.containingFirstIterator(true), AddressTrie::size, true);
		testIterate(testBase, tree, trie -> trie.containingFirstAllNodeIterator(true), AddressTrie::nodeSize, true);
		testIterate(testBase, tree, trie -> trie.containingFirstIterator(false), AddressTrie::size, true);
		testIterate(testBase, tree, trie -> trie.containingFirstAllNodeIterator(false), AddressTrie::nodeSize, true);
		
		testIterate(testBase, tree, trie -> new SpliteratorWrapper<>(trie.nodeSpliterator(true)), AddressTrie::size, false);
		testIterate(testBase, tree, trie -> new SpliteratorWrapper<>(trie.allNodeSpliterator(true)), AddressTrie::nodeSize, false);
		testIterate(testBase, tree, trie -> new SpliteratorWrapper<>(trie.nodeSpliterator(false)), AddressTrie::size, false);
		testIterate(testBase, tree, trie -> new SpliteratorWrapper<>(trie.allNodeSpliterator(false)), AddressTrie::nodeSize, false);
		
		testIterationContainment(testBase, tree);
		
		testBase.incrementTestCount();
	}

	static class SpliteratorWrapper<E> implements Iterator<E> {
		private Spliterator<E> spliterator;
		private E next;
		
		SpliteratorWrapper(Spliterator<E> spliterator) {
			this.spliterator = spliterator;
			if(!spliterator.tryAdvance(e -> { next = e; })) {
				next = null;
			}
		}

		@Override
		public boolean hasNext() {
			return next != null;
		}

		@Override
		public E next() {
			E result = next;
			if(!spliterator.tryAdvance(e -> { next = e; })) {
				next = null;
			}
			return result;
		}
	}
	
	@SuppressWarnings("unchecked")
	static <R extends AddressTrie<T>, T extends Address> void testIterate(
			TestBase testBase, 
			R trie, 
			Function<R, Iterator<? extends BinaryTreeNode<T>>> iteratorFunc, 
			ToIntFunction<R> countFunc,
			boolean removeAllowed) {
		// iterate the tree, confirm the size by counting
		// clone the trie, iterate again, but remove each time, confirm the size
		// confirm trie is empty at the end
		
		if(trie.size() > 0) {
			R clonedTrie = (R) trie.clone();
			TrieNode<T> node = clonedTrie.firstNode();
			T toAdd = node.getKey();
			node.remove();
			Iterator<? extends BinaryTreeNode<T>> modIterator = iteratorFunc.apply(clonedTrie);
			int mod = clonedTrie.size() / 2;
			int i = 0;
			boolean shouldThrow = false;
			try {
				while(modIterator.hasNext()) {
					if(++i == mod) {
						shouldThrow = true;
						clonedTrie.add(toAdd);
					}
					modIterator.next();
					if(shouldThrow) {
						addFailure(testBase, "expected throw ", clonedTrie);
					}
				}
			} catch(ConcurrentModificationException e) {
				if(!shouldThrow) {
					addFailure(testBase, "unexpected throw ", clonedTrie);
				}
			}
		}

		boolean firstTime = true;
		while(true) {
			int expectedSize = countFunc.applyAsInt(trie);
			int actualSize = 0;
			Set<T> set = new HashSet<>();
			Set<BinaryTreeNode<T>> nodeSet = new HashSet<>();
			Iterator<? extends BinaryTreeNode<T>> iterator = iteratorFunc.apply(trie);
			while(iterator.hasNext()) {
				BinaryTreeNode<T> next = iterator.next();
				nodeSet.add(next);
				T nextAddr = next.getKey();
				set.add(nextAddr);
				actualSize++;
				if(!firstTime) {
					try {
						iterator.remove();
						if(!removeAllowed) {
							addFailure(testBase, "removal " + next + " should not be supported", trie);
						} else if(trie.contains(nextAddr)) {
							addFailure(testBase, "after removal " + next + " still in trie ", trie);
						}
					} catch(UnsupportedOperationException e) {
						if(removeAllowed) {
							addFailure(testBase, "removal " + next + " should be supported", trie);
						}
					}
				} else {
					if(next.isAdded()) {
						if(!trie.contains(nextAddr)) {
							addFailure(testBase, "after iteration " + next + " not in trie ", trie);
						} else if(trie.getAddedNode(nextAddr) == null) {
							addFailure(testBase, "after iteration address node for " + nextAddr + " not in trie ", trie);
						}
					} else {
						if(trie.contains(nextAddr)) {
							addFailure(testBase, "non-added node " + next + " in trie ", trie);
						} else if(trie.getNode(nextAddr) == null) {
							addFailure(testBase, "after iteration address node for " + nextAddr + " not in trie ", trie);
						} else if(trie.getAddedNode(nextAddr) != null) {
							addFailure(testBase, "after iteration non-added node for " + nextAddr + " added in trie ", trie);
						}
					}
				}
			}
			if(set.size() != expectedSize) {
				addFailure(testBase, "set count was " + set.size() + " instead of expected " + expectedSize, trie);
			} else if(actualSize != expectedSize) {
				addFailure(testBase, "count was " + actualSize + " instead of expected " + expectedSize, trie);
			}
			trie = (R) trie.clone();
			if(!firstTime) {
				break;
			}
			firstTime = false;
		}
		if(removeAllowed) {
			if(!trie.isEmpty()) {
				addFailure(testBase, "trie not empty, size " + trie.size() + " after removing everything", trie);
			} else if(trie.nodeSize() > 1) {
				addFailure(testBase, "trie node size not 1, " + trie.nodeSize() + " after removing everything", trie);
			} else if(trie.size() > 0) {
				addFailure(testBase, "trie size not 0, " + trie.size() + " after removing everything", trie);
			}
		}
		testBase.incrementTestCount();
	}
	
	static <R extends AddressTrie<T>, T extends Address> void testSpliterate(TestBase testBase, R tree) {
		Function<R, Spliterator<T>> spliteratorFunc = AddressTrie::spliterator;
		testSpliterate(testBase, tree, spliteratorFunc);
		spliteratorFunc = AddressTrie::descendingSpliterator;
		testSpliterate(testBase, tree, spliteratorFunc);
		
	}

	static <R extends AddressTrie<T>, T extends Address> void testSpliterate(TestBase testBase, R tree, Function<R, Spliterator<T>> spliteratorFunc) {
		int size = tree.size();
		testSpliterate(testBase, tree, 0, size, spliteratorFunc);
		testSpliterate(testBase, tree, 1, size, spliteratorFunc);
		testSpliterate(testBase, tree, 5, size, spliteratorFunc);
		testSpliterate(testBase, tree, -1, size, spliteratorFunc);
	}

	private static ExecutorService threadPool = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors(),
	        new ThreadFactory() {
        @Override
		public Thread newThread(Runnable r) {
            Thread t = Executors.defaultThreadFactory().newThread(r);
            t.setDaemon(true);
            return t;
        }
    });
	
	static int spliterateTestCounter = 0;
	
	@SuppressWarnings("unchecked")
	static <R extends AddressTrie<T>, T extends Address> Set<Address> testSpliterate(TestBase testBase, R val, int splitCount, int number, 
			Function<R, Spliterator<T>> spliteratorFunc) {
		
		R modTrie = (R) val.clone();
		ArrayList<Spliterator<T>> modList = new ArrayList<>();
		Spliterator<T> spliterator = spliteratorFunc.apply(modTrie);
		modList.add(spliterator);
		
		spliterateTestCounter++;
		Set<Address> set = Collections.synchronizedSet(new HashSet<>());
		ArrayList<Spliterator<T>> list = new ArrayList<>();
		spliterator = spliteratorFunc.apply(val);
		list.add(spliterator);
		long originalSize = spliterator.getExactSizeIfKnown();
		for(int i = 0; splitCount < 0 || i < splitCount; i++) {
			boolean shouldThrow = false;
			if(i == splitCount - 1 && modTrie.size() > 0) {
				shouldThrow = true;
				modTrie.lastAddedNode().remove();
			}
			try {
				ArrayList<Spliterator<T>> newModList = new ArrayList<>();
				for(Spliterator<T> toSplit : modList) {
					Spliterator<T> split = toSplit.trySplit();
					if(shouldThrow) {
						addFailure(testBase, "expected throw ", modTrie);
					}
					if(split != null) {
						newModList.add(split);
					}
					newModList.add(toSplit);
				}
				modList = newModList;
			} catch(ConcurrentModificationException e) {
				if(!shouldThrow) {
					addFailure(testBase, "unexpected throw ", modTrie);
				}
			}
			
			ArrayList<Spliterator<T>> newList = new ArrayList<>();
			for(Spliterator<T> toSplit : list) {
				Spliterator<T> split = toSplit.trySplit();
				
				if(split != null) {
					newList.add(split);
					long size1 = toSplit.estimateSize();
					if(size1 > 3) {
						long size2 = split.estimateSize();
						if(2 * size1 < size2) {
							addFailure(testBase, "unequal split " + size1 + " and " + size2, val);
						} else if(size2 * 2 < size1) {
							addFailure(testBase, "unequal split " + size1 + " and " + size2, val);
						}
					}
				}
				newList.add(toSplit);
			}
			if(list.size() == newList.size()) {
				for(Spliterator<T> splitter : list) {
					long exactSize = splitter.estimateSize();
					if(exactSize > val.getRoot().getKey().getBitCount() * 2) {
						//if(exactSize > 5) {
						// In a tree with 403 addresses, one spliterator of size 27 could not be split.
						// Need to think a little about that.
						// This is limited by tree depth, because we split based on tree shape,
						// splitting the root at the top to two halves, so max would be 32.
						// 
						addFailure(testBase, "unable to split trie " + splitter + " but size is " + exactSize, val);
					
//unable to split spliterator from ● 129.0.0.0 to ● 128.0.0.0/1 but size is 59, 
//						└─● 128.0.0.0/1 (143) to here
//						  ├─○ 128.0.0.0/7 (12)
//						  │ ├─● 128.0.0.0/8 (11)
//						  │ │ ├─○ 128.0.0.0/14 (5)
//						  │ │ │ ├─● 128.0.0.0/16 (4)
//						  │ │ │ │ ├─● 128.0.0.0 (1)
//						  │ │ │ │ └─● 128.0.128.0/24 (2)
//						  │ │ │ │   └─● 128.0.128.0 (1)
//						  │ │ │ └─● 128.2.3.4 (1)
//						  │ │ └─○ 128.128.0.0/9 (5)
//						  │ │   ├─● 128.128.0.0/16 (3)
//						  │ │   │ └─● 128.128.128.0/24 (2)
//						  │ │   │   └─● 128.128.128.128 (1)
//						  │ │   └─○ 128.192.224.0/24 (2)
//						  │ │     ├─● 128.192.224.64 (1)
//						  │ │     └─● 128.192.224.240 (1)
//						  │ └─● 129.0.0.0 (1) here
//						  └─● 192.0.0.0/2 (130)
// stuff is below here
					}
				}
				break;
			}
			list = newList;
			long newSize = 0;
			for(Spliterator<T> splitter : list) {
				newSize += splitter.estimateSize();
			}
			if(newSize != originalSize) {
				addFailure(testBase, "split size differs, got " + newSize + " but size is " + originalSize, val);
			}
		}
		AtomicInteger counter = new AtomicInteger();
		List<Future<?>> jobs = new ArrayList<Future<?>>(list.size());

		int spliteratorCount = list.size();
		int newSpliteratorCount = 0;
		int subSpliteratorCount = 0;
		
		//System.out.println("We have " + list.size() + " spliterators and size " + val.size() + " and node size " + val.nodeSize());
		while(true) {
			ArrayList<Spliterator<T>> newList = new ArrayList<>();
			int splitsCounter = 0;
			for(Spliterator<T> splitter : list) {
				int ctr = ++splitsCounter;
				int adjustedCtr = spliterateTestCounter % 3 == 0 ? ctr - 1 : ctr; // this means sometimes we will split off the first spliterator, sometimes not the first
				Future<?> job = threadPool.submit(new Runnable() {
					Spliterator<T> toSplit = splitter;
					boolean doTryAdvance = (adjustedCtr % 3) == 0;
					boolean doAdditionalSplit = (adjustedCtr % 6) == 0;
					
					@Override
					public void run() {
						if(doTryAdvance) {
							toSplit.tryAdvance(next -> {
								set.add(next);
								//System.out.println(next + " advance came from " + toSplit);
								counter.incrementAndGet();
							});
							if(doAdditionalSplit) {
								Spliterator<T> split = toSplit.trySplit();
								if(split != null) {
									synchronized(newList) {
										newList.add(split);
									}
								}
							}
						}
						toSplit.forEachRemaining(next -> {
							set.add(next);
							counter.incrementAndGet();
						});
					}
				});
				jobs.add(job);
			}
			try {
				for(Future<?> job : jobs) {
					job.get();
				}
			} catch (InterruptedException | ExecutionException e) {
				addFailure(testBase, "unexpected interruption " + e, val);
			}
			if(newList.size() == 0) {
				break;
			}
			if(newSpliteratorCount == 0) {
				if(spliteratorCount == 0 || subSpliteratorCount > 0) {
					throw new Error();
				}
				newSpliteratorCount += newList.size();
			} else {
				subSpliteratorCount += newList.size();
			}
			list = newList;
		}
		//System.out.println("tested " + spliteratorCount + " spliterators, " + newSpliteratorCount + " split off, " + subSpliteratorCount + " split off from split off");
		if(number < Integer.MAX_VALUE && set.size() != number) {
			addFailure(testBase, "set count was " + set.size() + " instead of expected " + number, val);
		} else if(number < Integer.MAX_VALUE && counter.intValue() != number) {
			addFailure(testBase, "count was " + counter + " instead of expected " + number, val);
		}
		testBase.incrementTestCount();
		return set;
	}
	
	
	void createSampleTree(MACAddressTrie tree, String addrs[]) {
		for(String addr : addrs) {
			MACAddressString addressStr = createMACAddress(addr);
			MACAddress address = addressStr.getAddress();
			tree.add(address);
		}
	}
	
	void createSampleTree(IPv6AddressTrie tree, String addrs[]) {
		for(String addr : addrs) {
			IPAddressString addressStr = createAddress(addr);
			if(addressStr.isIPv6()) {
				IPv6Address address = addressStr.getAddress().toIPv6();
				tree.add(address);
			}
		}
	}
	
	void createSampleTree(IPv6AddressTrie tree, IPAddress addrs[]) {
		for(IPAddress addr : addrs) {
			if(addr.isIPv6()) {
				addr = Partition.checkBlockOrAddress(addr);
				if(addr != null) {
					IPv6Address address = addr.toIPv6();
					tree.add(address);
				}
			}
		}
	}
	
	void createSampleTree(IPv4AddressTrie tree, IPAddress addrs[]) {
		for(IPAddress addr : addrs) {
			if(addr.isIPv4()) {
				addr = Partition.checkBlockOrAddress(addr);
				if(addr != null) {
					IPv4Address address = addr.toIPv4();
					tree.add(address);
				}
			}
		}
	}
	
	void createSampleTree(IPv4AddressTrie tree, String addrs[]) {
		for(String addr : addrs) {
			IPAddressString addressStr = createAddress(addr);
			if(addressStr.isIPv4()) {
				IPv4Address address = addressStr.getAddress().toIPv4();
				tree.add(address);
			}
		}
	}
	
	<R extends AddressTrie<T>, T extends Address> void addFailure(String str, R trie) {
		addFailure(new Failure(str, trie));
	}
	
	<T extends Address> void addFailure(String str, Set<T> set) {
		addFailure(new Failure(str, set));
	}
	
	<T extends Address> void addFailure(String str, Map<T, ?> map) {
		addFailure(new Failure(str, map));
	}
	
	void addFailure(String str, Address address) {
		addFailure(new Failure(str, address));
	}
	
	@SuppressWarnings("unchecked")
	<R extends AddressTrie<T>, T extends Address> void testContains(R trie) {
		if(trie.size() > 0) {
			TrieNode<T> last = trie.getAddedNode(trie.lastAddedNode().getKey());
			if(!trie.contains(last.getKey())) {
				addFailure("failure " + last + " not in trie ", trie);
			}
			last.remove();
			if(trie.contains(last.getKey())) {
				addFailure("failure " + last + " is in trie ", trie);
			}
			trie.add(last.getKey());
			if(!trie.contains(last.getKey())) {
				addFailure("failure " + last + " not in trie ", trie);
			}
		}
		Iterator<? extends TrieNode<T>> iterator = trie.allNodeIterator(true);
		while(iterator.hasNext()) {
			TrieNode<T> next = iterator.next();
			T nextAddr = next.getKey();
			if(next.isAdded()) {
				if(!trie.contains(nextAddr)) {
					addFailure("after iteration " + next + " not in trie ", trie);
				} else if(trie.getAddedNode(nextAddr) == null) {
					addFailure("after iteration address node for " + nextAddr + " not in trie ", trie);
				}
			} else {
				if(trie.contains(nextAddr)) {
					addFailure("non-added node " + next + " in trie ", trie);
				} else if(trie.getNode(nextAddr) == null) {
					addFailure("after iteration address node for " + nextAddr + " not in trie ", trie);
				} else if(trie.getAddedNode(nextAddr) != null) {
					addFailure("after iteration non-added node for " + nextAddr + " added in trie ", trie);
				}
			}
			TrieNode<T> parent = next.getParent();
			Integer parentPrefLen;
			if(parent != null) {
				T parentKey = parent.getKey();
				parentPrefLen = parentKey.getPrefixLength();
			} else {
				parentPrefLen = Integer.valueOf(0);
			}
			Integer prefLen = nextAddr.getPrefixLength();
			T halfwayAddr;
			int halfway;
			if(prefLen == null) {
				prefLen = Integer.valueOf(nextAddr.getBitCount());
			}
			halfway = parentPrefLen + ((prefLen - parentPrefLen) >> 1);
			halfwayAddr = (T) nextAddr.setPrefixLength(halfway).toPrefixBlock();
			
			boolean halfwayIsParent = parent != null && parentPrefLen.intValue() == halfway;
			TrieNode<T> containedBy = trie.elementsContainedBy(halfwayAddr);
			if(halfwayIsParent) {
				if(containedBy != parent) {
					addFailure("containedBy is " + containedBy + " for address " + halfwayAddr + " instead of expected " + parent, trie);
				}
			} else {
				if(containedBy != next) {
					addFailure("containedBy is " + containedBy + " for address " + halfwayAddr + " instead of expected " + next, trie);
				}
			}
			T lpm = trie.longestPrefixMatch(halfwayAddr);
			TrieNode<T> smallestContaining = trie.longestPrefixMatchNode(halfwayAddr);
			TrieNode<T> containing = trie.elementsContaining(halfwayAddr);
			boolean elementsContains = trie.elementContains(halfwayAddr);
			TrieNode<T> addedParent = parent;
			while(addedParent != null && !addedParent.isAdded()) {
				addedParent = addedParent.getParent();
			}
			if(addedParent == null && prefLen == 0 && next.isAdded()) {
				addedParent = next;
			}
			if(addedParent == null) {
				if(containing != null || lpm != null) {
					addFailure("containing is " + containing + " for address " + halfwayAddr + " instead of expected " + null, trie);
				} else if(elementsContains) {
					addFailure("containing is " + elementsContains + " for address " + halfwayAddr + " instead of expected " + !elementsContains, trie);
				}
			} else {
				TrieNode<T> lastContaining = containing;
				while(lastContaining != null) {
					TrieNode<T> lower = lastContaining.getLowerSubNode();
					if(lower != null) {
						lastContaining = lower;
					} else {
						TrieNode<T> upper = lastContaining.getUpperSubNode();
						if(upper != null) {
							lastContaining = upper;
						} else {
							break;
						}
					}
				}
				if(lastContaining == null || !lastContaining.equals(addedParent)) {
					addFailure("containing ends with " + lastContaining + " for address " + halfwayAddr + " instead of expected " + addedParent, trie);
				} else if(!lastContaining.equals(smallestContaining)) {
					addFailure("containing ends with " + lastContaining + " for address " + halfwayAddr + " instead of expected smallest containing " + smallestContaining, trie);
				} else if(lastContaining.getKey() != lpm) {
					addFailure("containing ends with addr " + lastContaining.getKey() + " for address " + halfwayAddr + " instead of expected " + lpm, trie);
				}
				if(!elementsContains) {
					addFailure("containing is " + elementsContains + " for address " + halfwayAddr + " instead of expected " + !elementsContains, trie);
				}
			}
		}
		incrementTestCount();
	}
	
	
	
	@SuppressWarnings("unchecked")
	<R extends AddressTrie<T>, T extends Address> void testEdges(R trie, List<T> addrs) {
		R trie2 = (R) trie.clone();
		for(T addr : addrs) {
			trie.add(addr);
		}
		int i = 0;
		List<TrieNode<T>> ordered = new ArrayList<>(addrs.size());
		for(T addr : trie) {
			if(i % 2 == 0) {
				trie2.add(addr);
			}
			i++;
			ordered.add(trie.getAddedNode(addr));
		}
		i = 0;
		Iterator<? extends TrieNode<T>> nodeIter = trie.nodeIterator(true);
		int treeSize = trie.size();
		for(T addr : trie) {
			TrieNode<T> node = nodeIter.next();
			TrieNode<T> floor = trie2.floorAddedNode(addr);
			TrieNode<T> lower = trie2.lowerAddedNode(addr);
			TrieNode<T> ceiling = trie2.ceilingAddedNode(addr);
			TrieNode<T> higher = trie2.higherAddedNode(addr);
			if(i == 0) {
				if(node != trie.firstAddedNode()) {
					addFailure("wrong first, got " + trie.firstAddedNode() + " not " + node, trie);
				}
			} else if(i == treeSize - 1) {
				if(node != trie.lastAddedNode()) {
					addFailure("wrong last, got " + trie.lastAddedNode() + " not " + node, trie);
				}
			}
			if(i % 2 == 0) {
				// in the second trie
				if(!floor.equals(node)) {
					addFailure("wrong floor, got " + floor + " not " + node, trie);
				} else if(!ceiling.equals(node)) {
					addFailure("wrong ceiling, got " + ceiling + " not " + node, trie);
				} else {
					if(i > 0) {
						TrieNode<T> expected = ordered.get(i - 2);
						if(!lower.equals(expected)) {
							addFailure("wrong lower, got " + lower + " not " + expected, trie);
						}
					} else {
						if(lower != null) {
							addFailure("wrong lower, got " + lower + " not null", trie);
						}
					}
					if(i < ordered.size() - 2) {
						TrieNode<T> expected = ordered.get(i + 2);
						if(!higher.equals(expected)) {
							addFailure("wrong higher, got " + higher + " not " + expected, trie);
						}
					} else {
						if(higher != null) {
							addFailure("wrong higher, got " + higher + " not null", trie);
						}
					}
				}
			} else {
				// not in the second trie
				if(i > 0) {
					TrieNode<T> expected = ordered.get(i - 1);
					if(!lower.equals(expected)) {
						addFailure("wrong lower, got " + lower + " not " + expected, trie);
					} else if(!lower.equals(floor)) {
						addFailure("wrong floor, got " + floor + " not " + expected, trie);
					}
				} else {
					if(lower != null) {
						addFailure("wrong lower, got " + lower + " not null", trie);
					} else if(floor != null) {
						addFailure("wrong floor, got " + floor + " not null", trie);
					}
				}
				if(i < ordered.size() - 1) {
					TrieNode<T> expected = ordered.get(i + 1);
					if(!higher.equals(expected)) {
						addFailure("wrong higher, got " + higher + " not " + expected, trie);
					} else if(!higher.equals(ceiling)) {
						addFailure("wrong ceiling, got " + ceiling + " not " + expected, trie);
					}
				} else {
					if(higher != null) {
						addFailure("wrong higher, got " + higher + " not null", trie);
					} else if(ceiling != null) {
						addFailure("wrong ceiling, got " + ceiling + " not null", trie);
					}
				}
			}
			i++;
		}
		incrementTestCount();
	}
	
	// pass in an empty trie
	@SuppressWarnings("unchecked")
	<R extends AddressTrie<T>, T extends Address> void testAdd(R trie, List<T> addrs) {
		R trie2 = (R) trie.clone(), trie3 = (R) trie.clone(), trie4 = (R) trie.clone();
		int k = 0;
		for(T addr : addrs) {
			if(++k % 2 == 0) {
				boolean added = trie.add(addr);
				if(!added) {
					addFailure("trie empty, adding " + addr + " should succeed ", trie);
				}
			} else {
				TrieNode<T> node = trie.addNode(addr);
				if(node == null || !node.getKey().equals(addr)) {
					addFailure("trie empty, adding " + addr + " should succeed ", trie);
				}
			}
		}
		if(trie.size() != addrs.size()) {
			addFailure("trie size incorrect: " + trie.size() + ", not " + addrs.size(), trie);
		}
		TrieNode<T> node = trie.getRoot();
		int i = 0;
		for(; i < addrs.size() / 2; i++) {
			trie2.add(addrs.get(i));
		}
		for(; i < addrs.size(); i++) {
			trie3.add(addrs.get(i));
		}
		trie2.addTrie(node);
		trie3.addTrie(node);
		trie4.addTrie(node);
		if(!trie.equals(trie2)) {
			addFailure("tries not equal: " + trie + " and " + trie2, trie);
		}
		if(!trie3.equals(trie2)) {
			addFailure("tries not equal: " + trie3 + " and " + trie2, trie);
		}
		if(!trie3.equals(trie4)) {
			addFailure("tries not equal: " + trie3 + " and " + trie4, trie);
		}
		incrementTestCount();
	}
	
	@SuppressWarnings("unchecked")
	<R extends AssociativeAddressTrie<T,V>, T extends Address, V> void testMap(R trie, List<T> addrs,
			IntFunction<V> valueProducer, Function<V,V> mapper) {
		
		
		// put tests
		R trie2 = (R) trie.clone();
		R trie3 = (R) trie.clone();
		R trie4 = (R) trie.clone();
		int i = 0;
		for(T addr : addrs) {
			trie.put(addr, valueProducer.apply(i));
			i++;
		}
		i = 0;
		for(T addr : addrs) {
			V v = trie.get(addr);
			V expected = valueProducer.apply(i);
			if(!v.equals(expected)) {
				addFailure("get mismatch, got " + v + " not " + expected, trie);
			}
			i++;
		}
		
		// all trie2 from now on
		i = 0;
		trie2.putTrie(trie.getRoot());
		for(T addr : addrs) {
			V v = trie2.get(addr);
			V expected = valueProducer.apply(i);
			if(!v.equals(expected)) {
				addFailure("get mismatch, got " + v + " not " + expected, trie2);
			}
			if(i % 2 == 0) {
				trie2.remove(addr);
			}
			i++;
		}
		if(trie2.size() != (addrs.size() >> 1)) {
			addFailure("got size mismatch, got " + trie2.size() + " not " + (addrs.size() >> 1), trie2);
		}
		i = 0;
		trie2.putTrie(trie.getRoot());
		for(T addr : addrs) {
			V v = trie2.get(addr);
			V expected = valueProducer.apply(i);
			if(!v.equals(expected)) {
				addFailure("get mismatch, got " + v + " not " + expected, trie2);
			}
			i++;
		}
		if(trie2.size() != addrs.size()) {
			addFailure("got size mismatch, got " + trie2.size() + " not " + addrs.size(), trie2);
		}
		i = 0;
		for(T addr : addrs) {
			if(i % 2 == 0) {
				boolean b = trie2.remove(addr);
				if(!b) {
					addFailure("remove should have succeeded", trie2);
				}
				b = trie2.remove(addr);
				if(b) {
					addFailure("remove should not have succeeded", trie2);
				}
			}
			i++;
		}
		i = 0;
		for(T addr : addrs) {
			boolean res = trie2.putNew(addr, valueProducer.apply(i));
			if(res != (i % 2 == 0)) {
				addFailure("putNew mismatch", trie2);
			}
			i++;
		}
		if(trie2.size() != addrs.size()) {
			addFailure("got size mismatch, got " + trie.size() + " not " + addrs.size(), trie2);
		}
		i = 0;
		for(T addr : addrs) {
			boolean res = trie2.putNew(addr, valueProducer.apply(i + 1));
			if(res) {
				addFailure("putNew mismatch", trie2);
			}
			i++;
		}
		if(trie2.size() != addrs.size()) {
			addFailure("got size mismatch, got " + trie.size() + " not " + addrs.size(), trie2);
		}
		i = 0;
		for(T addr : addrs) {
			V v = trie2.get(addr);
			V expected = valueProducer.apply(i + 1);
			if(!v.equals(expected)) {
				addFailure("got mismatch, got " + v + " not " + expected, trie);
			}
			i++;
		}
		i = 0;
		for(T addr : addrs) {
			V v = trie2.put(addr, valueProducer.apply(i));
			V expected = valueProducer.apply(i + 1);
			if(!v.equals(expected)) {
				addFailure("got mismatch, got " + v + " not " + expected, trie);
			}
			v = trie2.get(addr);
			expected = valueProducer.apply(i);
			if(!v.equals(expected)) {
				addFailure("got mismatch, got " + v + " not " + expected, trie);
			}
			i++;
		}
		
		i = 0;
		int k = 0;
		for(T addr : addrs) {
			if(i % 2 == 0) {
				boolean b = trie2.remove(addr);
				if(!b) {
					addFailure("remove should have succeeded", trie2);
				}
			}
			// the reason for the (i % 8 == 1) is that the existing value is already valueProducer.apply(i), 
			// so half the time we are re-adding the existing value, 
			// half the time we are changing to a new value
			V value = (i % 4 == 1) ? ((i % 8 == 1) ? valueProducer.apply(i + 1) : valueProducer.apply(i)) : null;
			TrieNode<T> node = trie2.remap(addr, val -> {
				if(val == null) {
					return valueProducer.apply(0);
				} else {
					return value;
				}
			});
			//System.out.println(node);
			if(node == null || !node.getKey().equals(addr)) {
				addFailure("got unexpected return, got " + node, trie2);
			}
			if(i % 2 != 0 && value == null) {
				k++;
			}
			i++;
		}
		if(trie2.size() + k != addrs.size()) {
			addFailure("got size mismatch, got " + trie2.size() + " not " + (addrs.size() - k), trie2);
		}
		i = 0;
		for(T addr : addrs) {
			V v = trie2.get(addr);
			V expected;
			if(i % 2 == 0) {
				expected = valueProducer.apply(0);
			} else if(i % 4 == 1) {
				if(i % 8 == 1) {
					expected = valueProducer.apply(i + 1);
				} else {
					expected = valueProducer.apply(i);
				}
			} else {
				expected = null;
			}
			if(!Objects.equals(v, expected)) {
				addFailure("got mismatch, got " + v + " not " + expected, trie);
			}
			i++;
		}
		
		i = 0;
		for(T addr : addrs) {
			trie2.remapIfAbsent(addr, () -> {
				return valueProducer.apply(1);
			}, false);
			i++;
		}
		if(trie2.size() != addrs.size()) {
			addFailure("got size mismatch, got " + trie2.size() + " not " + addrs.size(), trie2);
		}
		i = 0;
		for(T addr : addrs) {
			V v = trie2.get(addr);
			V expected;
			if(i % 2 == 0) {
				expected = valueProducer.apply(0);
			} else if(i % 4 == 1) {
				if(i % 8 == 1) {
					expected = valueProducer.apply(i + 1);
				} else {
					expected = valueProducer.apply(i);
				}
			} else {
				// remapped
				expected = valueProducer.apply(1);
			}
			if(!Objects.equals(v, expected)) {
				addFailure("got mismatch, got " + v + " not " + expected, trie);
			}
			i++;
		}
		if(trie2.size() != addrs.size()) {
			addFailure("got size mismatch, got " + trie2.size() + " not " + addrs.size(), trie2);
		}
		i = 0;
		for(T addr : addrs) {
			if(i % 2 == 0) {
				trie2.getNode(addr).remove();
			}
			i++;
		}
		if(trie2.size() != (addrs.size() >> 1)) {
			addFailure("got size mismatch, got " + trie2.size() + " not " + (addrs.size() >> 1), trie2);
		}
		i = 0;
		for(T addr : addrs) {
			TrieNode<T> node = trie2.remapIfAbsent(addr, () -> {
				return null;
			}, false);
			if((node == null) != (i % 2 == 0)) {
				addFailure("got unexpected return, got " + node, trie2);
			}
			//System.out.println(node);
			i++;
		}
		if(trie2.size() != (addrs.size() >> 1)) {
			addFailure("got size mismatch, got " + trie2.size() + " not " + (addrs.size() >> 1), trie2);
		}
		i = 0;
		for(T addr : addrs) {
			TrieNode<T> node = trie2.remapIfAbsent(addr, () -> {
				return null;
			}, true);
			if(node == null || !node.getKey().equals(addr)) {
				addFailure("got unexpected return, got " + node, trie2);
			}
			i++;
		}
		if(trie2.size() != addrs.size()) {
			addFailure("got size mismatch, got " + trie2.size() + " not " + addrs.size(), trie2);
		}
		
		i = 0;
		for(T addr : addrs) {
			V v = trie2.get(addr);
			V expected;
			if(i % 2 == 0) {
				expected = null;
			} else if(i % 4 == 1) {
				if(i % 8 == 1) {
					expected = valueProducer.apply(i + 1);
				} else {
					expected = valueProducer.apply(i);
				}
			} else {
				expected = valueProducer.apply(1);
			}
			if(!Objects.equals(v, expected)) {
				addFailure("got mismatch, got " + v + " not " + expected, trie);
			}
			i++;
		}
		
		AssociativeAddressTrie<T, V> trie5 = trie2.clone();
		AssociativeAddressTrie<T, V> trie6 = trie2.clone();
		AssociativeAddressTrie<T, V> trie7 = trie2.clone();
		AssociativeAddressTrie<T, V> trie8 = trie2.clone();
		
		AddressTrieMap<T, V> map = trie6.asMap();
		i = 0;
		for(T addr : addrs) {
			int index = i;
			V v = map.computeIfAbsent(addr, key -> {
				if(index % 2 != 0) {
					throw new Error();
				}
				return valueProducer.apply(22);
			});
			V expected;
			if(i % 2 == 0) {
				expected = valueProducer.apply(22);
			} else if(i % 4 == 1) {
				if(i % 8 == 1) {
					expected = valueProducer.apply(i + 1);
				} else {
					expected = valueProducer.apply(i);
				}
			} else {
				expected = valueProducer.apply(1);
			}
			if(!Objects.equals(v, expected)) {
				addFailure("got mismatch, got " + v + " not " + expected, trie6);
			}
			i++;
		}
		if(trie2.size() != addrs.size()) {
			addFailure("got size mismatch, got " + trie2.size() + " not " + addrs.size(), trie6);
		}
		i = 0;
		for(T addr : addrs) {
			V v = trie6.get(addr);
			V expected;
			if(i % 2 == 0) {
				expected = valueProducer.apply(22);
			} else if(i % 4 == 1) {
				if(i % 8 == 1) {
					expected = valueProducer.apply(i + 1);
				} else {
					expected = valueProducer.apply(i);
				}
			} else {
				expected = valueProducer.apply(1);
			}
			if(!Objects.equals(v, expected)) {
				addFailure("got mismatch, got " + v + " not " + expected, trie6);
			}
			i++;
		}
		
		map = trie5.asMap();
		i = 0;
		for(T addr : addrs) {
			V v = map.putIfAbsent(addr, valueProducer.apply(22));
			V expected;
			if(i % 2 == 0) {
				expected = valueProducer.apply(22);
			} else if(i % 4 == 1) {
				if(i % 8 == 1) {
					expected = valueProducer.apply(i + 1);
				} else {
					expected = valueProducer.apply(i);
				}
			} else {
				expected = valueProducer.apply(1);
			}
			if(!Objects.equals(v, expected)) {
				addFailure("got mismatch, got " + v + " not " + expected, trie5);
			}
			i++;
		}
		if(trie2.size() != addrs.size()) {
			addFailure("got size mismatch, got " + trie2.size() + " not " + addrs.size(), trie5);
		}
		i = 0;
		for(T addr : addrs) {
			V v = trie5.get(addr);
			V expected;
			if(i % 2 == 0) {
				expected = valueProducer.apply(22);
			} else if(i % 4 == 1) {
				if(i % 8 == 1) {
					expected = valueProducer.apply(i + 1);
				} else {
					expected = valueProducer.apply(i);
				}
			} else {
				expected = valueProducer.apply(1);
			}
			if(!Objects.equals(v, expected)) {
				addFailure("got mismatch, got " + v + " not " + expected, trie5);
			}
			i++;
		}
		
		// compute
		
		map = trie7.asMap();
		i = 0;
		for(T addr : addrs) {
			V v = map.compute(addr, (key, val) -> {
				return mapper.apply(val);
			});
			V expected;
			if(i % 2 == 0) {
				expected = mapper.apply(null);
			} else if(i % 4 == 1) {
				if(i % 8 == 1) {
					expected = mapper.apply(valueProducer.apply(i + 1));
				} else {
					expected = mapper.apply(valueProducer.apply(i));
				}
			} else {
				expected = mapper.apply(valueProducer.apply(1));
			}
			if(!Objects.equals(v, expected)) {
				addFailure("got mismatch, got " + v + " not " + expected, trie7);
			}
			i++;
		}
		if(trie2.size() != addrs.size()) {
			addFailure("got size mismatch, got " + trie2.size() + " not " + addrs.size(), trie7);
		}
		i = 0;
		for(T addr : addrs) {
			V v = trie7.get(addr);
			V expected;
			if(i % 2 == 0) {
				expected = mapper.apply(null);
			} else if(i % 4 == 1) {
				if(i % 8 == 1) {
					expected = mapper.apply(valueProducer.apply(i + 1));
				} else {
					expected = mapper.apply(valueProducer.apply(i));
				}
			} else {
				expected = mapper.apply(valueProducer.apply(1));
			}
			if(!Objects.equals(v, expected)) {
				addFailure("got mismatch, got " + v + " not " + expected, trie7);
			}
			i++;
		}
		if(trie7.size() != addrs.size()) {
			addFailure("got size mismatch, got " + trie7.size() + " not " + addrs.size(), trie7);
		}
		i = 0;
		for(T addr : addrs) {
			map.compute(addr, (key, val) -> {
				return null;
			});
		}
		if(trie7.size() != 0) {
			addFailure("got size mismatch, got " + trie7.size() + " not " + 0, trie8);
		}

		map = trie8.asMap();
		i = 0;
		for(T addr : addrs) {
			V v = map.merge(addr, valueProducer.apply(33), (oldVal, suppliedVal) -> {
				if(oldVal == null) {
					return suppliedVal;
				}
				return mapper.apply(suppliedVal);
			});
			V expected;
			if(i % 2 == 0) {
				expected = valueProducer.apply(33);
			} else {
				expected = mapper.apply(valueProducer.apply(33));
			}
			if(!Objects.equals(v, expected)) {
				addFailure("got mismatch, got " + v + " not " + expected, trie8);
			}
			i++;
		}
		if(trie8.size() != addrs.size()) {
			addFailure("got size mismatch, got " + trie8.size() + " not " + addrs.size(), trie8);
		}
		R trie9 = (R) trie8.clone();
		i = 0;
		for(T addr : addrs) {
			V v = trie8.get(addr);
			V expected;
			if(i % 2 == 0) {
				expected = valueProducer.apply(33);
			} else {
				expected = mapper.apply(valueProducer.apply(33));
			}
			if(!Objects.equals(v, expected)) {
				addFailure("got mismatch, got " + v + " not " + expected, trie8);
			}
			i++;
		}
		if(trie8.size() != addrs.size()) {
			addFailure("got size mismatch, got " + trie8.size() + " not " + addrs.size(), trie8);
		}
		i = 0;
		for(T addr : addrs) {
			map.merge(addr, valueProducer.apply(33), (oldVal, suppliedVal) -> {
				return null;
			});
		}
		if(trie8.size() != 0) {
			addFailure("got size mismatch, got " + trie8.size() + " not " + 0, trie8);
		}
		
		HashSet<V> keySet = new HashSet<>();
		class Count {
			int count;
		}
		Count c = new Count();
		trie9.asMap().forEach((key, val) -> {
			c.count++;
			keySet.add(val);
		});
		if(c.count != trie9.size()) {
			addFailure("got count size mismatch, got " + c.count + " not " + trie9.size(), trie8);
		}
		if(trie9.size() != addrs.size()) {
			addFailure("got size mismatch, got " + trie9.size() + " not " + addrs.size(), trie9);
		}
		if(keySet.size() != Math.min(trie9.asMap().size(), 2)) {
			addFailure("got set size mismatch, got " + keySet.size() + " not " + Math.min(trie9.asMap().size(), 2), trie9);
		}
		
		for(T addr : addrs) {
			V v = trie9.asMap().replace(addr, valueProducer.apply(44));
			V expected = valueProducer.apply(33);
			if(!Objects.equals(v, expected)) {
				addFailure("got mismatch, got " + v + " not " + expected, trie9);
			}
			expected = valueProducer.apply(44);
			v = trie9.asMap().get(addr);
			if(!Objects.equals(v, expected)) {
				addFailure("got mismatch, got " + v + " not " + expected, trie9);
			}
			
			boolean b = trie9.asMap().replace(addr, valueProducer.apply(11), valueProducer.apply(55));
			expected = valueProducer.apply(44);
			v = trie9.asMap().get(addr);
			if(!Objects.equals(v, expected) || b) {
				addFailure("got mismatch, got " + v + " not " + expected, trie9);
			}
			
			b = trie9.asMap().replace(addr, valueProducer.apply(44), valueProducer.apply(55));
			expected = valueProducer.apply(55);
			v = trie9.asMap().get(addr);
			if(!Objects.equals(v, expected) || !b) {
				addFailure("got mismatch, got " + v + " not " + expected, trie9);
			}
			
			b = trie9.asMap().remove(addr, valueProducer.apply(11));
			expected = valueProducer.apply(55);
			v = trie9.asMap().get(addr);
			if(!Objects.equals(v, expected) || b) {
				addFailure("got mismatch, got " + v + " not " + expected, trie9);
			}
			
			b = trie9.asMap().remove(addr, valueProducer.apply(55));
			expected = null;
			v = trie9.asMap().get(addr);
			if(!Objects.equals(v, expected) || !b) {
				addFailure("got mismatch, got " + v + " not " + expected, trie9);
			}

			break;
		}
		
		trie9.asMap().replaceAll((key, oldVal) -> {
			if(oldVal.equals(valueProducer.apply(33))) {
				return valueProducer.apply(88);
			}
			return valueProducer.apply(99);
		});
		
		i = 0;
		for(T addr : addrs) {
			V v = trie9.get(addr);
			V expected;
			if(i == 0) {
				expected = null;
			} else if(i % 2 == 0) {
				expected = valueProducer.apply(88);
			} else {
				expected = valueProducer.apply(99);
			}
			if(!Objects.equals(v, expected)) {
				addFailure("got mismatch, got " + v + " not " + expected, trie8);
			}
			i++;
		}
		if(trie9.size() != Math.max(0, addrs.size() - 1)) {
			addFailure("got size mismatch, got " + trie8.size() + " not " + addrs.size(), trie9);
		}
		testSerialize(trie9);
		
		AssociativeAddressTrie<T, V> trie10 = trie9.clone();
		if(trie10.size() != trie9.size()) {
			addFailure("got size mismatch, got " + trie10.size() + " not " + trie9.size(), trie9);
		}
		if(addrs.size() > 0) {
			// put first back in
			V newVal = valueProducer.apply(77);
			T first = addrs.get(0);
			V v = trie10.put(first, newVal);
			if(v != null) {
				addFailure("unexpectedly got " + v + " for " + first + ", not null", trie10);
			}
			v = trie10.get(first);
			if(!v.equals(newVal)) {
				addFailure("unexpectedly got " + v + " for " + first + ", not " + newVal, trie10);
			}
			
			// remove it and put it back
			v = trie10.asMap().remove(first);
			if(!v.equals(newVal)) {
				addFailure("unexpectedly got " + v + " for " + first + ", not " + newVal, trie10);
			}
			v = trie10.put(first, newVal);
			if(v != null) {
				addFailure("unexpectedly got " + v + " for " + first + ", not null", trie10);
			}
			v = trie10.get(first);
			if(!v.equals(newVal)) {
				addFailure("unexpectedly got " + v + " for " + first + ", not " + newVal, trie10);
			}

			AssociativeTrieNode<T, V> node = trie10.getAddedNode(first);
			boolean result = trie10.asMap().entrySet().contains(node);
			if(!result) {
				addFailure("unexpectedly could not find " + first + " in entry set", trie10);
			}
			result = trie10.asMap().containsValue(newVal);
			if(!result) {
				addFailure("unexpectedly could not find " + first + " from entry set", trie10);
			}
			AssociativeTrieNode<T, V> oldNode = node.clone();
			//BiFunction<? super K, ? super V, ? extends V> remappingFunction
			V changedVal = valueProducer.apply(76);
			trie10.asMap().computeIfPresent(first, (key, val) -> {
				return changedVal;
			});
			if(!node.getValue().equals(changedVal)) {
				addFailure("unexpectedly node value " + node.getValue() + " not remapped to " + valueProducer.apply(76), trie10);
			}
			if(!oldNode.getValue().equals(newVal)) {
				addFailure("unexpectedly old node value " + node.getValue() + " not remapped to " + newVal, trie10);
			}

			// after remapping it, we should not be able to remove it based on the old value
			result = trie10.asMap().entrySet().remove(oldNode);
			if(result) {
				addFailure("unexpectedly could remove " + first + " from entry set", trie10);
			}
			result = trie10.asMap().entrySet().contains(oldNode);
			if(result) {
				addFailure("unexpectedly could find " + first + " in entry set after removed", trie10);
			}
			result = trie10.asMap().containsValue(oldNode.getValue());
			if(result) {
				addFailure("unexpectedly could find " + first + " from entry set", trie10);
			}
			
			// but we should be able to find and remove it, based on the new val
			
			result = trie10.asMap().entrySet().contains(node);
			if(!result) {
				addFailure("unexpectedly could not find " + first + " in entry set", trie10);
			}
			result = trie10.asMap().containsValue(changedVal);
			if(!result) {
				addFailure("unexpectedly could not remove " + first + " from entry set", trie10);
			}
			result = trie10.asMap().entrySet().remove(node);
			if(!result) {
				addFailure("unexpectedly could not remove " + first + " from entry set", trie10);
			}
			result = trie10.asMap().entrySet().contains(node);
			if(result) {
				addFailure("unexpectedly could find " + first + " in entry set after removed", trie10);
			}
			result = trie10.asMap().containsValue(changedVal);
			if(result) {
				addFailure("unexpectedly could not remove " + first + " from entry set", trie10);
			}
		}
		
		if(trie10.size() > 0) {
			R trie11 = (R) trie10.clone();
			R trie12 = (R) trie9.clone();
			
			T last = addrs.get(addrs.size() - 1);
			trie12.remove(last);
			
			trie11.asMap().entrySet().removeAll(trie12.asMap().entrySet());
			if(trie11.size() != 1) {
				addFailure("got size mismatch, got " + trie11.size() + " not " + 1, trie11);
			}
		}
		
		trie10.asMap().entrySet().removeAll(trie9.asMap().entrySet());
		if(trie10.size() != 0) {
			addFailure("got size mismatch, got " + trie10.size() + " not " + trie9.size(), trie9);
		}

		AssociativeTrieNode<T,V> firstNode = null;
		try {
			for(T addr : addrs) {
				AssociativeTrieNode<T,V> node = trie2.getAddedNode(addr);
				firstNode = node;
				trie2.remapIfAbsent(addr, () -> {
					node.remove();
					return valueProducer.apply(1);
				}, false);
				addFailure("should have thrown", trie2);
				i++;
			}
		} catch(ConcurrentModificationException e) {
			boolean b = trie2.putNew(firstNode.getKey(), firstNode.getValue());
			if(!b) {
				addFailure("should have added", trie2);
			}
		}
		
		try {
			for(T addr : addrs) {
				AssociativeTrieNode<T,V> node = trie2.getAddedNode(addr);
				firstNode = node;
				trie2.remap(addr, val -> {
					node.remove();
					return valueProducer.apply(1);
				});
				addFailure("should have thrown", trie2);
				i++;
			}
		} catch(ConcurrentModificationException e) {
			boolean b = trie2.putNew(firstNode.getKey(), firstNode.getValue());
			if(!b) {
				addFailure("should have added", trie2);
			}
		}
		
		// all trie3 from now on
		i = 0;
		map = trie3.asMap();
		for(T addr : addrs) {
			map.put(addr, valueProducer.apply(i));
			i++;
		}
		i = 0;
		for(T addr : addrs) {
			V v = map.get(addr);
			V expected = valueProducer.apply(i);
			if(!v.equals(expected)) {
				addFailure("got map mismatch, got " + v + " not " + expected, trie3);
			}
			i++;
		}
		if(trie3.size() != addrs.size()) {
			addFailure("got size mismatch, got " + trie3.size() + " not " + addrs.size(), trie3);
		}
		
		// all trie4 from now on
		for(T addr : addrs) {
			AssociativeTrieNode<T, V> node = trie4.putNode(addr, valueProducer.apply(i));
			if(!node.getValue().equals(valueProducer.apply(i))) {
				addFailure("got putNode mismatch, got " + node.getValue() + " not " + valueProducer.apply(i), trie);
			}
			i++;
			
		}
		if(trie4.size() != addrs.size()) {
			addFailure("got size mismatch, got " + trie4.size() + " not " + addrs.size(), trie4);
		}
		// end put tests

		//i = 0;
		List<TrieNode<T>> ordered = new ArrayList<>(addrs.size());
		for(T addr : trie) {
			//i++;
			ordered.add(trie.getAddedNode(addr));
		}

		NavigableSet<T> set = new WrappedMap<T,V>(trie.asMap(), valueProducer.apply(0));
		testNavSet(trie, ordered, set);
		
		set = new AnotherWrappedMap<T,V>(trie.asMap(), valueProducer.apply(0));
		testNavSet(trie, ordered, set);
		
		set = trie.asSet();
		testNavSet(trie, ordered, set);
	}
	
	<R extends AddressTrie<T>, T extends Address> void testSet(R trie, List<T> addrs) {
		for(T addr : addrs) {
			trie.add(addr);
		}
		List<TrieNode<T>> ordered = new ArrayList<>(addrs.size());
		for(T addr : trie) {
			ordered.add(trie.getAddedNode(addr));
		}

		AddressTrieSet<T> set = trie.asSet();
		testNavSet(trie, ordered, set);
		incrementTestCount();
	}

	// this is non-bounded test code
	private <R extends AddressTrie<T>, T extends Address> void testNavSet(R trie, List<TrieNode<T>> ordered,
			NavigableSet<T> set) {
		if(ordered.size() != set.size()) {
			addFailure("size mismatch, " + set.size() + " does not match expected " + ordered.size(), trie);
		}
		if(ordered.size() > 0) {
			if(!ordered.get(ordered.size() - 1).getKey().equals(set.last())) {
				addFailure("last in set " + set.last() + " does not match expected " + ordered.get(ordered.size() - 1), trie);
			}
		} else {
			try {
				set.last();
				addFailure("last in set " + set.last() + " unexpected", trie);
			} catch(NoSuchElementException e) {}
			try {
				set.first();
				addFailure("last in set " + set.first() + " unexpected", trie);
			} catch(NoSuchElementException e) {}
		}
		List<T> orderedAddrs = new ArrayList<T>();
		for(TrieNode<T> n : ordered) {
			orderedAddrs.add(n.getKey());
		}
		testContainment(orderedAddrs, set);
	}

	@SuppressWarnings("unchecked")
	<R extends AddressTrie<T>, T extends Address> void testContainment(
			T address, List<T> ordered, NavigableSet<T> set) {
		ArrayList<T> containing = new ArrayList<T>();
		if(set instanceof AddressTrieSet) {
			AddressTrieSet<T> trieSet = (AddressTrieSet<T>) set;
			AddressTrie<T> trie = trieSet.asTrie();
			TrieNode<T> node = trie.getAddedNode(address);
			containing.add(address);
			if(node == null) {
				addFailure("should have found node for " + address, set);
			} else {
				TrieNode<T> parent = node.getParent();
				while(parent != null) {
					if(parent.isAdded() && trieSet.contains(parent.getKey())) {
						containing.add(parent.getKey());
					}
					parent = parent.getParent();
				}
				AddressTrieSet<T> containingSet = trieSet.elementsContaining(address);
				if(containing.size() != containingSet.size()) {
					addFailure("containing size mismatch for " + address + ", got " + containingSet.size() + ", not " + containing.size(), set);
					trieSet.elementsContaining(address);
				}
				boolean elContains = trieSet.elementContains(address);
				if(elContains == containingSet.isEmpty()) {
					addFailure("containing mismatch for " + address + ", got " + elContains + ", not " + containingSet.isEmpty(), set);
				} else if(elContains == (containingSet.size() == 0)) {
					addFailure("containing mismatch for " + address + ", got " + elContains + ", not " + (containingSet.size() == 0), set);
				}
				AddressTrieSet<T> containedSet = trieSet.elementsContainedBy(address);
				if(node.size() < containedSet.size()) { // node size can be bigger due to bounded tries
					addFailure("containing size mismatch for " + address + ", got " + containedSet.size() + ", bigger than " + node.size(), set);
				}
				Iterator<? extends TrieNode<T>> iterator = node.nodeIterator(true);
				while(iterator.hasNext()) {
					TrieNode<T> next = iterator.next();
					if(trieSet.contains(next.getKey())) {
						if(!containedSet.contains(next.getKey())) {
							addFailure("expected " + next + " to be in set " + containedSet, set);
						}
					}
				}
				Iterator<T> iter = containedSet.iterator();
				while(iter.hasNext()) {
					T next = iter.next();
					if(!address.contains(next)) {
						addFailure("expected " + next + " to not be in set " + containedSet, set);
					}
				}
				AddressTrie<T> trie2 = trie.clone();
				if(containingSet.size() > 1) {
					trie2.removeElementsContainedBy(address);
					if(trie2.size() == 0) {
						addFailure("containing should be left ", set);
					}
				}
				trie2.removeElementsContainedBy(trie.getRoot().getKey());
				if(trie2.size() > 0) {
					addFailure("expected everything to be deleted ", set);
				}
			}
			
		} else if(set instanceof WrappedMap) {
			WrappedMap<T,?> wrapped = (WrappedMap<T,?>) set;
			AddressTrieMap<T, ?> trieMap = wrapped.map;
			AssociativeAddressTrie<T,?> trie = trieMap.asTrie();
			AssociativeTrieNode<T,?> node = trie.getAddedNode(address);
			containing.add(address);
			if(node == null) {
				addFailure("should have found node for " + address, set);
			} else {
				TrieNode<T> parent = node.getParent();
				while(parent != null) {
					if(parent.isAdded() && trieMap.containsKey(parent.getKey())) {
						containing.add(parent.getKey());
					}
					parent = parent.getParent();
				}
				AddressTrieMap<T, ?> containingSet = trieMap.subMapFromKeysContaining(address);
				if(containing.size() != containingSet.size()) {
					addFailure("containing size mismatch for " + address + ", got " + containingSet.size() + ", not " + containing.size(), set);
					trieMap.subMapFromKeysContaining(address);
				}
				boolean elContains = trieMap.keyContains(address);
				if(elContains == containingSet.isEmpty()) {
					addFailure("containing mismatch for " + address + ", got " + elContains + ", not " + containingSet.isEmpty(), set);
				} else if(elContains == (containingSet.size() == 0)) {
					addFailure("containing mismatch for " + address + ", got " + elContains + ", not " + (containingSet.size() == 0), set);
				}
				AddressTrieMap<T, ?> containedSet = trieMap.subMapFromKeysContainedBy(address);
				if(node.size() < containedSet.size()) { // node size can be bigger due to bounded tries
					addFailure("containing size mismatch for " + address + ", got " + containedSet.size() + ", bigger than " + node.size(), set);
				}
				Iterator<? extends AssociativeTrieNode<T, ?>> iterator = node.nodeIterator(true);
				while(iterator.hasNext()) {
					AssociativeTrieNode<T, ?> next = iterator.next();
					if(trieMap.containsKey(next.getKey())) {
						if(!containedSet.containsKey(next.getKey())) {
							addFailure("expected " + next + " to be in set " + containedSet, set);
						}
						EntrySet<T, ?> entrySet = trieMap.entrySet();
						if(!entrySet.contains(next)) {
							addFailure("expected " + next + " to be in entry set " + entrySet, set);
						}
					}
				}
				EntrySet<T, ?> entrySet = containedSet.entrySet();
				Iterator<? extends Entry<T,?>> iter = entrySet.iterator();
				while(iter.hasNext()) {
					T next = iter.next().getKey();
					if(!address.contains(next)) {
						addFailure("expected " + next + " to not be in set " + containedSet, set);
					}
				}
				AddressTrie<T> trie2 = trie.clone();
				if(containingSet.size() > 1) {
					trie2.removeElementsContainedBy(address);
					if(trie2.size() == 0) {
						addFailure("containing should be left ", set);
					}
				}
				trie2.removeElementsContainedBy(trie.getRoot().getKey());
				if(trie2.size() > 0) {
					addFailure("expected everything to be deleted ", set);
				}
			}
		} else {
			// never goes here, at least for now, there are not other set types at this time
		}
	}
	
	<R extends AddressTrie<T>, T extends Address> void testContainment(
			List<T> ordered, NavigableSet<T> set) {
		if(ordered.size() == 0) {
			return;
		}
		// we pick an element somewhere in the middle of the range
		T address = null; // this one is not multiple, so more likely contained by others in the set
		T multipleAddress = null; // whatever we land on
		for(int i = ordered.size() / 2; i < ordered.size(); i++) {
			T addr = ordered.get(i);
			multipleAddress = address;
			if(!addr.isMultiple()) {
				address = addr;
				break;
			}
		}
		if(address == null) {
			for(int i = ordered.size() / 2; i >= 0; i--) {
				T addr = ordered.get(i);
				if(multipleAddress == null) {
					multipleAddress = address;
				}
				if(!addr.isMultiple()) {
					address = addr;
					break;
				}
			}
			
		}
		if(address != null) {
			testContainment(address, ordered, set);
		}
		if(multipleAddress != null && multipleAddress.isMultiple()) {
			testContainment(multipleAddress, ordered, set);
		}
		// also, we take the first and the last, so possibly the parents/children are on the other side of the bounds
		T first = ordered.get(0);
		if(!first.equals(address) && !first.equals(multipleAddress)) {
			testContainment(first, ordered, set);
		}
		if(ordered.size() > 1) {
			T last = ordered.get(ordered.size() - 1);
			if(!last.equals(address) && !last.equals(multipleAddress)) {
				testContainment(last, ordered, set);
			}
		}
	}
	
	static class AnotherWrappedMap<T extends Address, V> extends WrappedMap<T,V> {
		AnotherWrappedMap(AddressTrieMap<T, V> map, V val) {
			super(map, val);
		}
		
		@Override
		public T first() {
			Entry<T,V> entry = map.firstEntry();
			if(entry == null) {
				throw new NoSuchElementException();
			}
			return entry.getKey();
		}

		@Override
		public T last() {
			Entry<T,V> entry = map.lastEntry();
			if(entry == null) {
				throw new NoSuchElementException();
			}
			return entry.getKey();
		}

		@Override
		public T lower(T e) {
			Entry<T,V> entry = map.lowerEntry(e);
			if(entry == null) {
				return null;
			}
			return entry.getKey();
		}

		@Override
		public T floor(T e) {
			Entry<T,V> entry = map.floorEntry(e);
			if(entry == null) {
				return null;
			}
			return entry.getKey();
		}

		@Override
		public T ceiling(T e) {
			Entry<T,V> entry = map.ceilingEntry(e);
			if(entry == null) {
				return null;
			}
			return entry.getKey();
		}

		@Override
		public T higher(T e) {
			Entry<T,V> entry = map.higherEntry(e);
			if(entry == null) {
				return null;
			}
			return entry.getKey();
		}
	}

	static class WrappedMap<T extends Address, V> extends AbstractSet<T> implements NavigableSet<T>, Cloneable {
		AddressTrieMap<T, V> map;
		V val;
		
		WrappedMap(AddressTrieMap<T, V> map, V val) {
			this.map = map;
			this.val = val;
		}
		
		@SuppressWarnings("unchecked")
		@Override
		public WrappedMap<T, V> clone() {
			try {
				WrappedMap<T, V> clone = (WrappedMap<T, V>) super.clone();
				clone.map = map.clone();
				return clone;
			} catch (CloneNotSupportedException e) {
				return null;
			}
		}
		
		@Override
		public boolean add(T entry) {
			return map.put(entry, val) == null;
		}
		
		@Override
		public Iterator<T> iterator() {
			return map.keySet().iterator();
		}
		
		@Override
		public NavigableSet<T> descendingSet() {
			return map.descendingKeySet();
		}

		@Override
		public Iterator<T> descendingIterator() {
			return map.keySet().descendingIterator();
		}

		@Override
		public int size() {
			return map.size();
		}

		@Override
		public Comparator<? super T> comparator() {
			return map.comparator();
		}

		@Override
		public T first() {
			return map.firstKey();
		}

		@Override
		public T last() {
			return map.lastKey();
		}

		@Override
		public T lower(T e) {
			return map.lowerKey(e);
		}

		@Override
		public T floor(T e) {
			return map.floorKey(e);
		}

		@Override
		public T ceiling(T e) {
			return map.ceilingKey(e);
		}

		@Override
		public T higher(T e) {
			return map.higherKey(e);
		}

		@Override
		public T pollFirst() {
			Entry<T,V> entry = map.pollFirstEntry();
			if(entry == null) {
				return null;
			}
			return entry.getKey();
		}

		@Override
		public T pollLast() {
			Entry<T,V> entry = map.pollLastEntry();
			if(entry == null) {
				return null;
			}
			return entry.getKey();
		}

		@Override
		public NavigableSet<T> subSet(T fromElement, boolean fromInclusive, T toElement, boolean toInclusive) {
			return new WrappedMap<T,V>(map.subMap(fromElement, fromInclusive, toElement, toInclusive), val);
		}

		@Override
		public NavigableSet<T> headSet(T toElement, boolean inclusive) {
			return new WrappedMap<T,V>(map.headMap(toElement, inclusive), val);
		}

		@Override
		public NavigableSet<T> tailSet(T fromElement, boolean inclusive) {
			return new WrappedMap<T,V>(map.tailMap(fromElement, inclusive), val);
		}

		@Override
		public SortedSet<T> subSet(T fromElement, T toElement) {
			return new WrappedMap<T,V>(map.subMap(fromElement, true, toElement, false), val);
		}

		@Override
		public SortedSet<T> headSet(T toElement) {
			return new WrappedMap<T,V>(map.headMap(toElement, false), val);
		}

		@Override
		public SortedSet<T> tailSet(T fromElement) {
			return new WrappedMap<T,V>(map.tailMap(fromElement, true), val);
		}
	}
	
	@SuppressWarnings("unchecked")
	<R extends AssociativeAddressTrie<T,V>, T extends Address, V> void testMapEdges(
			R trie, 
			List<T> addrs,
			IntFunction<V> valueProducer) {
		R trie2 = (R) trie.clone();
		int i = 0;
		for(T addr : addrs) {
			trie.put(addr, valueProducer.apply(i));
			i++;
		}
		i = 0;
		List<T> ordered = new ArrayList<>(addrs.size());
		for(T addr : trie) {
			if(i % 2 == 0) {
				trie2.put(addr, trie.get(addr));
			}
			i++;
			ordered.add(addr);
		}
		addrs = ordered;
		NavigableSet<T> set = new WrappedMap<T,V>(trie2.asMap(), valueProducer.apply(0));
		testSetEdges(ordered, set);
		
		set = new AnotherWrappedMap<T,V>(trie2.asMap(), valueProducer.apply(0));
		testSetEdges(ordered, set);
		
		set = trie2.asSet();
		testSetEdges(ordered, set);
		
		testContainment(ordered, trie.asSet());
		incrementTestCount();
	}
	
	@SuppressWarnings("unchecked")
	<R extends AddressTrie<T>, T extends Address> void testSetEdges(
			R trie, 
			List<T> addrs) {
		R trie2 = (R) trie.clone();
		R trie3 = (R) trie.clone();
		for(T addr : addrs) {
			trie.add(addr);
		}
		int i = 0;
		List<T> ordered = new ArrayList<>(addrs.size());
		for(T addr : trie) {
			if(i % 2 == 0) {
				trie2.add(addr);
			}
			i++;
			ordered.add(addr);
		}
		addrs = ordered;
		AddressTrieSet<T> set = trie2.asSet();
		testSetEdges(ordered, set);
		testBounds(trie3, ordered);
		incrementTestCount();
	}
	
	private <R extends AddressTrie<T>, T extends Address>void testBounds(R emptyTrie, 
			List<T> ordered) {
		if(ordered.size() < 5) {
			return;
		}
		T outside1 = ordered.get(0);
		T outside2 = ordered.get(ordered.size() - 1);
		AddressTrieSet<T> set = emptyTrie.asSet().subSet(ordered.get(1), ordered.get(ordered.size() - 2));
		
		ArrayList<T> els = new ArrayList<T>();
		for(int i = 2; i < ordered.size() - 2; i++) {
			T t = ordered.get(i);
			els.add(t);
			set.add(t);
		}
		testContainment(els, set);
		set.clear();
		if(emptyTrie.asSet().size() > 0) {
			addFailure("unexpected size " + emptyTrie.asSet().size(), set);
			set.clear();
			emptyTrie.asSet().clear();
		}
		
		try {
			set.add(outside1);
			addFailure("should have thrown from trie with bounds " + set.getRange() + " when adding " + outside1, set);
		} catch(IllegalArgumentException e) {}
		try {
			set.add(outside2);
			addFailure("should have thrown from trie with bounds " + set.getRange() + " when adding " + outside2, set);
		} catch(IllegalArgumentException e) {}
		
		set.add(ordered.get(2));
		set.remove(outside1);// removing outside the bounds is fine
		set.remove(outside2);
		set.remove(ordered.get(2));
		
		set.clear();
		
		AddressTrieSet<T> set2 = emptyTrie.asSet();
		set2.add(outside1);
		set2.add(outside1);
		set2.add(outside2);
		if(set2.size() != 2) {
			addFailure("unexpected size " + set2.size(), set);
		}
		set = set2.subSet(ordered.get(1), ordered.get(ordered.size() - 2));
		try {
			set.add(outside1);
			addFailure("should have thrown from trie with bounds " + set.getRange() + " when adding " + outside1, set);
		} catch(IllegalArgumentException e) {}
		try {
			set.add(outside1);
			addFailure("should have thrown from trie with bounds " + set.getRange() + " when adding " + outside1, set);
		} catch(IllegalArgumentException e) {}
		set.remove(outside1);// removing outside the bounds is fine
		set.remove(outside2);
		// backing set should have same size even when we removed from subset
		if(set2.size() != 2) {
			addFailure("out of bounds remove affected set", set);
		}
	}
	
	private <R extends AddressTrie<T>, T extends Address> void testSetEdges(List<T> ordered,
			NavigableSet<T> set) {
		testSetEdgesImpl(ordered, set);
		ArrayList<T> reverse = reverse(ordered);
		testSetEdgesImpl(reverse, set.descendingSet());
	}

	private <T extends Address> ArrayList<T> reverse(List<T> ordered) {
		ArrayList<T> reverse = new ArrayList<>(ordered.size());
		for(int i = ((ordered.size() - 1) >> 1) << 1; i >= 0; i--) {
			reverse.add(ordered.get(i));
		}
		return reverse;
	}

	private <R extends AddressTrie<T>, T extends Address> void testSetEdgesImpl(List<T> ordered, NavigableSet<T> set) {
		// no bounds
		testSetEdges(set, ordered, -1, -1);
		// no upper bounds loop
		NavigableSet<T> lastSet = set;
		NavigableSet<T> origSet = set;
		for(int j = 0; j < ordered.size(); j++) {
			if(j > 0) {
				set = lastSet.tailSet(ordered.get(j - 1), false);
				testSetEdges(set, ordered, j, -1);
			}
			set = (NavigableSet<T>) lastSet.tailSet(ordered.get(j));
			testSetEdges(set, ordered, j, -1);
			lastSet = set;
			
			// the test expects the set to contain elememnts 0, 2, 4, ....
			// so when we reverse, the same must be true
			// testing odd-sized trees is enough anyway, screwing around with the indices here is ridiculously complicated otherwise
			if(ordered.size() % 2 == 1) {
				ArrayList<T> reversedAgain = reverse(ordered);
				NavigableSet<T> reversedSet = set.descendingSet();
				testSetEdges(reversedSet, reversedAgain, -1, ordered.size() - j - 1);
			}
			
			testBoundedClone(set);
			
		}
		// no lower bounds loop
		lastSet = origSet;
		for(int j = ordered.size() - 1; j >= 0; j--) {
			if(j < ordered.size() - 1) {
				set = lastSet.headSet(ordered.get(j + 1), false);
				testSetEdges(set, ordered, -1, j);
			}
			set = lastSet.headSet(ordered.get(j), true);
			testSetEdges(set, ordered, -1, j);
			lastSet = set;
			testBoundedClone(set);
		}
		// double bounds loop
		for(int j = 0; j < ordered.size(); j++) {
			lastSet = origSet;
			boolean fromInclusive;
			T fromElement;
			if(j > 0) {
				fromInclusive = false;
				fromElement = ordered.get(j - 1);
				for(int k = ordered.size() - 1; k >= j; k--) {
					boolean toInclusive;
					T toElement;
					if(k < ordered.size() - 1) {
						toElement = ordered.get(k + 1);
						toInclusive = false;
						set = lastSet.subSet(fromElement, fromInclusive, toElement, toInclusive);
						testSetEdges(set, ordered, j, k);
						testBoundedClone(set);
					}
					toElement = ordered.get(k);
					toInclusive = true;
					set = lastSet.subSet(fromElement, fromInclusive, toElement, toInclusive);
					testSetEdges(set, ordered, j, k);
					lastSet = set;
					testBoundedClone(set);
				}
			}
			lastSet = origSet;
			fromInclusive = true;
			fromElement = ordered.get(j);
			set = set.tailSet(fromElement, fromInclusive);
			for(int k = ordered.size() - 1; k >= j; k--) {
				boolean toInclusive;
				T toElement;
				if(k < ordered.size() - 1) {
					toElement = ordered.get(k + 1);
					toInclusive = false;
					set = lastSet.subSet(fromElement, fromInclusive, toElement, toInclusive);
					testSetEdges(set, ordered, j, k);
					testBoundedClone(set);
					
				}
				toElement = ordered.get(k);
				toInclusive = true;
				set = lastSet.subSet(fromElement, fromInclusive, toElement, toInclusive);
				testSetEdges(set, ordered, j, k);
				lastSet = set;
				testBoundedClone(set);
			}
		}
	}

	@SuppressWarnings("unchecked")
	private <R extends AddressTrie<T>, T extends Address> void testBoundedClone(NavigableSet<T> set) {
		// when cloning, the bounds are removed and the out-of-bounds nodes are trimmed from the trie
		AddressTrie<T> newTrie;
		if(set instanceof AddressTrieSet) {
			AddressTrieSet<T> trieSet = (AddressTrieSet<T>) set;
			newTrie = trieSet.asTrie();
		} else if(set instanceof WrappedMap) {
			WrappedMap<T, ?> wrapped = (WrappedMap<T, ?>) set;
			newTrie = wrapped.map.asTrie();
		} else {
			return;
		}
		if(newTrie.size() != set.size()) {
			addFailure("size mismatch, got " + newTrie.size() + " after clone, not " + set.size(), set);
		}
		// now we check the trie looks like it should
		int count = 0;
		Iterator<? extends TrieNode<T>> iterator = newTrie.allNodeIterator(true);
		while(iterator.hasNext()) {
			TrieNode<T> next = iterator.next();
			if(next.isAdded()) {
				count++;
				if(!set.contains(next.getKey())) {
					addFailure("failed clone, found " + next + " when iterating, not in set", set);
				}
			} else {
				if(!next.isRoot() && (next.getLowerSubNode() == null || next.getUpperSubNode() == null)) {
					addFailure("trie structure flawed below " + next, set);
				}
			}
		}	
		if(newTrie.size() != count) {
			addFailure("size mismatch, got " + count + " when iterating, not " + newTrie.size(), set);
		}
	}
	
	
	static class WrappedEntrySetIterator<T extends Address, V> implements Iterator<T> {
		Iterator<Entry<T,V>> entrySetIterator;
		
		WrappedEntrySetIterator(Iterator<Entry<T,V>> entrySetIterator) {
			this.entrySetIterator = entrySetIterator;
		}

		@Override
		public boolean hasNext() {
			return entrySetIterator.hasNext();
		}

		@Override
		public T next() {
			return entrySetIterator.next().getKey();
		}
		
		
		@Override
		public void remove() {
			entrySetIterator.remove();
		}
	}
	
	static class WrappedEntrySetSpliterator<T extends Address, V> implements Spliterator<T> {
		Spliterator<Entry<T,V>> entrySetSpliterator;
		
		WrappedEntrySetSpliterator(Spliterator<Entry<T,V>> entrySetSpliterator) {
			this.entrySetSpliterator = entrySetSpliterator;
		}
		
		@Override
		public boolean tryAdvance(Consumer<? super T> action) {
			return entrySetSpliterator.tryAdvance(entry -> action.accept(entry.getKey()));
		}

		@Override
		public Spliterator<T> trySplit() {
			Spliterator<Entry<T, V>> split = entrySetSpliterator.trySplit();
			if(split == null) {
				return null;
			}
			return new WrappedEntrySetSpliterator<T,V>(split);
		}

		@Override
		public long estimateSize() {
			return entrySetSpliterator.estimateSize();
		}

		@Override
		public int characteristics() {
			return entrySetSpliterator.characteristics();
		}
	}
	
	<T extends Address, V> void testBoundedMapIterators(
			WrappedMap<T,V> set, 
			List<T> ordered, int lowerIndex, int upperIndex,
			Function<? super EntrySet<T,V>, ? extends Iterator<Entry<T,V>>> iteratorFunc) {
		AddressTrieMap<T, V> map = set.map;
		EntrySet<T, V> entrySet = map.entrySet();
		testBoundedSetIterator(set, ordered, lowerIndex, upperIndex, () -> new WrappedEntrySetIterator<T,V>(iteratorFunc.apply(entrySet)));
	}
	
	<T extends Address, V> void testBoundedIterators(NavigableSet<T> set, 
			List<T> ordered, int lowerIndex, int upperIndex,
			Function<? super NavigableSet<T>, ? extends Iterator<T>> iteratorFunc) {
		testBoundedSetIterator(set, ordered, lowerIndex, upperIndex, () -> iteratorFunc.apply(set));
	}
	
	<T extends Address, V> void testBoundedTrieIterators(AddressTrieSet<T> set, 
			List<T> ordered, int lowerIndex, int upperIndex, Function<? super AddressTrieSet<T>, ? extends Iterator<T>> iteratorFunc) {
		testBoundedSetIterator(set, ordered, lowerIndex, upperIndex, () -> iteratorFunc.apply(set));
	}

	private <T extends Address> void testBoundedSetIterator(Set<T> set, List<T> ordered, int lowerIndex,
			int upperIndex, 
			Supplier<? extends Iterator<T>> iteratorFunc) {
		Set<T> elements = new HashSet<T>();
		for(int i = lowerIndex; i <= upperIndex; i += 2) {
			elements.add(ordered.get(i));
		}
		int count = 0;
		Set<T> iterElements = new HashSet<T>();
		Iterator<T> iterator = iteratorFunc.get();
		while(iterator.hasNext()) {
			iterElements.add(iterator.next());
			count++;
		}
		if(count != elements.size()) {
			addFailure("wrong iterator count, got " + count + " not " + elements.size(), set);
		}
		if(!iterElements.equals(elements)) {
			addFailure("wrong iterator elements, got " + iterElements + " not " + elements, set);
		}
		if(!set.equals(elements)) {
			addFailure("failed set equality", set);
			set.equals(elements);
		}
	}
	
	
	<T extends Address, V> void testBoundedMapSpliterators(
			WrappedMap<T,V> set, 
			List<T> ordered, int lowerIndex, int upperIndex,
			Function<? super EntrySet<T,V>, ? extends Spliterator<Entry<T,V>>> spliteratorFunc) {
		AddressTrieMap<T, V> map = set.map;
		EntrySet<T, V> entrySet = map.entrySet();
		testBoundedSetSpliterator(set, ordered, lowerIndex, upperIndex, () -> new WrappedEntrySetSpliterator<T,V>(spliteratorFunc.apply(entrySet)));
	}
	
	<T extends Address, V> void testBoundedSpliterators(NavigableSet<T> set, 
			List<T> ordered, int lowerIndex, int upperIndex,
			Function<? super NavigableSet<T>, ? extends Spliterator<T>> spliteratorFunc) {
		testBoundedSetSpliterator(set, ordered, lowerIndex, upperIndex, () -> spliteratorFunc.apply(set));
	}
	
	private <T extends Address> void testBoundedSetSpliterator(Set<T> set, List<T> ordered, int lowerIndex,
			int upperIndex, 
			//Iterator<T> iterator) {
			Supplier<? extends Spliterator<T>> iteratorFunc) {
		Set<T> elements = new HashSet<T>();
		for(int i = lowerIndex; i <= upperIndex; i += 2) {
			elements.add(ordered.get(i));
		}
		//int count = 0;
		Set<T> iterElements = new HashSet<T>();
		Spliterator<T> spliterator = iteratorFunc.get();
		Spliterator<T> spliterator2 = spliterator.trySplit();
		if(spliterator2 != null) {
			Spliterator<T> spliterator3 = spliterator2.trySplit();
			spliterator2.forEachRemaining(addr -> iterElements.add(addr));
			if(spliterator3 != null) {
				spliterator3.forEachRemaining(addr -> iterElements.add(addr));
			}
		}
		spliterator.forEachRemaining(addr -> iterElements.add(addr));
		if(!iterElements.equals(elements)) {
			addFailure("wrong iterator elements, got " + iterElements + " not " + elements, set);
		
			Set<T> iterElements2 = new HashSet<T>();
			spliterator = iteratorFunc.get();
			spliterator2 = spliterator.trySplit();
			if(spliterator2 != null) {
				Spliterator<T> spliterator3 = spliterator2.trySplit();
				spliterator2.forEachRemaining(addr -> iterElements2.add(addr));
				if(spliterator3 != null) {
					spliterator3.forEachRemaining(addr -> iterElements2.add(addr));
				}
			}
			spliterator.forEachRemaining(addr -> iterElements2.add(addr));
		}
		if(!set.equals(iterElements)) {
			addFailure("failed set equality", set);
		}
	}

	@SuppressWarnings("unchecked")
	<T extends Address, V> void testSetEdges(
			NavigableSet<T> set, 
			List<T> ordered, 
			int lowerBoundIndex, int upperBoundIndex) {
		
		// elements 0, 2, 4, ... are in the set
		int notOne = ~0 << 1;
		int lowerEven = (lowerBoundIndex + 1) & notOne;
		int lowerInd = lowerBoundIndex >= 0 ? lowerEven : 0;
		// we have to get an even number, 
		// because only every 2nd address is in the set, starting from 0
		int lastIndex = (ordered.size() - 1) & notOne;
		int lastBounded = upperBoundIndex & notOne;
		int upperInd = upperBoundIndex >= 0 ? lastBounded : lastIndex;

		testBoundedIterators(set, ordered, lowerInd, upperInd, NavigableSet::iterator);
		testBoundedIterators(set, ordered, lowerInd, upperInd, NavigableSet::descendingIterator);
		testBoundedSpliterators(set, ordered, lowerInd, upperInd, NavigableSet::spliterator);
		if(set instanceof AddressTrieSet) {
			AddressTrieSet<T> trieSet = (AddressTrieSet<T>) set;
			testBoundedTrieIterators(trieSet, ordered, lowerInd, upperInd, AddressTrieSet::containedFirstIterator);
			testBoundedTrieIterators(trieSet, ordered, lowerInd, upperInd, AddressTrieSet::containingFirstIterator);
			testBoundedTrieIterators(trieSet, ordered, lowerInd, upperInd, AddressTrieSet::blockSizeIterator);
		} else if(set instanceof WrappedMap) {
			WrappedMap<T,?> wrappedMap = (WrappedMap<T,?>) set;
			testBoundedMapIterators(wrappedMap, ordered, lowerInd, upperInd, EntrySet::iterator);
			testBoundedMapIterators(wrappedMap, ordered, lowerInd, upperInd, EntrySet::containingFirstIterator);
			testBoundedMapIterators(wrappedMap, ordered, lowerInd, upperInd, EntrySet::containedFirstIterator);
			testBoundedMapIterators(wrappedMap, ordered, lowerInd, upperInd, EntrySet::blockSizeIterator);
			testBoundedMapSpliterators(wrappedMap, ordered, lowerInd, upperInd, EntrySet::spliterator);
		}
		if(lowerInd <= upperInd) {
			T expectedFirst = ordered.get(lowerInd);
			try {
				if(!expectedFirst.equals(set.first())) {
					addFailure("wrong first, got " + set.first() + " not " + expectedFirst, set);
					set.first();
				}
			} catch(NoSuchElementException e) {
				addFailure("wrong first, got none not " + expectedFirst, set);
			}
			T expectedLast = ordered.get(upperInd);
			try {
				if(!expectedLast.equals(set.last())) {
					addFailure("wrong last, got " + set.last() + " not " + expectedLast, set);
					//set.last();
				}
			} catch(NoSuchElementException e) {
				addFailure("wrong last, got none not " + expectedLast, set);
			}
		} else {
			try {
				set.first();
				addFailure("no throw calling first() on empty ", set);
			} catch(NoSuchElementException e) {}
			try {
				set.last();
				addFailure("no throw calling last() on empty ", set);
			} catch(NoSuchElementException e) {}
		}
		
		int i = 0;
		
		int lowestInSetIndex, highestInSetIndex;
		if(lowerBoundIndex > 0) {
			// round up to even number
			lowestInSetIndex = (lowerBoundIndex + 1) & notOne;
		} else {
			lowestInSetIndex = 0;
		}
		if(upperBoundIndex >= 0) {
			// round down to even number
			highestInSetIndex = upperBoundIndex & notOne;
		} else {
			// round down to even number
			highestInSetIndex = (ordered.size() - 1) & notOne;
		}
		
		for(T addr : ordered) {
			T floor = set.floor(addr);
			T lower = set.lower(addr);
			T ceiling = set.ceiling(addr);
			T higher = set.higher(addr);

			//x x x x 
			//  y   y
			//      z
			
			//x x x x 
			//  y   y
			//  z   
			
			T expectedFloor, expectedCeiling, expectedLower, expectedHigher;
			if(lowestInSetIndex > highestInSetIndex) {
				expectedFloor = null;
				expectedCeiling = null;
				expectedLower = null;
				expectedHigher = null;
			} else if(i % 2 == 0) {
				// in the set/map
				if(i >= lowestInSetIndex) {
					if(i <= highestInSetIndex) {
						expectedFloor = ordered.get(i);
					} else {
						expectedFloor = ordered.get(highestInSetIndex);
					}
				} else {
					expectedFloor = null;
				}
				
				if(i <= highestInSetIndex) {
					if(i >= lowestInSetIndex) {
						expectedCeiling = ordered.get(i);
					} else {
						expectedCeiling = ordered.get(lowestInSetIndex);
					}
				} else {
					expectedCeiling = null;
				}
				
				int j = i - 2;
				if(j >= 0) {
					if(j >= lowestInSetIndex) {
						if(j <= highestInSetIndex) {
							expectedLower = ordered.get(j);
						} else {
							expectedLower = ordered.get(highestInSetIndex);
						}
					} else {
						expectedLower = null;
					}
				} else {
					expectedLower = null;
				}
				
				int k = i + 2;
				if(k < ordered.size()) {
					if(k <= highestInSetIndex) {
						if(k >= lowestInSetIndex) {
							expectedHigher = ordered.get(k);
						} else {
							expectedHigher = ordered.get(lowestInSetIndex);
						}
					} else {
						expectedHigher = null;
					}
				} else {
					expectedHigher = null;
				}
				
			} else {
				// not in the set/map
				int j = i - 1;
				if(j >= 0) {
					if(j >= lowestInSetIndex) {
						if(j <= highestInSetIndex) {
							expectedLower = ordered.get(j);
						} else {
							expectedLower = ordered.get(highestInSetIndex);
						}
					} else {
						expectedLower = null;
					}
				} else {
					expectedLower = null;
				}
				expectedFloor = expectedLower;
				int k = i + 1;
				if(k < ordered.size()) {
					if(k <= highestInSetIndex) {
						if(k >= lowestInSetIndex) {
							expectedHigher = ordered.get(k);
						} else {
							expectedHigher = ordered.get(lowestInSetIndex);
						}
					} else {
						expectedHigher = null;
					}
				} else {
					expectedHigher = null;
				}
				expectedCeiling = expectedHigher;
			}

			if(!Objects.equals(floor, expectedFloor)) {
				addFailure("wrong floor, got " + floor + " not " + expectedFloor, set);
			} else if(!Objects.equals(ceiling, expectedCeiling)) {
				addFailure("wrong ceiling, got " + ceiling + " not " + expectedCeiling, set);
			} else if(!Objects.equals(lower, expectedLower)) {
				addFailure("wrong lower, got " + lower + " not " + expectedLower, set);
			} else if(!Objects.equals(higher, expectedHigher)) {
				addFailure("wrong higher, got " + higher + " not " + expectedHigher, set);
			}
			i++;
		}
		

		if(set.size() >= 2) {
			T first = set.pollFirst();
			T second = set.pollFirst();
			set.add(first);
			set.add(second);
			Iterator<T> z = set.iterator();
			T next = z.next();
			if(!next.equals(first)) {
				addFailure("wrong first, got " + next + " not " + first, set);
			}
			next = z.next();
			if(!next.equals(second)) {
				addFailure("wrong second, got " + next + " not " + second, set);
			}
			T last = set.pollLast();
			T almostLast = set.pollLast();
			set.add(last);
			z = set.descendingIterator();
			set.add(almostLast);
			try {
				next = z.next();
				addFailure("should have thrown since I added to set after grabbing iterator ", set);
			} catch(ConcurrentModificationException e) {
				z = set.descendingIterator();
				next = z.next();
			}
			if(!next.equals(last)) {
				addFailure("wrong last, got " + next + " not " + last, set);
			}
			next = z.next();
			if(!next.equals(almostLast)) {
				addFailure("wrong almostLast, got " + next + " not " + almostLast, set);
			}
		} else if(set.size() == 1) {
			T first = set.pollFirst();
			T second = set.pollFirst();
			set.add(first);
			if(second != null) {
				addFailure("wrong second, got " + second + " not null", set);
			}
			Iterator<T> z = set.iterator();
			T next = z.next();
			if(!next.equals(first)) {
				addFailure("wrong first, got " + next + " not " + first, set);
			}
			z = set.descendingIterator();
			next = z.next();
			if(!next.equals(first)) {
				addFailure("wrong first, got " + next + " not " + first, set);
			}
		} else {
			T first = set.pollFirst();
			if(first != null) {
				addFailure("wrong first, got " + first + " not null for set of size " + set.size(), set);
			}
		}
		incrementTestCount();
	}

	void testNonBlock(String str) {
		IPAddress addr = createAddress(str).getAddress();
		IPAddress result = Partition.checkBlockOrAddress(addr);
		if(result != null) {
			addFailure("unexpectedly got a single block or address for " + addr, addr);
		}
	}
	
	void testNonMACBlock(String str) {
		MACAddress addr = createMACAddress(str).getAddress();
		MACAddress result = Partition.checkBlockOrAddress(addr);
		if(result != null) {
			addFailure("unexpectedly got a single block or address for " + addr, addr);
		}
	}
	
	void testIPAddrBlock(String str) {
		IPAddress addr = createAddress(str).getAddress();
		IPAddress result = Partition.checkBlockOrAddress(addr);
		if(result != addr) {
			addFailure("unexpectedly got different address " + result + " for " + addr, addr);
		}
	}
	
	void testMACAddrBlock(String str) {
		MACAddress addr = createMACAddress(str).getAddress();
		MACAddress result = Partition.checkBlockOrAddress(addr);
		if(result != addr) {
			addFailure("unexpectedly got different address " + result + " for " + addr, addr);
		}
	}
	
	void testConvertedBlock(String str, Integer expectedPrefLen) {
		IPAddress addr = createAddress(str).getAddress();
		testConvertedBlock(addr, expectedPrefLen);
	}
	
	void testConvertedBlock(Address addr, Integer expectedPrefLen) {
		Address result = Partition.checkBlockOrAddress(addr);
		if(result == null) {
			addFailure("unexpectedly got no single block or address for " + addr, addr);
		}
		if(!Objects.equals(addr, result) && !Objects.equals(result.getPrefixLength(), expectedPrefLen)) {
			addFailure("unexpectedly got wrong pref len " + result.getPrefixLength() + " not " + expectedPrefLen, addr);
		}
	}
	
	void testAddressCheck() {
		IPAddress addr = createAddress("1.2.3.4/16").getAddress();
		PrefixConfiguration prefCon = addr.getNetwork().getPrefixConfiguration();
		if(!prefCon.allPrefixedAddressesAreSubnets()) {
			testConvertedBlock(addr, null);
		} else {
			testIPAddrBlock("1.2.3.4/16");
		}
		testIPAddrBlock("1.2.3.4");
		testIPAddrBlock("::");
		testNonBlock("1-3.2.3.4");
		testConvertedBlock("1.2.3.4-5", 31);
		testNonBlock("1.2.3.5-6");
		testConvertedBlock("1.2.3.4-7", 30);
		testNonBlock("::1-2:0");
		testNonBlock("::1-2:0/112");
		if(!prefCon.prefixedSubnetsAreExplicit()) {
			testConvertedBlock("::0-3:0/112", 110);
			testIPAddrBlock("::/64");
			testIPAddrBlock("1.2.0.0/16");
		} else {
			testNonBlock("::0-3:0/112");
			testConvertedBlock("::/64", null);
			testConvertedBlock("1.2.0.0/16", null);
		}
		MACAddress mac = createMACAddress("a:b:c:*:*:*").getAddress();
		mac = mac.setPrefixLength(48, false);
		testConvertedBlock(mac, 24);
		testMACAddrBlock("a:b:c:*:*:*");
		testNonMACBlock("a:b:c:*:2:*");
		testNonBlock("a:b:c:*:2:*"); // passes null into checkBlockOrAddress
		testMACAddrBlock("a:b:c:1:2:3");
	}
	
	@SuppressWarnings("unchecked")
	<R extends AddressTrie<T>, T extends Address>void testSerialize(R trie) {
		try {
			R result = (R) serialize(trie);
			if(result.nodeSize() != trie.nodeSize()) {
				addFailure("wrong node size, got " + result.nodeSize() + " not " +trie.nodeSize(), trie);
			}
			if(result.size() != trie.size()) {
				addFailure("wrong node size, got " + result.size() + " not " +trie.size(), trie);
			}
			if(!result.equals(trie)) {
				addFailure("serialize failed for trie", trie);
			}
			
			
			if(trie.size() > 0) {
				
				if(!trie.getRoot().treeEquals(result.getRoot())) {
					addFailure("serialize failed for trie nodes", trie);
				}
				
				
				T lower = trie.firstNode().getKey();
				T upper = trie.lastNode().getKey();
				if(trie instanceof AssociativeAddressTrie) {
					AssociativeAddressTrie<T, ?> mapTrie = (AssociativeAddressTrie<T, ?>) trie;
					AddressTrieMap<T, ?> map = mapTrie.asMap().subMap(lower, upper).descendingMap();
					map.entrySet();
					map.keySet();
					AddressTrieMap<T, ?> mapResult = (AddressTrieMap<T, ?>) serialize(map);
					if(mapResult.size() != map.size()) {
						addFailure("wrong node size, got " + result.size() + " not " +trie.size(), trie);
					}
					if(!mapResult.equals(map)) {
						addFailure("serialize failed for map", map);
					}
				} else {
					AddressTrieSet<T> set = trie.asSet().headSet(upper).descendingSet();
					AddressTrieSet<T> setResult = (AddressTrieSet<T>) serialize(set);
					if(setResult.size() != set.size()) {
						addFailure("wrong size, got " + setResult.size() + " not " + set.size(), trie);
					}
					if(!setResult.equals(set)) {
						addFailure("serialize failed for set", set);
					}
				}
				
			}
		} catch (ClassNotFoundException | IOException e) {
			addFailure("serialize failed for trie: " + e, trie);
		}
		incrementTestCount();
	}
	
	public Object serialize(Object input) throws IOException, ClassNotFoundException {
		EfficientByteArrayOuputStream outmine = new EfficientByteArrayOuputStream();
		ObjectOutput outputmine = new ObjectOutputStream(outmine);
		outputmine.writeObject(input);
		outputmine.close();
		List<? extends byte[]> bytesmine = outmine.getBytes();
		EfficientByteArrayInputStream inmine = new EfficientByteArrayInputStream(bytesmine);
		ObjectInput inputmine = null;
		Object result = null;
		try {
			inputmine = new ObjectInputStream(inmine);
			result = inputmine.readObject();
			return result;
		} finally {
			if(inputmine != null) {
				try {
					inputmine.close();
				} catch(IOException e) {
					if(result != null) {
						throw e;
					}
					//else throw the original exception instead
				}
			}
		}
	}

	String[][] getSampleIPAddressTries() {
		if(!fullTest) {
			return testIPAddressTries;
		}
		HashSet<String> all = new HashSet<>();
		for(String tree[] : testIPAddressTries) {
			for(String addr : tree) {
				all.add(addr);
			}
		}
		String allStrings[] = all.toArray(new String[all.size()]);
		String[][] oneMore = new String[testIPAddressTries.length + 1][];
		System.arraycopy(testIPAddressTries, 0, oneMore, 0, testIPAddressTries.length);
		oneMore[oneMore.length - 1] = allStrings;
		return oneMore;
	}
	
	@Override
	void runTest() {
		testAddressCheck();
		partitionTest(this);
		
		String[][] sampleIPAddressTries = getSampleIPAddressTries();
		for(String treeAddrs[] : sampleIPAddressTries) {
			testRemove(this, treeAddrs);
		}
		boolean notDoneEmptyIPv6 = true;
		boolean notDoneEmptyIPv4 = true;
		for(String treeAddrs[] : sampleIPAddressTries) {
			IPv6AddressTrie ipv6Tree = new IPv6AddressTrie();
			createSampleTree(ipv6Tree, treeAddrs);
			int size = ipv6Tree.size();
			if(size > 0 || notDoneEmptyIPv6) {
				if(notDoneEmptyIPv6) {
					notDoneEmptyIPv6 = size != 0;
				}
				testIterate(this, ipv6Tree);
				testSpliterate(this, ipv6Tree);
				testContains(ipv6Tree);
				testSerialize(ipv6Tree);

//				System.out.println(ipv6Tree);
//				String s = ipv6Tree.toAddedNodesTreeString();
//				System.out.println(s);
			}
			
			IPv4AddressTrie ipv4Tree = new IPv4AddressTrie();
			createSampleTree(ipv4Tree, treeAddrs);
			size = ipv4Tree.size();
			if(size > 0 || notDoneEmptyIPv4) {
				if(notDoneEmptyIPv4) {
					notDoneEmptyIPv4 = size != 0;
				}
				testIterate(this, ipv4Tree);
				testSpliterate(this, ipv4Tree);
				testContains(ipv4Tree);
				testSerialize(ipv4Tree);
				
//				System.out.println(ipv4Tree);
//				String s = ipv4Tree.toAddedNodesTreeString();
//				System.out.println(s);
			}
		}
		notDoneEmptyIPv6 = true;
		notDoneEmptyIPv4 = true;
		for(String treeAddrs[] : sampleIPAddressTries) {
			List<IPv4Address> addrs = collect(treeAddrs, addrStr -> createAddress(addrStr).getAddress().toIPv4());
			int size = addrs.size();
			if(size > 0 || notDoneEmptyIPv4) {
				if(notDoneEmptyIPv4) {
					notDoneEmptyIPv4 = size != 0;
				}
				testAdd(new IPv4AddressTrie(), addrs);
				testEdges(new IPv4AddressTrie(), addrs);
				testSet(new IPv4AddressTrie(), addrs);
				testMap(new IPv4AddressAssociativeTrie<Integer>(), addrs, i -> i, i -> 2 * 1);
				testSetEdges(new IPv4AddressTrie(), addrs);
				testMapEdges(new IPv4AddressAssociativeTrie<String>(), addrs, i -> ("foo" + i));
			}
			List<IPv6Address> addrsv6 = collect(treeAddrs, addrStr -> createAddress(addrStr).getAddress().toIPv6());
			size = addrsv6.size();
			if(size > 0 || notDoneEmptyIPv6) {
				if(notDoneEmptyIPv6) {
					notDoneEmptyIPv6 = size != 0;
				}
				testAdd(new IPv6AddressTrie(), addrsv6);
				testEdges(new IPv6AddressTrie(), addrsv6);
				testSet(new IPv6AddressTrie(), addrsv6);
				testMap(new IPv6AddressAssociativeTrie<String>(), addrsv6, i -> ("bla" + i), str -> str + "foo");
				testSetEdges(new IPv6AddressTrie(), addrsv6);
				testMapEdges(new IPv6AddressAssociativeTrie<Integer>(), addrsv6, i -> i);
			}
		}
		
		boolean notDoneEmptyMAC = true;
		for(String treeAddrs[] : testMACTries) {
			MACAddressTrie macTree = new MACAddressTrie();
			createSampleTree(macTree, treeAddrs);
			int size = macTree.size();
			if(size > 0 || notDoneEmptyMAC) {
				if(notDoneEmptyMAC) {
					notDoneEmptyMAC = size != 0;
				}
				testIterate(this, macTree);
				testSpliterate(this, macTree);
				testContains(macTree);
			}
		}
		notDoneEmptyMAC = true;
		for(String treeAddrs[] : testMACTries) {
			List<MACAddress> addrs = collect(treeAddrs, addrStr -> createMACAddress(addrStr).getAddress());
			int size = addrs.size();
			if(size > 0 || notDoneEmptyIPv4) {
				if(notDoneEmptyMAC) {
					notDoneEmptyMAC = size != 0;
				}
				testAdd(new MACAddressTrie(), addrs);
				testEdges(new MACAddressTrie(), addrs);
				testSet(new MACAddressTrie(), addrs);
				testMap(new MACAddressAssociativeTrie<Integer>(), addrs, i -> i, i -> 3 * 1);
				testSetEdges(new MACAddressTrie(), addrs);
				testMapEdges(new MACAddressAssociativeTrie<String>(), addrs, i -> ("foobar" + i));
			}
			
		}
		for(String treeAddrs[] : testMACTries) {
			testRemoveMAC(this, treeAddrs);
		}
		
		IPAddress cached[] = getAllCached();
		if(fullTest && cached != null && cached.length > 0 && !didOneMegaTree) {
			if(cached[0].getNetwork().getPrefixConfiguration().zeroHostsAreSubnets()) {
				didOneMegaTree = true;
				IPv6AddressTrie ipv6Tree1 = new IPv6AddressTrie();
				createSampleTree(ipv6Tree1, cached);
				//System.out.println(ipv6Tree1);
				testIterate(this, ipv6Tree1);
				testSpliterate(this, ipv6Tree1);
				testContains(ipv6Tree1);
				
				IPv4AddressTrie ipv4Tree1 = new IPv4AddressTrie();
				createSampleTree(ipv4Tree1, cached);
				//System.out.println(ipv4Tree1);
				testIterate(this, ipv4Tree1);
				testSpliterate(this, ipv4Tree1);
				testContains(ipv4Tree1);
			}
		}
		IPAddress addr = createAddress("::").getAddress();
		PrefixConfiguration prefCon = addr.getNetwork().getPrefixConfiguration();
		if(prefCon.zeroHostsAreSubnets()) {
			testString(one);
			testString(two);
		}
		
		// try deleting the root
		IPv4AddressTrie trie = new IPv4AddressTrie();
		trie.add(new IPAddressString("1.2.3.4").getAddress().toIPv4());
		trie.getRoot().setAdded();
		if(trie.size() != 2) {
			addFailure("unexpected size " + trie.size(), trie);
		}
		trie.getRoot().remove();
		if(trie.size() != 1) {
			addFailure("unexpected size " + trie.size(), trie);
		}
		if(trie.nodeSize() != 2) {
			addFailure("unexpected node size " + trie.nodeSize(), trie);
		}
		trie.clear();
		if(trie.nodeSize() != 1) {
			addFailure("unexpected node size " + trie.nodeSize(), trie);
		}
		if(trie.size() != 0) {
			addFailure("unexpected size " + trie.size(), trie);
		}
		trie.getRoot().remove();
		if(trie.nodeSize() != 1) {
			addFailure("unexpected node size " + trie.nodeSize(), trie);
		}
		if(trie.size() != 0) {
			addFailure("unexpected size " + trie.size(), trie);
		}
		incrementTestCount();
		//trieOrders();
	}
	
	static boolean didOneMegaTree = false;

	static void foo(IPv6AddressTrie ipv6Tree) {
		System.out.println(ipv6Tree);
		System.out.println();
		visitRecursive(ipv6Tree.getRoot(), null);
		System.out.println();
		visitIterative(ipv6Tree.getRoot());
	}
	
	static <E> void visitRecursive(BinaryTreeNode<E> node, String direction) {
		if(direction == null) {
			direction = "root";
		}
		System.out.println("visited " + direction + " " + node);
		BinaryTreeNode<E> sub = node.getLowerSubNode();
		if(sub != null) {
			visitRecursive(sub, direction + " left");
		}
		sub = node.getUpperSubNode();
		if(sub != null) {
			visitRecursive(sub, direction + " right");
		}
	}

	static <E> void visitIterative(BinaryTreeNode<E> node) {	
		CachingIterator<? extends BinaryTreeNode<E>, E, String> iterator = node.containingFirstAllNodeIterator(true);
		while(iterator.hasNext()) {
			BinaryTreeNode<E> next = iterator.next();
			String direction = iterator.getCached();
			if(direction == null) {
				direction = "root";
			}
			System.out.println("visited " + direction + " " + next);
			iterator.cacheWithLowerSubNode(direction + " left");
			iterator.cacheWithUpperSubNode(direction + " right");
		}
	}
	
	static class Node extends BinaryTreeNode<Integer> {

		private static final long serialVersionUID = 1L;

		Node(int i) {
			super(i);
			setAdded(true);
		}
		
		protected void setUpper(int upper) {
			super.setUpper(new Node(upper));
		}

		protected void setLower(int lower) {
			super.setLower(new Node(lower));
		}
		
		@Override
		public Node getUpperSubNode() {
			return (Node) super.getUpperSubNode();
		}

		@Override
		public Node getLowerSubNode() {
			return (Node) super.getLowerSubNode();
		}
	}
	
	static void trieOrders() {
		Node root = new Node(1);
		root.setLower(2);
		root.setUpper(3);
		root.getLowerSubNode().setLower(4);
		root.getLowerSubNode().setUpper(5);
		root.getUpperSubNode().setLower(6);
		root.getUpperSubNode().setUpper(7);
		root.getLowerSubNode().getLowerSubNode().setLower(8);
		root.getLowerSubNode().getLowerSubNode().setUpper(9);
		root.getLowerSubNode().getUpperSubNode().setLower(10);
		root.getLowerSubNode().getUpperSubNode().setUpper(11);
		root.getUpperSubNode().getLowerSubNode().setLower(12);
		root.getUpperSubNode().getLowerSubNode().setUpper(13);
		root.getUpperSubNode().getUpperSubNode().setLower(14);
		root.getUpperSubNode().getUpperSubNode().setUpper(15);
		
		PrintStream out = System.out;
		out.println(root.toTreeString(true, false));
		
		out.println("natural tree order:");
		print(root.nodeIterator(true));
		out.println("reverse natural tree order:");
		print(root.nodeIterator(false));
		out.println("pre-order traversal, lower node first:");
		print(root.containingFirstIterator(true));
		out.println("pre-order traversal, upper node first:");
		print(root.containingFirstIterator(false));
		out.println("post-order traversal, lower node first:");
		print(root.containedFirstIterator(true));
		out.println("post-order traversal, upper node first:");
		print(root.containedFirstIterator(false));
	}
	
	static void print(Iterator<? extends BinaryTreeNode<Integer>> iterator) {
		PrintStream out = System.out;
		while(iterator.hasNext()) {
			Integer i = iterator.next().getKey();
			out.print(i);
			out.print(' ');
		}
		out.println();
		out.println();
	}
}
