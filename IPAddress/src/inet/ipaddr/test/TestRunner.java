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

package inet.ipaddr.test;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CyclicBarrier;

import inet.ipaddr.Address;
import inet.ipaddr.AddressNetwork.PrefixConfiguration;
import inet.ipaddr.HostName;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressNetwork.HostNameGenerator;
import inet.ipaddr.IPAddressNetwork.IPAddressStringGenerator;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.MACAddressString;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv4.IPv4AddressNetwork;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.ipv6.IPv6AddressNetwork;
import inet.ipaddr.mac.MACAddress;
import inet.ipaddr.mac.MACAddressNetwork;
import inet.ipaddr.test.MACAddressTest.MACAddressKey;
import inet.ipaddr.test.MACAddressTest.MACAddressLongKey;
import inet.ipaddr.test.MACAddressTest.MACAddressStringKey;

public class TestRunner extends TestBase implements AddressCreator {
	
	public static void main(String args[]) {
		TestRunner testRunner = new TestRunner();
		for(int i=0; i<args.length; i++) {
			String arg = args[i];
			if(arg.equalsIgnoreCase("fast")) {
				HostTest.runDNS = false;
				testRunner.fullTest = false;
			} else if(arg.equalsIgnoreCase("limited")) {
				HostTest.runDNS = false;
				testRunner.limited = true;
			} else if(arg.equalsIgnoreCase("performance")) {
				HostTest.runDNS = false;
				testRunner.performance = true;
			}
		}
		testRunner.runTest();
	}

	private static interface Creator<K, V> {
		V create(K k);
	}
	
	private Creator<HostKey, HostName> hostCreator = new Creator<HostKey, HostName>() {
		@Override
		public HostName create(HostKey hostKey) {
			if(hostKey.options == null) {
				return new HostName(hostKey.keyString, TestBase.HOST_OPTIONS);
			}
			return new HostName(hostKey.keyString, hostKey.options);
		}
	};
	
	private Creator<IPAddressStringKey, IPAddressString> ipAddressStringCreator = new Creator<IPAddressStringKey, IPAddressString>() {
		@Override
		public IPAddressString create(IPAddressStringKey addressStringKey) {
			if(addressStringKey.options == null) {
				return new IPAddressString(addressStringKey.keyString, TestBase.ADDRESS_OPTIONS);
			}
			return new IPAddressString(addressStringKey.keyString, addressStringKey.options);
		}
	};
	
	private Creator<IPAddressKey, IPAddress> ipAddressCreator = new Creator<IPAddressKey, IPAddress>() {
		@Override
		public IPAddress create(IPAddressKey addressKey) {
			if(addressKey.bytes.length == 4) {
				return new IPv4Address(addressKey.bytes);
			}
			return new IPv6Address(addressKey.bytes);
		}
	};
	
	private Creator<Integer, IPv4Address> ipIntAddressCreator = new Creator<Integer, IPv4Address>() {
		@Override
		public IPv4Address create(Integer addressKey) {
			return new IPv4Address(addressKey);
		}
	};

	private Creator<MACAddressStringKey, MACAddressString> macAddressStringCreator = new Creator<MACAddressStringKey, MACAddressString>() {
		@Override
		public MACAddressString create(MACAddressStringKey addressStringKey) {
			if(addressStringKey.options == null) {
				return new MACAddressString(addressStringKey.keyString, TestBase.MAC_ADDRESS_OPTIONS);
			}
			return new MACAddressString(addressStringKey.keyString, addressStringKey.options);
		}
	};
	
	private Creator<MACAddressKey, MACAddress> macAddressCreator = new Creator<MACAddressKey, MACAddress>() {
		@Override
		public MACAddress create(MACAddressKey addressKey) {
			return new MACAddress(addressKey.bytes);
		}
	};
	
	private Creator<MACAddressLongKey, MACAddress> macAddressFromLongCreator = new Creator<MACAddressLongKey, MACAddress>() {
		@Override
		public MACAddress create(MACAddressLongKey addressKey) {
			return new MACAddress(addressKey.val, addressKey.extended);
		}
	};
	
	HostNameGenerator hostNameCache = new HostNameGenerator(new ConcurrentHashMap<String, HostName>(), TestBase.HOST_OPTIONS, false);
	IPAddressStringGenerator ipAddressStringCache = new IPAddressStringGenerator(new ConcurrentHashMap<String, IPAddressString>(), TestBase.ADDRESS_OPTIONS);
	
	@Override
	public HostName createHost(HostKey key) {
		if(CACHING) {
			return cache.getFromHostMap(key, hostCreator);
		}
		return hostCreator.create(key);
	}
	
	@Override
	public IPAddressString createAddress(IPAddressStringKey key) {
		if(CACHING) {
			return cache.getFromAddressStringMap(key, ipAddressStringCreator);
		}
		return ipAddressStringCreator.create(key);
	}
	
	@Override
	public MACAddressString createMACAddress(MACAddressStringKey key) {
		if(CACHING) {
			return cache.getFromAddressStringMap(key, macAddressStringCreator);
		}
		return macAddressStringCreator.create(key);
	}
	
	@Override
	public IPAddress createAddress(byte bytes[]) {
		IPAddressKey key = new IPAddressKey(bytes);
		if(CACHING) {
			return cache.getFromAddressMap(key, ipAddressCreator);
		}
		return ipAddressCreator.create(key);
	}

	@Override
	public IPv4Address createAddress(int val) {
		Integer key = Integer.valueOf(val);
		if(CACHING) {
			return cache.getFromAddressMap(key, ipIntAddressCreator);
		}
		return ipIntAddressCreator.create(key);
	}
	
	@Override
	public MACAddress createMACAddress(byte[] bytes) {
		MACAddressKey key = new MACAddressKey(bytes);
		if(CACHING) {
			return cache.getFromAddressMap(key, macAddressCreator);
		}
		return macAddressCreator.create(key);
	}
	
	@Override
	public MACAddress createMACAddress(long val, boolean extended) {
		MACAddressLongKey key = new MACAddressLongKey(val, extended);
		if(CACHING) {
			return cache.getFromAddressMap(key, macAddressFromLongCreator);
		}
		return macAddressFromLongCreator.create(key);
	}
	
	
	static boolean DEBUG_CACHE;
	
	private static class Cache implements Serializable {

		private static final long serialVersionUID = 4L;
		
		ConcurrentHashMap<IPAddressStringKey, IPAddressString> cachingIPStringMap = new ConcurrentHashMap<IPAddressStringKey, IPAddressString>();
		ConcurrentHashMap<IPAddressKey, IPAddress> cachingIPMap = new ConcurrentHashMap<IPAddressKey, IPAddress>();
		ConcurrentHashMap<Integer, IPv4Address> cachingIPIntMap = new ConcurrentHashMap<Integer, IPv4Address>();
		ConcurrentHashMap<MACAddressStringKey, MACAddressString> cachingMACStringMap = new ConcurrentHashMap<MACAddressStringKey, MACAddressString>();
		ConcurrentHashMap<MACAddressKey, MACAddress> cachingMACMap = new ConcurrentHashMap<MACAddressKey, MACAddress>();
		ConcurrentHashMap<MACAddressLongKey, MACAddress> cachingMACLongMap = new ConcurrentHashMap<MACAddressLongKey, MACAddress>();
		ConcurrentHashMap<HostKey, HostName> cachingHostMap = new ConcurrentHashMap<HostKey, HostName>();
		
		private static <K, V> V getFromMap(Map<K, V> map, K key, Creator<K, V> creator) {
			V result = map.get(key);
			if(result == null) {
				synchronized(map) {
					result = map.get(key);
					if(result == null) {
						result = creator.create(key);
						map.put(key, result);
					} else {
						if(DEBUG_CACHE) {
							System.out.println("reusing " + result);
						}
					}
				}
			} else {
				if(DEBUG_CACHE) {
					System.out.println("reusing " + result);
				}
			}
			return result;
		}
		
		IPv4Address getFromAddressMap(Integer key, Creator<Integer, IPv4Address> addressCreator) {
			return getFromMap(cachingIPIntMap, key, addressCreator);
		}
		
		IPAddress getFromAddressMap(IPAddressKey key, Creator<IPAddressKey, IPAddress> addressCreator) {
			return getFromMap(cachingIPMap, key, addressCreator);
		}
		
		IPAddressString getFromAddressStringMap(IPAddressStringKey key, Creator<IPAddressStringKey, IPAddressString> addressStringCreator) {
			return getFromMap(cachingIPStringMap, key, addressStringCreator);
		}
		
		MACAddress getFromAddressMap(MACAddressKey key, Creator<MACAddressKey, MACAddress> addressCreator) {
			return getFromMap(cachingMACMap, key, addressCreator);
		}
		
		MACAddress getFromAddressMap(MACAddressLongKey key, Creator<MACAddressLongKey, MACAddress> addressCreator) {
			return getFromMap(cachingMACLongMap, key, addressCreator);
		}
		
		MACAddressString getFromAddressStringMap(MACAddressStringKey key, Creator<MACAddressStringKey, MACAddressString> addressStringCreator) {
			return getFromMap(cachingMACStringMap, key, addressStringCreator);
		}
		
		HostName getFromHostMap(HostKey key, Creator<HostKey, HostName> hostCreator) {
			return getFromMap(cachingHostMap, key, hostCreator);
		}
		
		void clear() {
			cachingIPStringMap.clear();
			cachingIPMap.clear();
			cachingHostMap.clear();
			cachingMACMap.clear();
			cachingMACStringMap.clear();
		}
		
		@Override
		public boolean equals(Object o) {
			if(o instanceof Cache) {
				Cache other = (Cache) o;
				return cachingIPStringMap.equals(other.cachingIPStringMap) &&
						cachingIPMap.equals(other.cachingIPMap) && 
						cachingHostMap.equals(other.cachingHostMap);
			}
			return false;
		}
		
		@Override
		public String toString() {
			return "IPAddressString count: " + cachingIPStringMap.size() + "; IPAddress count: " + cachingIPMap.size() + "; Host count: " + cachingHostMap.size() + "; "
					+ "; MACAddressString count: " + cachingMACStringMap.size() + "; MACAddress count: " + cachingMACMap.size();
		}
	}
	
	public Cache serialize(Cache input) throws IOException, ClassNotFoundException {
		EfficientByteArrayOuputStream outmine = new EfficientByteArrayOuputStream();
		ObjectOutput outputmine = new ObjectOutputStream(outmine);
		outputmine.writeObject(input);
		outputmine.close();
		List<? extends byte[]> bytesmine = outmine.getBytes();
		EfficientByteArrayInputStream inmine = new EfficientByteArrayInputStream(bytesmine);
		ObjectInput inputmine = null;
		Cache result = null;
		try {
			inputmine = new ObjectInputStream(inmine);
			result = (Cache) inputmine.readObject();
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
	
	public static class EfficientByteArrayOuputStream extends OutputStream {
		public static final int BOUNDARY_SIZE = 1024;
		final LinkedList<byte[]> streamList = new LinkedList<byte[]>();
		private int currentCount;
		
		public EfficientByteArrayOuputStream() {
			add();
		}
		
		List<? extends byte[]> getBytes() {
			ArrayList<byte[]> result = new ArrayList<byte[]>(streamList);
			int lastIndex = result.size() - 1;
			if(currentCount < BOUNDARY_SIZE) {
				byte last[] = streamList.getLast();
				last = Arrays.copyOf(last, currentCount);
				result.add(lastIndex, last);
			}
			return result;
		}
		
		byte[] toByteArray() {
			byte result[] = new byte[getCount()];
			int current = 0;
			for(int i = 0; i < streamList.size() - 1; i++, current += BOUNDARY_SIZE) {
				byte bytes[] = streamList.get(i);
				System.arraycopy(bytes, 0, result, current, BOUNDARY_SIZE);
			}
			byte last[] = streamList.getLast();
			System.arraycopy(last, 0, result, current, currentCount);
			return result;
		}
		
		int getCount() {
			int total = 0;
			for(byte bytes[] : streamList) {
				total += bytes.length;
			}
			total -= (BOUNDARY_SIZE - currentCount);
			return total;
		}
		
		private byte[] add() {
			byte toAdd[] = new byte[BOUNDARY_SIZE];
			streamList.add(toAdd);
			currentCount = 0;
			return toAdd;
		}
		
		@Override
		public void write(int b) throws IOException {
			byte current[];
			if(currentCount == BOUNDARY_SIZE) {
				current = add();
			} else {
				current = streamList.getLast();
			}
			current[currentCount++] = (byte) b;
		}

	    @Override
		public void write(byte b[], int off, int len) throws IOException {
	    	byte current[] = streamList.getLast();
	    	while(currentCount + len > BOUNDARY_SIZE) {
		    	int toWrite = BOUNDARY_SIZE - currentCount;
		    	System.arraycopy(b, off, current, currentCount, toWrite);
		    	len -= toWrite;
		    	off += toWrite;
		    	current = add();
		    }
	    	System.arraycopy(b, off, current, currentCount, len);
	    	currentCount += len;
	    }
	}
	
	public static class EfficientByteArrayInputStream extends InputStream {
		private LinkedList<byte[]> streamList;
		private int currentCount;
		private int totalRead;
		
		EfficientByteArrayInputStream(List<? extends byte[]> initial) {
			streamList = new LinkedList<byte[]>(initial);
		}
		
		@Override
		public int read() throws IOException {
			if(streamList.isEmpty()) {
				return -1;
			}
			byte current[] = streamList.getFirst();
			int result = current[currentCount++];
			if(currentCount == current.length) {
				remove();
			}
			totalRead++;
			return result;
		}
		
		void remove() {
			currentCount = 0;
			streamList.removeFirst();
		}

	    @Override
		public int read(byte b[], int off, int len) throws IOException {
	    	int originalLen = len;
	    	if(streamList.isEmpty()) {
				return -1;
			}
	    	byte current[] = streamList.getFirst();
	    	while(currentCount + len >= current.length) {
	    		int bytes = current.length - currentCount;
	    		System.arraycopy(current, currentCount, b, off, bytes);
	    		len -= bytes;
	    		off += bytes;
	    		remove();
	    		if(streamList.isEmpty()) {
	    			return originalLen - len;
	    		}
	    		current = streamList.getFirst();
	    	}
	    	System.arraycopy(current, currentCount, b, off, len);
	    	currentCount += len;
	    	totalRead += len;
	    	return originalLen;
	    }
	    
	    int getBytesRead() {
	    	return totalRead;
	    }
	}
	
	private Cache cache = new Cache();
	private boolean CACHING; //set to true to share the same address and host objects among all tests

	boolean fullTest = true;//set this to false to exclude slow-running tests
	boolean limited = false;//set this to true to exclude caching and threading tests
	boolean performance = false;//set this to true to run performance tests
	
	TestRunner() {
		super(null);
	}
	
	@Override
	void runTest() {
		PrefixConfiguration ordering[] = new PrefixConfiguration[] {
			PrefixConfiguration.ALL_PREFIXED_ADDRESSES_ARE_SUBNETS,
			PrefixConfiguration.PREFIXED_ZERO_HOSTS_ARE_SUBNETS,
			PrefixConfiguration.EXPLICIT_SUBNETS,
		};
		int count = 0;
		while(count < ordering.length) {
			showMessage("");
			PrefixConfiguration prefConf = ordering[count++];
			TestBase.prefixConfiguration = prefConf;
			IPv4AddressNetwork.setDefaultPrefixConfiguration(prefConf);
			IPv6AddressNetwork.setDefaultPrefixConfiguration(prefConf);
			MACAddressNetwork.setDefaultPrefixConfiguration(prefConf);
			showMessage("testing with " + prefConf);
			showMessage("count of 1.2.0.0/16 is " + new IPAddressString("1.2.0.0/16").getAddress().getCount());
			showMessage("count of 1.2.3.4/16 is " + new IPAddressString("1.2.3.4/16").getAddress().getCount());
			runBattery();
			Address.defaultIpv4Network().clearCaches();
			Address.defaultIpv6Network().clearCaches();
			Address.defaultMACNetwork().clearCaches();
		}
	}
	
	void runBattery() {
		CACHING = false;
		failures = new Failures();
		perf = new Perf();
		
		showMessage("Starting " + getClass().getSimpleName());
		//long startTime = System.currentTimeMillis();
		long startTime = System.nanoTime();
		
		runPerf(startTime);
		
		failures.add(testAll());
		
		if(!limited) {
		
			//now set the caching and do it again
			CACHING = true;
			failures.add(testAll());
			failures.add(testAll());
	
			//now multi-threaded with the caching
			Thread threads[] = runInThreads(10, new Runnable() {
				@Override
				public void run() {
					failures.add(testAll());
				}
			});

			try {
				for(Thread thread : threads) {
					thread.join();
				}
				
				//now use caching but start with a fresh cache, to test synchronization better
				cache.clear();
				
				threads = runInThreads(10, new Runnable() {
					@Override
					public void run() {
						failures.add(testAll());
					}
				});
				Thread threads2[] = runInThreads(5, new Runnable() {
					@Override
					public void run() {
						failures.add(testAll());
					}
				});
				for(Thread thread : threads) {
					thread.join();
				}
				for(Thread thread : threads2) {
					thread.join();
				}
			} catch(InterruptedException e) {
				e.printStackTrace();
			}
			
			try {
				Cache oldCache = cache;
				cache = serialize(oldCache);
				//DEBUG_CACHE = true;
				if(!oldCache.equals(cache)) {
					failures.numTested++;
					failures.failures.add(new Failure("serialized cache mismatch"));
					System.out.println("cache is same: " + oldCache.equals(cache));
				}
				failures.add(testAll());
			} catch(IOException | ClassNotFoundException e) {
				failures.numTested++;
				failures.failures.add(new Failure(e.toString()));
			}
			runPerf(System.nanoTime());
		}
		report();
		showMessage("Done in " + (System.nanoTime() - startTime)/1000000 + " milliseconds");
		cache.clear();
		
	}

	private void runPerf(long startTime) {
		if(performance) {
			long perfStartTime = startTime;
			for(int i = 0; i < 10; i++) {
				failures.add(testAll());
				//long endTime = System.currentTimeMillis();
				long endTime = System.nanoTime();
				long totalTime = endTime - perfStartTime;
				perf.addTime(totalTime);
				perfStartTime = endTime;
			}
		}
	}
	
	Thread[] runInThreads(int numThreads, final Runnable runnable) {
		Thread threads[] = new Thread[numThreads];
		final CyclicBarrier barrier = new CyclicBarrier(numThreads);
		for(int i = 0; i < numThreads; i++) {
			Thread thread = new Thread() {
				@Override
				public void run() {
					try {
						barrier.await();
						runnable.run();
					} catch (InterruptedException | BrokenBarrierException e) {
						e.printStackTrace();
					}
				}
			};
			threads[i] = thread;
			thread.start();
		}
		return threads;
	}
	
	public Failures testAll() {
		Failures failures = new Failures();
		TestBase tests[] = new TestBase[] {
					new SpecialTypesTest(this),
					new IPAddressTest(this),
					new HostTest(this),
					new IPAddressRangeTest(this),
					new IPAddressAllTest(this),
					new HostRangeTest(this),
					new HostAllTest(this),
					new MACAddressTest(this),
					new MACAddressRangeTest(this),
					new AddressOrderTest(this)
				};
		for(TestBase test : tests) {
			test.fullTest = fullTest;
			test.runTest();
			failures.add(test.failures);
		}
		return failures;
	}
}
