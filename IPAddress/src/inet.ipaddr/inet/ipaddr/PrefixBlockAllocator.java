package inet.ipaddr;

import java.math.BigInteger;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.format.AddressItem;

/**
 * 
 * Allocates blocks of the desired size from a set of seed blocks provided to it previously for allocation.
 * 
 * Once a prefix block allocator of generic type IPAddress has been provided with either an IPv4 or IPv6 address or subnet for allocation,
 * it can only be used with the same address version from that point onwards.  
 * In other words, it can allocate either IPv4 or IPv6 blocks, but not both.
 * 
 * @author scfoley
 *
 * @param <E> the address type
 */
public class PrefixBlockAllocator<E extends IPAddress> {
	private static final IPAddress emptyBlocks[] = new IPAddress[0];
	private IPVersion version;
	private ArrayDeque<E> blocks[];
	int reservedCount, totalBlockCount;
	
	/**
	 * Returns the count of available blocks in this allocator.
	 */
	public int getBlockCount()  {
		return totalBlockCount;
	}
	
	/** 
	 * Returns the IP version of the available blocks in the allocator,
	 * which is determined by the version of the first block made available to the allocator.
	 */
	public IPVersion getVersion()  {
		return version;
	}
	
	/**
	 * Returns the total of the count of all individual addresses available in this allocator,
	 * which is the total number of individual addresses in all the blocks.
	 */
	public BigInteger getTotalCount()   {
		if(getBlockCount() == 0) {
			return BigInteger.ZERO;
		}
		BigInteger result = BigInteger.ZERO;
		if(blocks == null) {
			return result;
		}
		IPVersion version = this.version;
		for(int i = blocks.length - 1; i >= 0; i--) {
			ArrayDeque<E> rowBlocks = blocks[i];
			if(rowBlocks == null) {
				continue;
			}
			int blockCount = rowBlocks.size();
			if(blockCount != 0) {
				BigInteger size = AddressItem.getBlockSize(IPAddress.getBitCount(version) - i);
				size = size.multiply(BigInteger.valueOf(blockCount));
				result = result.add(size);
			}
		}
		return result;
	}
	
	/**
	 * Sets the additional number of addresses to be included in any size allocation.
	 * Any request for a block of a given size will adjust that size by the given number.
	 * This can be useful when the size requests do not include the count of additional addresses that must be included in every block.
	 * For IPv4, it is common to reserve two addresses, the network and broadcast addresses.
	 * If the reservedCount is negative, then every request will be shrunk by that number, useful for cases where
	 * insufficient space requires that all subnets be reduced in size by an equal number.
	 */
	public void setReserved(int reservedCount) {
		this.reservedCount = reservedCount;
	}
	
	/**
	 * Returns the reserved count.  Use setReserved to change the reserved count.
	 */
	public int getReserved()  {
		return reservedCount;
	}

	void insertBlocks(E newBlocks[]) {
		for(int i = 0; i < newBlocks.length; i++) {
			E newBlock = newBlocks[i];
			int prefLen = newBlock.getPrefixLength();
			ArrayDeque<E> existing = blocks[prefLen];
			if(existing == null) {
				blocks[prefLen] = existing = new ArrayDeque<E>();
			}
			existing.addLast(newBlock);
			totalBlockCount++;
		}
	}
	
	/**
	 * Provides the given blocks to the allocator for allocating.
	 */
	@SuppressWarnings("unchecked")
	public void addAvailable(E ...newBlocks) {
		if(newBlocks.length == 0) {
			return;
		}
		IPVersion version = this.version;
		for(int i = 0; i < newBlocks.length; i++) {
			E block = newBlocks[i];
			if(version == null) {
				this.version = version = block.getIPVersion();
			} else if(!version.equals(block.getIPVersion())) {
				throw new IncompatibleAddressException(block, "ipaddress.error.typeMismatch");
			}
		}
		if(blocks == null){
			int size = IPAddress.getBitCount(version) + 1;
			blocks = new ArrayDeque[size];
		} else if(totalBlockCount > 0){
			ArrayList<E> newList = new ArrayList<E>(newBlocks.length + totalBlockCount);
			for(int i = 0; i < blocks.length; i++) {
				if(blocks[i] != null) {
					newList.addAll(blocks[i]);
					blocks[i].clear();
				}
			}
			newList.addAll(Arrays.asList(newBlocks));
			newBlocks = newList.toArray((E[]) new IPAddress[newList.size()]);
		}
		newBlocks = (E[]) newBlocks[0].mergeToPrefixBlocks(newBlocks);
		insertBlocks(newBlocks);
	}
	
	/**
	 * Returns a list of all the blocks available for allocating in the allocator.
	 */
	@SuppressWarnings("unchecked")
	public E[] getAvailable() {
		if(totalBlockCount == 0) {
			return (E[]) emptyBlocks;
		}
		ArrayList<E> newList = new ArrayList<E>(totalBlockCount);
		for(int i = 0; i < blocks.length; i++) {
			if(blocks[i] != null) {
				newList.addAll(blocks[i]);
			}
		}
		return newList.toArray((E[]) new IPAddress[newList.size()]);
	}
	
	/** 
	 * Allocates a block with the given bit-length,
	 * the bit-length being the number of bits extending beyond the prefix length,
	 * or nil if no such block is available in the allocator.
	 * The reserved count is ignored when allocating by bit-length.
	 */
	@SuppressWarnings("unchecked")
	public E allocateBitLength(int bitLength) {
		if(totalBlockCount == 0) {
			return null;
		}
		int newPrefixBitCount = IPAddress.getBitCount(version) - bitLength;
		E block = null;
		int i = newPrefixBitCount;
		for(; i >= 0; i--) {
			ArrayDeque<E> blockRow = blocks[i];
			if (blockRow != null && blockRow.size() > 0) {
				block = blockRow.removeFirst();
				totalBlockCount--;
				break;
			}
		}
		if(block == null || !block.isMultiple() || i == newPrefixBitCount) {
			return block;
		}
		// block is larger than needed, adjust it
		E adjustedBlock = (E) block.setPrefixLength(newPrefixBitCount, false);
		Iterator<E> blockIterator = (Iterator<E>) adjustedBlock.prefixBlockIterator();
		E result = blockIterator.next();

		// now we add the remaining from the block iterator back into the list
		IPAddressSeqRange range = blockIterator.next().getLower().spanWithRange(block.getUpper());
		insertBlocks((E[]) range.spanWithPrefixBlocks());

		return result;
	}
	
	/** 
	 * Returns a block of sufficient size,
	 * the size indicating the number of distinct addresses required in the block.
	 * AllocateSize returns null if no such block is available in the allocator,
	 * or if the size required is zero or negative.
	 * The returned block will be able to accommodate sizeRequired hosts as well as the reserved count, if any.
	 * @param sizeRequired
	 * @return
	 */
	public E allocateSize(long sizeRequired) {
		int bitsRequired;
		if(reservedCount < 0) {
			long adjustment = -reservedCount;
			if(adjustment >= sizeRequired) {
				return null;
			}
			sizeRequired -= adjustment;
			bitsRequired = AddressItem.getBitsForCount(sizeRequired);
		} else if(Long.MAX_VALUE - reservedCount < sizeRequired) {
			// 63 bits holds Long.MAX_VALUE + 1 addresses.
			// So we need to know how much total size of sizeRequired + reservedCount exceeds Long.MAX_VALUE + 1
			long extra = sizeRequired - (Long.MAX_VALUE - reservedCount) - 1;	
			if(extra == 0) {
				bitsRequired = 63;
			} else {
				bitsRequired = AddressItem.getBitsForCount(extra) + 63;
			}
		} else {
			sizeRequired += reservedCount;
			Integer bRequired = AddressItem.getBitsForCount(sizeRequired);
			if(bRequired == null) {
				return null;
			}
			bitsRequired = bRequired;
		}
		return allocateBitLength(bitsRequired);
	}
	
	/** 
	 * 
	 * Represents a block of addresses allocated for assignment to hosts.
	 * @author scfoley
	 *
	 * @param <E> the address type
	 */
	public static class AllocatedBlock<E extends IPAddress> {
		/**
		 * The number of requested addresses.
		 */
		public final BigInteger blockSize;
		
		/**
		 * The allocated prefix block.
		 */
		public final E block;
		
		/**
		 * The number of reserved addresses.
		 */
		public final int reservedCount;
		
		AllocatedBlock(E block, BigInteger blockSize, int reservedCount) {
			this.block = block;
			this.blockSize = blockSize;
			this.reservedCount = reservedCount;
		}
		
		/**
		 * Returns the total number of addresses within the block.
		 * blockSize + reservedCount will not exceed this value.
		 * @return
		 */
		public BigInteger getCount() {
			return block.getCount();
		}
		
		/** 
		 * Returns a string representation of the allocated block.
		 */
		@Override
		public String toString() {
			if( reservedCount > 0) {
				return block + " for " + blockSize + " hosts and " +
					reservedCount + " reserved addresses";
			}
			return block + " for " + blockSize + " hosts";
		}
	}

	/** 
	 * Returns multiple blocks of sufficient size for the given size required,
	 * or null if there is insufficient space in the allocator.
	 * The reserved count, if any, will be added to the required sizes.
	 */
	@SuppressWarnings("unchecked")
	public AllocatedBlock<E>[] allocateSizes(long ...blockSizes)  {
		List<Long> sizes = new ArrayList<>(blockSizes.length);
		for(int i = 0; i < blockSizes.length; i++) {
			sizes.add(blockSizes[i]);
		}
		// sort required subnets by size, largest first
		sizes.sort((one, two) -> {
			long diff = two - one;
			if(diff < 0) {
				return -1;
			} else if (diff > 0) {
				return 1;
			}
			return 0;
		});
		ArrayList<AllocatedBlock<E>> result = new ArrayList<>();
		for(int i = 0; i < sizes.size(); i++) {
			long blockSize = sizes.get(i);
			if(reservedCount < 0 && -reservedCount >= blockSize) {
				// size zero
				continue;
			}
			E allocated = allocateSize(blockSize);
			if(allocated == null) { 
				return null;
			}
			result.add(new AllocatedBlock<E>(allocated, BigInteger.valueOf(blockSize), reservedCount));
		}
		return result.toArray(new AllocatedBlock[result.size()]);
	}
	
	/**
	 * Returns multiple blocks of the given bit-lengths,
	 * or null if there is insufficient space in the allocator.
	 * The reserved count is ignored when allocating by bit-length.
	 */
	@SuppressWarnings("unchecked")
	public AllocatedBlock<E>[] allocateMultiBitLens(int ...bitLengths)  {
		List<Integer> lengths = new ArrayList<>(bitLengths.length);
		for(int i = 0; i < bitLengths.length; i++) {
			lengths.add(bitLengths[i]);
		}
		// sort required subnets by size, largest first
		lengths.sort((one, two) -> {
			long diff = two - one;
			if(diff < 0) {
				return -1;
			} else if (diff > 0) {
				return 1;
			}
			return 0;
		});
		ArrayList<AllocatedBlock<E>> result = new ArrayList<>();
		for(int i = 0; i < lengths.size(); i++) {
			int bitLength = lengths.get(i);
			E allocated = allocateBitLength(bitLength);
			if(allocated == null) { 
				return null;
			}
			BigInteger blockSize = AddressItem.getBlockSize(bitLength);
			result.add(new AllocatedBlock<E>(allocated, blockSize, 0));
		}
		return result.toArray(new AllocatedBlock[result.size()]);
	}
	
	/**
	 * Returns a string showing the counts of available blocks for each prefix size in the allocator.
	 */
	@Override
	public String toString()  {
		StringBuilder builder = new StringBuilder();
		IPVersion version = this.version;
		boolean hasBlocks = false;
		builder.append("available blocks:\n");
		if(blocks != null) {
			for(int i = blocks.length - 1; i >= 0; i--) {
				ArrayDeque<E> row = blocks[i];
				if(row != null && row.size() != 0) {
					int blockCount = row.size();
					BigInteger size = AddressItem.getBlockSize(IPAddress.getBitCount(version) - i);
					builder.append(blockCount);
					if(blockCount == 1) {
						builder.append(" block");
					} else {
						builder.append(" blocks");
					}
					builder.append(" with prefix length ").append(i).
						append(" size ").append(size).append("\n");
					hasBlocks = true;
				}
			}
		}
		if(!hasBlocks) {
			builder.append("none\n");
		}
		return builder.toString();
	}

}
