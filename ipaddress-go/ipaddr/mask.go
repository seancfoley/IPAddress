package ipaddr

import (
	"math/big"
	"math/bits"
)

var (
	defaultMasker                = extendedMaskerBase{maskerBase{true}}
	defaultNonSequentialMasker   = extendedMaskerBase{}
	defaultOrMasker              = bitwiseOrerBase{true}
	defaultNonSequentialOrMasker = bitwiseOrerBase{}
)

type Masker interface {
	// GetMaskedLower provides the lowest masked value, which is not necessarily the lowest value masked
	GetMaskedLower(value, maskValue uint64) uint64

	// GetMaskedUpper provides the highest masked value, which is not necessarily the highest value masked
	GetMaskedUpper(upperValue, maskValue uint64) uint64

	// IsSequential returns whether masking all values in the range results in a sequential set of values
	IsSequential() bool
}

type maskerBase struct {
	isSequentialVal bool
}

func (masker maskerBase) GetMaskedLower(value, maskValue uint64) uint64 {
	return value & maskValue
}

func (masker maskerBase) GetMaskedUpper(upperValue, maskValue uint64) uint64 {
	return upperValue & maskValue
}

func (masker maskerBase) IsSequential() bool {
	return masker.isSequentialVal
}

var _ Masker = maskerBase{}

func newFullRangeMasker(fullRangeBit int, isSequential bool) Masker {
	return fullRangeMasker{
		fullRangeBit: fullRangeBit,
		upperMask:    ^uint64(0) >> fullRangeBit,
		maskerBase:   maskerBase{isSequential},
	}
}

// These can be cached by the int used to construct
type fullRangeMasker struct {
	maskerBase

	upperMask    uint64 //upperMask = ~0L >>> fullRangeBit;
	fullRangeBit int
}

func (masker fullRangeMasker) GetMaskedLower(value, maskValue uint64) uint64 {
	return masker.maskerBase.GetMaskedLower(value & ^masker.upperMask, maskValue)
}

func (masker fullRangeMasker) GetMaskedUpper(upperValue, maskValue uint64) uint64 {
	return masker.maskerBase.GetMaskedUpper(upperValue|masker.upperMask, maskValue)
}

func newSpecificValueMasker(lower, upper uint64) Masker {
	return specificValueMasker{lower: lower, upper: upper}
}

type specificValueMasker struct {
	maskerBase

	lower, upper uint64
}

func (masker specificValueMasker) GetMaskedLower(value, maskValue uint64) uint64 {
	return masker.maskerBase.GetMaskedLower(value, maskValue)
}

func (masker specificValueMasker) GetMaskedUpper(upperValue, maskValue uint64) uint64 {
	return masker.maskerBase.GetMaskedUpper(upperValue, maskValue)
}

// Extended maskers for handling > 64 bits

//
//
type ExtendedMasker interface {
	Masker

	GetExtendedMaskedLower(extendedValue, extendedMaskValue uint64) uint64

	GetExtendedMaskedUpper(extendedUpperValue, extendedMaskValue uint64) uint64
}

type extendedMaskerBase struct {
	maskerBase
}

func (masker extendedMaskerBase) GetExtendedMaskedLower(extendedValue, extendedMaskValue uint64) uint64 {
	return extendedValue & extendedMaskValue
}

func (masker extendedMaskerBase) GetExtendedMaskedUpper(extendedUpperValue, extendedMaskValue uint64) uint64 {
	return extendedUpperValue & extendedMaskValue
}

var _ ExtendedMasker = extendedMaskerBase{}
var _ Masker = extendedMaskerBase{}

func newExtendedFullRangeMasker(fullRangeBit int, isSequential bool) ExtendedMasker {
	var upperMask, extendedUpperMask uint64
	if fullRangeBit >= 64 {
		upperMask = ^uint64(0) >> (fullRangeBit - 64)
	} else {
		extendedUpperMask = ^uint64(0) >> fullRangeBit
		upperMask = 0xffffffffffffffff
	}
	return extendedFullRangeMasker{
		extendedUpperMask:  extendedUpperMask,
		upperMask:          upperMask,
		extendedMaskerBase: extendedMaskerBase{maskerBase{isSequential}},
	}
}

// These can be cached by the int used to construct
type extendedFullRangeMasker struct {
	extendedMaskerBase

	upperMask, extendedUpperMask uint64
}

func (masker extendedFullRangeMasker) GetMaskedLower(value, maskValue uint64) uint64 {
	return masker.extendedMaskerBase.GetMaskedLower(value & ^masker.upperMask, maskValue)
}

func (masker extendedFullRangeMasker) GetMaskedUpper(upperValue, maskValue uint64) uint64 {
	return masker.extendedMaskerBase.GetMaskedUpper(upperValue|masker.upperMask, maskValue)
}

func (masker extendedFullRangeMasker) GetExtendedMaskedLower(extendedValue, extendedMaskValue uint64) uint64 {
	return masker.extendedMaskerBase.GetExtendedMaskedLower(extendedValue & ^masker.extendedUpperMask, extendedMaskValue)
}

func (masker extendedFullRangeMasker) GetExtendedMaskedUpper(extendedUpperValue, extendedMaskValue uint64) uint64 {
	return masker.extendedMaskerBase.GetExtendedMaskedUpper(extendedUpperValue|masker.extendedUpperMask, extendedMaskValue)
}

func newExtendedSpecificValueMasker(extendedLower, lower, extendedUpper, upper uint64) ExtendedMasker {
	return extendedSpecificValueMasker{
		extendedLower: extendedLower,
		lower:         lower,
		extendedUpper: extendedUpper,
		upper:         upper,
	}
}

// These can be cached by the int used to construct
type extendedSpecificValueMasker struct {
	extendedMaskerBase

	extendedLower, lower, extendedUpper, upper uint64
}

func (masker extendedSpecificValueMasker) GetMaskedLower(value, maskValue uint64) uint64 {
	return masker.extendedMaskerBase.GetMaskedLower(masker.lower, maskValue)
}

func (masker extendedSpecificValueMasker) GetMaskedUpper(upperValue, maskValue uint64) uint64 {
	return masker.extendedMaskerBase.GetMaskedUpper(masker.upper, maskValue)
}

func (masker extendedSpecificValueMasker) GetExtendedMaskedLower(extendedValue, extendedMaskValue uint64) uint64 {
	return masker.extendedMaskerBase.GetExtendedMaskedLower(masker.extendedLower, extendedMaskValue)
}

func (masker extendedSpecificValueMasker) GetExtendedMaskedUpper(extendedUpperValue, extendedMaskValue uint64) uint64 {
	return masker.extendedMaskerBase.GetExtendedMaskedUpper(masker.extendedUpper, extendedMaskValue)
}

func newWrappedMasker(masker Masker) ExtendedMasker {
	return wrappedMasker{
		extendedMaskerBase: extendedMaskerBase{maskerBase{masker.IsSequential()}},
		masker:             masker,
	}
}

type wrappedMasker struct {
	extendedMaskerBase

	masker Masker
}

func (masker wrappedMasker) GetMaskedLower(value, maskValue uint64) uint64 {
	return masker.masker.GetMaskedLower(value, maskValue)
}

func (masker wrappedMasker) GetMaskedUpper(upperValue, maskValue uint64) uint64 {
	return masker.masker.GetMaskedUpper(upperValue, maskValue)
}

//
//
//
//
//
type BitwiseOrer interface {
	// GetMaskedLower provides the lowest masked value, which is not necessarily the lowest value masked
	GetOredLower(value, maskValue uint64) uint64

	// GetMaskedUpper provides the highest masked value, which is not necessarily the highest value masked
	GetOredUpper(upperValue, maskValue uint64) uint64

	// IsSequential returns whether masking all values in the range results in a sequential set of values
	IsSequential() bool
}

type bitwiseOrerBase struct {
	isSequentialVal bool
}

func (masker bitwiseOrerBase) GetOredLower(value, maskValue uint64) uint64 {
	return value | maskValue
}

func (masker bitwiseOrerBase) GetOredUpper(upperValue, maskValue uint64) uint64 {
	return upperValue | maskValue
}

func (masker bitwiseOrerBase) IsSequential() bool {
	return masker.isSequentialVal
}

var _ BitwiseOrer = bitwiseOrerBase{}

func newFullRangeBitwiseOrer(fullRangeBit int, isSequential bool) BitwiseOrer {
	return fullRangeBitwiseOrer{
		fullRangeBit:    fullRangeBit,
		upperMask:       ^uint64(0) >> fullRangeBit,
		bitwiseOrerBase: bitwiseOrerBase{isSequential},
	}
}

// These can be cached by the int used to construct
type fullRangeBitwiseOrer struct {
	bitwiseOrerBase

	upperMask    uint64
	fullRangeBit int
}

func (masker fullRangeBitwiseOrer) GetOredLower(value, maskValue uint64) uint64 {
	return masker.bitwiseOrerBase.GetOredLower(value & ^masker.upperMask, maskValue)
}

func (masker fullRangeBitwiseOrer) GetOredUpper(upperValue, maskValue uint64) uint64 {
	return masker.bitwiseOrerBase.GetOredUpper(upperValue|masker.upperMask, maskValue)
}

func newSpecificValueBitwiseOrer(lower, upper uint64) BitwiseOrer {
	return specificValueBitwiseOrer{lower: lower, upper: upper}
}

type specificValueBitwiseOrer struct {
	bitwiseOrerBase

	lower, upper uint64
}

func (masker specificValueBitwiseOrer) GetOredLower(value, maskValue uint64) uint64 {
	return masker.bitwiseOrerBase.GetOredLower(value, maskValue)
}

func (masker specificValueBitwiseOrer) GetOredUpper(upperValue, maskValue uint64) uint64 {
	return masker.bitwiseOrerBase.GetOredUpper(upperValue, maskValue)
}

//
//
//
//
//
func maskExtendedRange(
	value, extendedValue,
	upperValue, extendedUpperValue,
	maskValue, extendedMaskValue,
	maxValue, extendedMaxValue uint64) ExtendedMasker {

	//algorithm:
	//here we find the highest bit that is part of the range, highestDifferingBitInRange (ie changes from lower to upper)
	//then we find the highest bit in the mask that is 1 that is the same or below highestDifferingBitInRange (if such a bit exists)
	//
	//this gives us the highest bit that is part of the masked range (ie changes from lower to upper after applying the mask)
	//if this latter bit exists, then any bit below it in the mask must be 1 to include the entire range.

	extendedDiffering := extendedValue ^ extendedUpperValue
	if extendedDiffering == 0 {
		// the top is single-valued so just need to check the lower part
		masker := maskRange(value, upperValue, maskValue, maxValue)
		if masker == defaultMasker {
			return defaultMasker
		}
		return newWrappedMasker(masker)
	}
	//if(extendedValue > extendedUpperValue) {
	//	throw new IllegalArgumentException("value > upper value");
	//}
	if (maskValue == maxValue && extendedMaskValue == extendedMaxValue /* all ones mask */) ||
		(maskValue == 0 && extendedMaskValue == 0 /* all zeros mask */) {
		return defaultMasker
	}
	highestDifferingBitInRange := bits.LeadingZeros64(extendedDiffering)
	extendedDifferingMasked := extendedMaskValue & (^uint64(0) >> highestDifferingBitInRange)
	var highestDifferingBitMasked int
	if extendedDifferingMasked != 0 {
		differingIsLowestBit := (extendedDifferingMasked == 1)
		highestDifferingBitMasked = bits.LeadingZeros64(extendedDifferingMasked)
		var maskedIsSequential bool
		hostMask := ^uint64(0) >> (highestDifferingBitMasked + 1)
		if !differingIsLowestBit { // Anything below highestDifferingBitMasked in the mask must be ones.
			//for the first mask bit that is 1, all bits that follow must also be 1
			maskedIsSequential = (extendedMaskValue&hostMask) == hostMask && maskValue == maxValue //check if all ones below
		} else {
			maskedIsSequential = maskValue == maxValue
		}
		if value == 0 && extendedValue == 0 &&
			upperValue == maxValue && extendedUpperValue == extendedMaxValue {
			// full range
			if maskedIsSequential {
				return defaultMasker
			}
			return defaultNonSequentialMasker
		}
		if highestDifferingBitMasked > highestDifferingBitInRange {
			if maskedIsSequential {
				// We need to check that the range is larger enough that when chopping off the top it remains sequential

				// Note: a count of 2 in the extended could equate to a count of 2 total!
				// upper: xxxxxxx1 00000000
				// lower: xxxxxxx0 11111111
				// Or, it could be everything:
				// upper: xxxxxxx1 11111111
				// lower: xxxxxxx0 00000000
				// So for that reason, we need to check the full count here and not just extended

				countRequiredForSequential := big.NewInt(1)
				countRequiredForSequential.Lsh(countRequiredForSequential, 128-uint(highestDifferingBitMasked))

				var upperBig, lowerBig, val big.Int
				upperBig.SetUint64(extendedUpperValue).Lsh(&upperBig, 64).Or(&upperBig, val.SetUint64(upperValue))
				lowerBig.SetUint64(extendedValue).Lsh(&lowerBig, 64).Or(&lowerBig, val.SetUint64(value))
				count := upperBig.Sub(&upperBig, &lowerBig).Add(&upperBig, big.NewInt(1))
				maskedIsSequential = count.Cmp(countRequiredForSequential) >= 0
				//			BigInteger countRequiredForSequential = ONE_SHIFTED_EXTENDED[shift];
				//			if(countRequiredForSequential == null) {
				//				countRequiredForSequential = ONE_SHIFTED_EXTENDED[shift] = BigInteger.valueOf(1L << shift).shiftLeft(Long.SIZE);
				//			}
				//			BigInteger upperBig = new BigInteger(1, toBytesSizeAdjusted(upperValue, extendedUpperValue, 16));
				//			BigInteger lowerBig = new BigInteger(1, toBytesSizeAdjusted(value, extendedValue, 16));
				//			BigInteger count = upperBig.subtract(lowerBig).add(BigInteger.ONE);
				//			maskedIsSequential = count.compareTo(countRequiredForSequential) >= 0;
			}
			//		ExtendedFullRangeMasker cache[] = maskedIsSequential ? EXTENDED_SEQUENTIAL_FULL_RANGE_MASKERS : EXTENDED_FULL_RANGE_MASKERS;
			//		ExtendedFullRangeMasker result = cache[highestDifferingBitMasked];
			//		if(result == null) {
			//			cache[highestDifferingBitMasked] = result = new ExtendedFullRangeMasker(highestDifferingBitMasked, maskedIsSequential);
			//		}
			//		return result;
			return newExtendedFullRangeMasker(highestDifferingBitMasked, maskedIsSequential)
		} else if !maskedIsSequential {
			//xxx
			//countRequiredForSequential := big.NewInt(1)
			//countRequiredForSequential.Lsh(countRequiredForSequential, 128-uint(highestDifferingBitMasked))
			//

			//count := upperBig.Sub(&upperBig, &lowerBig).Add(&upperBig, big.NewInt(1))
			//maskedIsSequential = count.Cmp(countRequiredForSequential) >= 0

			//		BigInteger bigHostMask = HOST_MASK_EXTENDED[highestDifferingBitMasked];
			//		if(bigHostMask == null) {
			//			bigHostMask = BigInteger.valueOf(hostMask);
			//			bigHostMask = bigHostMask.shiftLeft(Long.SIZE);
			//			byte b = (byte) 0xff;
			//			bigHostMask = bigHostMask.or(new BigInteger(1, new byte[] {b, b, b, b, b, b, b, b}));
			//			HOST_MASK_EXTENDED[highestDifferingBitMasked] = bigHostMask;
			//		}
			//		BigInteger bigHostZeroed = NETWORK_MASK_EXTENDED[highestDifferingBitMasked];
			//		if(bigHostZeroed == null) {
			//			bigHostZeroed = NETWORK_MASK_EXTENDED[highestDifferingBitMasked] = bigHostMask.not();
			//		}
			//		BigInteger upperBig = new BigInteger(1, toBytesSizeAdjusted(upperValue, extendedUpperValue, 16));
			//		BigInteger lowerBig = new BigInteger(1, toBytesSizeAdjusted(value, extendedValue, 16));
			//		BigInteger upperToBeMaskedBig = upperBig.and(bigHostZeroed);
			//		BigInteger lowerToBeMaskedBig = lowerBig.or(bigHostMask);
			//		BigInteger maskBig = new BigInteger(1, toBytesSizeAdjusted(maskValue, extendedMaskValue, 16));

			var bigHostZeroed, bigHostMask, val big.Int
			bigHostMask.SetUint64(hostMask).Lsh(&bigHostMask, 64).Or(&bigHostMask, val.SetUint64(^uint64(0)))
			bigHostZeroed.Not(&bigHostMask)

			var upperBig, lowerBig big.Int
			upperBig.SetUint64(extendedUpperValue).Lsh(&upperBig, 64).Or(&upperBig, val.SetUint64(upperValue))
			lowerBig.SetUint64(extendedValue).Lsh(&lowerBig, 64).Or(&lowerBig, val.SetUint64(value))

			var upperToBeMaskedBig, lowerToBeMaskedBig, maskBig big.Int
			upperToBeMaskedBig.And(&upperBig, &bigHostZeroed)
			lowerToBeMaskedBig.Or(&lowerBig, &bigHostMask)
			maskBig.SetUint64(extendedMaskValue).Lsh(&maskBig, 64).Or(&maskBig, val.SetUint64(maskValue))

			for nextBit := (128 - (highestDifferingBitMasked + 1) - 1); nextBit >= 0; nextBit-- {
				// check if the bit in the mask is 1
				if maskBig.Bit(nextBit) != 0 {
					val.Set(&upperToBeMaskedBig).SetBit(&val, nextBit, 1)
					if val.Cmp(&upperBig) <= 0 {
						upperToBeMaskedBig.Set(&val)
					}
					val.Set(&lowerToBeMaskedBig).SetBit(&val, nextBit, 0)
					if val.Cmp(&lowerBig) >= 0 {
						lowerToBeMaskedBig.Set(&val)
					}
				} //else
				// keep our upperToBeMasked bit as 0
				// keep our lowerToBeMasked bit as 1
			}
			//newExtendedSpecificValueMasker(extendedLower, lower, extendedUpper, upper uint64)
			var lowerMaskedBig, upperMaskedBig big.Int
			lowerMaskedBig.Set(&lowerToBeMaskedBig).And(&lowerToBeMaskedBig, val.SetUint64(^uint64(0)))
			upperMaskedBig.Set(&upperToBeMaskedBig).And(&upperToBeMaskedBig, &val)

			//var lowerMasked, upperMasked uint64 = lowerMaskedBig.Uint64(), upperMaskedBig.Uint64()
			//var extendedLowerMasked, extendedUpperMasked uint64 = lowerToBeMaskedBig.Rsh(&lowerToBeMaskedBig, 64).Uint64(),
			//	upperToBeMaskedBig.Rsh(&upperToBeMaskedBig, 64).Uint64()

			return newExtendedSpecificValueMasker(
				lowerToBeMaskedBig.Rsh(&lowerToBeMaskedBig, 64).Uint64(),
				lowerMaskedBig.Uint64(),
				upperToBeMaskedBig.Rsh(&upperToBeMaskedBig, 64).Uint64(),
				upperMaskedBig.Uint64())

			//		for(int nextBit = 128 - (highestDifferingBitMasked + 1) - 1; nextBit >= 0; nextBit--) {
			//			if(maskBig.testBit(nextBit)) {
			//				BigInteger candidate = upperToBeMaskedBig.setBit(nextBit);
			//				if(candidate.compareTo(upperBig) <= 0) {
			//					upperToBeMaskedBig = candidate;
			//				}
			//				candidate = lowerToBeMaskedBig.clearBit(nextBit);
			//				if(candidate.compareTo(lowerBig) >= 0) {
			//					lowerToBeMaskedBig = candidate;
			//				}
			//			} //else
			//			// keep our upperToBeMaskedBig bit as 0
			//			// keep our lowerToBeMaskedBig bit as 1
			//		}
			//		return new ExtendedSpecificValueMasker(
			//				lowerToBeMaskedBig.shiftRight(Long.SIZE).longValue(),
			//				lowerToBeMaskedBig.longValue(),
			//				upperToBeMaskedBig.shiftRight(Long.SIZE).longValue(),
			//				upperToBeMaskedBig.longValue());
		}
		return defaultMasker
	}
	// When masking, the top becomes single-valued.

	// We go to the lower values to find highestDifferingBitMasked.

	// At this point, the highest differing bit in the lower range is 0
	// and the highestDifferingBitMasked is the first 1 bit in the lower mask

	if maskValue == 0 {
		// the mask zeroes out everything,
		return defaultMasker
	}
	maskedIsSequential := true
	highestDifferingBitMaskedLow := bits.LeadingZeros64(maskValue)
	if maskValue != maxValue && highestDifferingBitMaskedLow < 63 {
		//for the first mask bit that is 1, all bits that follow must also be 1
		hostMask := ^uint64(0) >> (highestDifferingBitMaskedLow + 1) // this shift of since case of highestDifferingBitMaskedLow of 64 and 63 taken care of, so the shift is < 64
		maskedIsSequential = (maskValue & hostMask) == hostMask      //check if all ones below
	}
	if maskedIsSequential {
		//Note: a count of 2 in the lower values could equate to a count of everything in the full range:
		//upper: xxxxxx10 00000000
		//lower: xxxxxxx0 11111111
		//Another example:
		//upper: xxxxxxx1 00000001
		//lower: xxxxxxx0 00000000
		//So for that reason, we need to check the full count here and not just lower values

		//We need to check that the range is larger enough that when chopping off the top it remains sequential

		countRequiredForSequential := big.NewInt(1)
		countRequiredForSequential.Lsh(countRequiredForSequential, 64-uint(highestDifferingBitMaskedLow))

		var upperBig, lowerBig, val big.Int
		upperBig.SetUint64(extendedUpperValue).Lsh(&upperBig, 64).Or(&upperBig, val.SetUint64(upperValue))
		lowerBig.SetUint64(extendedValue).Lsh(&lowerBig, 64).Or(&lowerBig, val.SetUint64(value))
		count := upperBig.Sub(&upperBig, &lowerBig).Add(&upperBig, big.NewInt(1))
		maskedIsSequential = count.Cmp(countRequiredForSequential) >= 0

		//	BigInteger countRequiredForSequential;
		//	if(highestDifferingBitMaskedLow == 0) {
		//		countRequiredForSequential = ONE_EXTENDED;
		//	} else if(highestDifferingBitMaskedLow == 1) { // need this case because 1 << 63 is a negative number
		//		countRequiredForSequential = HIGH_BIT;
		//	} else {
		//		int shift = Long.SIZE - highestDifferingBitMaskedLow;
		//		countRequiredForSequential = ONE_SHIFTED[shift];
		//		if(countRequiredForSequential == null) {
		//			countRequiredForSequential = ONE_SHIFTED[shift] = BigInteger.valueOf(1L << shift);
		//		}
		//	}
		//	BigInteger upperBig = new BigInteger(1, toBytesSizeAdjusted(upperValue, extendedUpperValue, 16));
		//	BigInteger lowerBig = new BigInteger(1, toBytesSizeAdjusted(value, extendedValue, 16));
		//	BigInteger count = upperBig.subtract(lowerBig).add(BigInteger.ONE);
		//	maskedIsSequential = count.compareTo(countRequiredForSequential) >= 0;
	}
	highestDifferingBitMasked = highestDifferingBitMaskedLow + 64
	//ExtendedFullRangeMasker cache[] = maskedIsSequential ? EXTENDED_SEQUENTIAL_FULL_RANGE_MASKERS : EXTENDED_FULL_RANGE_MASKERS;
	//ExtendedFullRangeMasker result = cache[highestDifferingBitMasked];
	//if(result == null) {
	//	cache[highestDifferingBitMasked] = result = new ExtendedFullRangeMasker(highestDifferingBitMasked, maskedIsSequential);
	//}
	//return result;
	return newExtendedFullRangeMasker(highestDifferingBitMasked, maskedIsSequential)
	//return nil
}

//func maskRange(value, upperValue, maskValue uint64) Masker {
//	return maskRange(value, upperValue, maskValue, 0xffffffffffffffff)
//}

func maskRange(value, upperValue, maskValue, maxValue uint64) Masker {
	if value == upperValue {
		return defaultMasker
	}
	//if(value > upperValue) { TODO figure out errors for address masking later
	//	throw new IllegalArgumentException("value > upper value");
	//}
	if maskValue == 0 || maskValue == maxValue {
		return defaultMasker
	}

	//algorithm:
	//here we find the highest bit that is part of the range, highestDifferingBitInRange (ie changes from lower to upper)
	//then we find the highest bit in the mask that is 1 that is the same or below highestDifferingBitInRange (if such a bit exists)

	//this gives us the highest bit that is part of the masked range (ie changes from lower to upper after applying the mask)
	//if this latter bit exists, then any bit below it in the mask must be 1 to remain sequential.

	differing := value ^ upperValue
	if differing != 1 {
		highestDifferingBitInRange := bits.LeadingZeros64(differing)
		maskMask := ^uint64(0) >> highestDifferingBitInRange
		differingMasked := maskValue & maskMask
		foundDiffering := (differingMasked != 0)
		if foundDiffering {
			// Anything below highestDifferingBitMasked in the mask must be ones.
			// Also, if we have masked out any 1 bit in the original, then anything that we do not mask out that follows must be all 1s
			highestDifferingBitMasked := bits.LeadingZeros64(differingMasked) // first one bit in the mask covering the range
			var hostMask uint64
			if highestDifferingBitMasked != 63 {
				hostMask = ^uint64(0) >> (highestDifferingBitMasked + 1)
			}
			//for the first mask bit that is 1, all bits that follow must also be 1
			maskedIsSequential := (maskValue & hostMask) == hostMask
			if maxValue == ^uint64(0) &&
				(!maskedIsSequential || highestDifferingBitMasked > highestDifferingBitInRange) {
				highestOneBit := bits.LeadingZeros64(upperValue)
				// note we know highestOneBit < 64, otherwise differing would be 1 or 0
				maxValue = ^uint64(0) >> highestOneBit
			}
			if value == 0 && upperValue == maxValue {
				// full range
				if maskedIsSequential {
					return defaultMasker
				} else {
					return defaultNonSequentialMasker
				}
			}
			if highestDifferingBitMasked > highestDifferingBitInRange {
				if maskedIsSequential {
					// the count will determine if the masked range is sequential
					if highestDifferingBitMasked < 63 {
						count := upperValue - value + 1

						// if original range is 0xxxx to 1xxxx and our mask starts with a single 0 so the mask is 01111,
						// then our new range covers 4 bits at most (could be less).
						// If the range covers 4 bits, we need to know if that range covers the same count of values as 0000 to 1111.
						// If so, the resulting range is not disjoint.
						// How do we know the range is disjoint otherwise?  We know because it has the values 1111 and 0000.
						// In order to go from 0xxxx to 1xxxx you must cross the consecutive values 01111 and 10000.
						// These values are consecutive in the original range (ie 01111 is followed by 10000) but in the new range
						// they are farthest apart and we need the entire range to fill the gap between them.
						// That count of values for the entire range is 1111 - 0000 + 1 = 10000
						// So in this example, the first bit in the original range is bit 0, highestDifferingBitMasked is 1,
						// and the range must cover 2 to the power of (5 - 1),
						// or 2 to the power of bit count - highestDifferingBitMasked, or 1 shifted by that much.

						countRequiredForSequential := uint64(1) << (64 - highestDifferingBitMasked)
						if count < countRequiredForSequential {
							// the resulting masked values are disjoint, not sequential
							maskedIsSequential = false
						}
					} // else count of 2 is good enough, even if the masked range does not cover both values, then the result is a single value, which is also sequential
					// another way of looking at it: when the range is just two, we do not need to see if the masked range covers all values in between, as there is no values in between
				}
				// The range part of the values will go from 0 to the mask itself.
				// This is because we know that if the range is 0xxxx... to 1yyyy..., then 01111... and 10000... are also in the range,
				// since that is the only way to transition from 0xxxx... to 1yyyy...
				// Because the mask has no 1 bit at the top bit, then we know that when masking with those two values 01111... and 10000...
				// we get the mask itself and 00000 as the result.
				return newFullRangeMasker(highestDifferingBitMasked, maskedIsSequential)
			} else if !maskedIsSequential {
				hostZeroed := ^hostMask
				upperToBeMasked := upperValue & hostZeroed
				lowerToBeMasked := value | hostMask
				// we find a value in the range that will produce the highest and lowest values when masked
				for nextBit := uint64(1) << (64 - (highestDifferingBitMasked + 1) - 1); nextBit != 0; nextBit >>= 1 {
					// check if the bit in the mask is 1
					if (maskValue & nextBit) != 0 {
						candidate := upperToBeMasked | nextBit
						if candidate <= upperValue {
							upperToBeMasked = candidate
						}
						candidate = lowerToBeMasked & ^nextBit
						if candidate >= value {
							lowerToBeMasked = candidate
						}
					} //else
					// keep our upperToBeMasked bit as 0
					// keep our lowerToBeMasked bit as 1
				}
				return newSpecificValueMasker(lowerToBeMasked, upperToBeMasked)
			} // else fall through to default masker
		}
	}
	return defaultMasker
}

//public static BitwiseOrer bitwiseOrRange(long value, long upperValue, long maskValue) {
//		return bitwiseOrRange(value, upperValue, maskValue, -1);
//	}
//
func bitwiseOrRange(value, upperValue, maskValue, maxValue uint64) BitwiseOrer {
	if value == upperValue {
		return defaultOrMasker
	}
	//		if(value > upperValue) {
	//			throw new IllegalArgumentException("value > upper value");
	//		}
	if maskValue == 0 || maskValue == maxValue {
		return defaultOrMasker
	}

	//algorithm:
	//here we find the highest bit that is part of the range, highestDifferingBitInRange (ie changes from lower to upper)
	//then we find the highest bit in the mask that is 0 that is the same or below highestDifferingBitInRange (if such a bit exists)

	//this gives us the highest bit that is part of the masked range (ie changes from lower to upper after applying the mask)
	//if this latter bit exists, then any bit below it in the mask must be 0 to include the entire range.

	differing := value ^ upperValue
	if differing != 1 {
		highestDifferingBitInRange := bits.LeadingZeros64(differing)
		maskMask := ^uint64(0) >> highestDifferingBitInRange
		differingMasked := maskValue & maskMask
		foundDiffering := (differingMasked != maskMask) // mask not all ones
		if foundDiffering {
			highestDifferingBitMasked := bits.LeadingZeros64(^differingMasked & maskMask) // first 0 bit in the part of the mask covering the range
			var hostMask uint64
			if highestDifferingBitMasked != 63 {
				hostMask = ^uint64(0) >> (highestDifferingBitMasked + 1)
			}
			maskedIsSequential := (maskValue & hostMask) == 0
			if maxValue == ^uint64(0) &&
				(!maskedIsSequential || highestDifferingBitMasked > highestDifferingBitInRange) {
				highestOneBit := bits.LeadingZeros64(upperValue)
				// note we know highestOneBit < 64, otherwise differing would be 1 or 0, so shift is OK
				maxValue = ^uint64(0) >> highestOneBit
			}
			if value == 0 && upperValue == maxValue {
				// full range
				if maskedIsSequential {
					return defaultOrMasker
				} else {
					return defaultNonSequentialOrMasker
				}
			}
			if highestDifferingBitMasked > highestDifferingBitInRange {
				if maskedIsSequential {
					// the count will determine if the ored range is sequential
					if highestDifferingBitMasked < 63 {
						count := upperValue - value + 1
						countRequiredForSequential := uint64(1) << (64 - highestDifferingBitMasked)
						if count < countRequiredForSequential {
							// the resulting ored values are disjoint, not sequential
							maskedIsSequential = false
						}
					}
				}
				return newFullRangeBitwiseOrer(highestDifferingBitMasked, maskedIsSequential)
			} else if !maskedIsSequential {
				hostZeroed := ^hostMask
				upperToBeMasked := upperValue & hostZeroed
				lowerToBeMasked := value | hostMask
				for nextBit := uint64(1) << (64 - (highestDifferingBitMasked + 1) - 1); nextBit != 0; nextBit >>= 1 {
					// check if the bit in the mask is 0
					if (maskValue & nextBit) == 0 {
						candidate := upperToBeMasked | nextBit
						if candidate <= upperValue {
							upperToBeMasked = candidate
						}
						candidate = lowerToBeMasked & ^nextBit
						if candidate >= value {
							lowerToBeMasked = candidate
						}
					} //else
					// keep our upperToBeMasked bit as 0
					// keep our lowerToBeMasked bit as 1
				}
				return newSpecificValueBitwiseOrer(lowerToBeMasked, upperToBeMasked)
			}
		}
	}
	return defaultOrMasker
}
