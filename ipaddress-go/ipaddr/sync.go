package ipaddr

// write barrier - we want to read a memory location
// barrier flushes all pipelines and write caches for other processors
// so we read the authentic value
//
// read barrier - we want to write a memory location
// synchronise with any outstanding writes to memory
// so that it gets the value we write
//
// with our pattern:
// if !isSet
//		lock
//		do our initialization
//		set isSet
//		unlock
//	end if
//
// - we do not need a read barrier for isSet (we can only write one value), so doesn't matter if others writing isSet
// - we do not need a write barrier, we don't care if we read an earlier value saying it was done, because initMultAndPrefLen can be done twice
// But then we may get data race errors when using the data race detector.
// The most important one to remove is the first read because it may happen often.
//
// I guess we also want atomicity, but you get that just from doing an atomic write.
// https://preshing.com/20130618/atomic-vs-non-atomic-operations/ claims both needed, but that is really only if they truly operate on same var
// which is not really true here.  Here it is ok if we read something out-of-date.  Can we get torn reads/writes?  Not with a bool.
// Check this code: https://golang.org/src/sync/once.go
// Load (of "done") is done with atomic.  But after lock acquired, it is done without atomic.
// Since holding the lock means no write can occur, I guess that makes sense.
//
// if !isSet <-- no lock.  (a) it may not be atomic, but we do not care (atomicity).  we also do not care if a write is pending (visibility).  Ordering does not apply for a single var.
//		lock
//		do our initialization
//		set isSet <- atomic lock.  we do not care about atomic or visibility (because it can be done twice) and ordering does not apply.   BUT we want to avoid warnings from the race-detector.
//		unlock
//	end if

//// A flag is set just once by just one goroutine
//type atomicFlag struct {
//	val uint32
//}
//
////func (a *atomicFlag) isSet() bool {
////	return atomic.LoadUint32(&a.val) != 0
////}
//
//func (a *atomicFlag) isSetNoSync() bool {
//	return a.val != 0
//}
//
//func (a *atomicFlag) isNotSetNoSync() bool {
//	return a.val == 0
//}
//
//func (a *atomicFlag) set() {
//
//	think about our pattern that we use everywhere
//	field b
//	field val
//
//	if b // non-atomic
//		lock
//			if b // non-atomic
//			set val
//			set !b // atomic?
//		unlock
//	end if
//	return val
//
//	We can never have an invalid "val" in memory.
//	Unless the write to b were reordered to before the setting of val
//	We don't care if we read an invalid b
//	It just makes us initMultAndPrefLen the thing twice
//	We do care if
//	1. somehow b could be flipped before val is set
//	Or
//	2. if our read of val was reordered to happen before we check b
//
//	I guess those those two things can happen
//	I guess that means we atomic read b?
//	What if val were obtained through b?  that would work
//
//	But hold on, doOnce has the same problem, it must ensure whatever is done by the func f,
//	we see those effects if we see the changed bool.
//	This suggests we are good for 1.
//
//	https://preshing.com/20130618/atomic-vs-non-atomic-operations/
//
//	I don't know, seems as though I have read everywhere that you need atomic on both the read and write.
//	But I think you can use an atomic pointer perhaps.  That eliminates the double var problem,
//	if you are getting the memory with the var you want from the synchronized var.
//
//	So, that would once again required an update to this code.
//
//	It would be similar to sync.Value
//	Except that the read need to be atomic
//
//	Either that or use teh doOnce pattern which uses atomics on both.
//
//	*/
//	atomic.StoreUint32(&a.val, 1)
//}

//func (a *atomicFlag) setNoSync() {
//	a.val = 1
//}

//func (a *atomicFlag) unset() {
//	atomic.StoreUint32(&a.val, 0)
//}

//type CreationLock struct { //xxx get rid of this, then get rid of this file xxxx
//	created    atomicFlag // to check if created
//	createLock sync.Mutex // acquire to create
//}
//
//func (lock *CreationLock) isItemCreated() bool {
//	return lock.created.isSetNoSync()
//}
//
//func (lock *CreationLock) create(creator func()) (ret bool) {
//	lock.createLock.Lock()
//	if lock.created.isNotSetNoSync() {
//		creator()
//		ret = true
//		lock.created.set()
//	}
//	lock.createLock.Unlock()
//	return
//}
