package ipaddr

import (
	"sync"
	"sync/atomic"
)

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
// - we do not need a write barrier, we don't care if we read an earlier value saying it was done, because init can be done twice
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

// A flag is set just once by just one goroutine
type atomicFlag struct {
	val uint32
}

func (a *atomicFlag) isSet() bool {
	return atomic.LoadUint32(&a.val) != 0
}

func (a *atomicFlag) isSetNoSync() bool {
	return a.val == 0
}

func (a *atomicFlag) set() {
	atomic.StoreUint32(&a.val, 1)
}

func (a *atomicFlag) setNoSync() {
	a.val = 1
}

//func (a *atomicFlag) unset() {
//	atomic.StoreUint32(&a.val, 0)
//}

type CreationLock struct {
	created    atomicFlag // to check if created
	createLock sync.Mutex // acquire to create
}

func (lock *CreationLock) isItemCreated() bool {
	return lock.created.isSetNoSync()
}

func (lock *CreationLock) create(creator func()) (ret bool) {
	lock.createLock.Lock()
	if !lock.created.isSetNoSync() {
		creator()
		ret = true
		lock.created.set()
	}
	lock.createLock.Unlock()
	return
}
