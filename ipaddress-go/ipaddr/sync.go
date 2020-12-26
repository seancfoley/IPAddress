package ipaddr

import (
	"sync"
	"sync/atomic"
)

// A flag is set just once by just one goroutine
type atomicFlag struct {
	val uint32
}

func (a *atomicFlag) isSet() bool {
	return atomic.LoadUint32(&a.val) > 0
}

func (a *atomicFlag) set() {
	atomic.StoreUint32(&a.val, 1)
}

func (a *atomicFlag) unset() {
	atomic.StoreUint32(&a.val, 0)
}

type CreationLock struct {
	createdx    atomicFlag // to check if created //TODO rename back to createdx and createLockx
	createLockx sync.Mutex // acquire to create
}

func (lock *CreationLock) isCreated() bool {
	return lock.createdx.isSet()
}

func (lock *CreationLock) create(creator func()) (ret bool) {
	lock.createLockx.Lock()
	if !lock.isCreated() {
		creator()
		ret = true
		lock.createdx.set()
	}
	lock.createLockx.Unlock()
	return
}
