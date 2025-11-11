package common

import (
	"sync"

	"github.com/cespare/xxhash/v2"
)

const (
	UDPLocksCount    = 512
	UDPLocksAndOpVal = 511
)

var udpLocks [UDPLocksCount]sync.Mutex

func LockKey(key string) {
	hashVal := xxhash.Sum64String(key)
	lockID := hashVal & UDPLocksAndOpVal
	udpLocks[lockID].Lock()
}

func UnlockKey(key string) {
	hashVal := xxhash.Sum64String(key)
	lockID := hashVal & UDPLocksAndOpVal
	udpLocks[lockID].Unlock()
}
