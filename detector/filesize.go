package detector

import (
	"os"
	"syscall"
	"golang.org/x/sys/unix"
	"unsafe"
)

func FileSize(path string) (int64, error){
	// 1. Try just stat'ing the file
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}

	if info.Size() > 0 {
		// Stat got the file size, good times
		return info.Size(), nil
	}

	// 2. Ok, assume we've got a *nix block device then, need to use ioctl to get device size
	f, err := os.Open(path)
	defer f.Close()

	size := int64(0)
	sizePtr := uintptr(unsafe.Pointer(&size))
	_, _, errNo := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), unix.BLKGETSIZE64, sizePtr)

	if errNo != 0 {
		return 0, errNo
	}

	return size, nil
}


