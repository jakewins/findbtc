// +build !linux

package detector

import (
	"os"
)

func FileSize(path string) (int64, error){
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}

	return info.Size(), nil
}

