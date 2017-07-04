package detector

import (
"bytes"
"fmt"
	"os"
	"io"
)

// A block of data being worked on
type Block struct {
	offset int64
	data []byte

	// Describe how to find this block of data
	location string
}

// Describes a detected wallet
type Detection struct {
	Description string
}

type ProgressInfo struct {
	ScannedBytes int64
	TotalBytes int64
}

var EOF *Block = &Block{};

// Bootstrap and run the detection system, scanning the given path
// for remnants of wallets. Normally, the path given would
// be a raw device file handle, like /dev/sdb or some such; the system
// would then scan every sector of that device
func Scan(startOffset int64, path string, onDetection func(Detection), onProgress func(ProgressInfo)) (error) {
	signals := make(chan error, 10)
	emptyPages := make(chan *Block, 30)
	scannerQueue := make(chan *Block, 30)

	for i := 0; i<20; i++ {
		emptyPages <- &Block{
			offset:0,
			data:make([]byte, 16*1024),
		}
	}

	onError := errorHandler([]chan *Block{emptyPages, scannerQueue}, signals)
	onComplete := func() { signals <- io.EOF }

	go scanBlocks(path, startOffset, emptyPages, scannerQueue, onProgress, onError)
	go detectWallets(scannerQueue, emptyPages, onDetection, onComplete)

	// Wait for system to signal outcome
	signal := <- signals
	if signal == io.EOF {
		return nil
	}

	return signal
}

func errorHandler(blockChannels []chan *Block, signals chan error) func(error) {
	return func(err error) {
		// 1. Signal that there was an error
		signals <- err

		// 2. Shut down everything
		for _, ch := range blockChannels {
			ch <- EOF
		}
	}
}


func scanBlocks(path string, startOffset int64, emptyPages chan *Block, out chan *Block,
onProgress func(ProgressInfo), onError func(error)) {
	totalBytes, err := FileSize(path)
	if err != nil {
		onError(err)
		return
	}

	f, err := os.Open(path)
	if err != nil {
		onError(err)
		return
	}
	defer f.Close()

	if _, err = f.Seek(startOffset, 0); err != nil {
		onError(err)
		return
	}

	currentOffset := startOffset
	for page := range emptyPages {
		if page == EOF {
			return
		}

		read, err := f.Read(page.data)
		if err == io.EOF && read == 0 {
			out <- EOF
			return
		} else if err != nil {
			onError(err)
			return
		}

		// Got a block; send it to be scanned
		page.offset = currentOffset
		page.location = fmt.Sprintf("%s in %dkB block at byte offset %d", path, len(page.data)/1024, currentOffset)

		onProgress(ProgressInfo{currentOffset, totalBytes})

		out <- page
	}
}

// BTC wallets are Berkeley DBs, details on them here: https://github.com/berkeleydb/libdb/blob/master/src/dbinc/db.in
// The byte chunks below are btc-specific keys that appear in wallets.
var needles = [][]byte{
	[]byte("orderposnext"),
	[]byte("addrIncoming"),
	[]byte("bestblock"),
	[]byte("defaultkey"),
	[]byte("acentry"),
}

// Scan blocks for traces of bitcoin wallets, the function will
// wait in blocks on in until it sees EOF, and output scanned blocks
// to out for reuse.
func detectWallets(in chan *Block, out chan *Block, onDetection func(Detection), onComplete func()) {
	for {
		page := <- in
		if page == EOF {
			onComplete()
			return
		}
		for _, needle := range needles {
			if(bytes.Contains(page.data, needle)) {
				onDetection(Detection{
					Description: fmt.Sprintf("Found '%s' at %s", needle, page.location),
				})
			}
		}
		out <- page
	}
}