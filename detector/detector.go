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

	// The target this block came from
	source scanTarget
}

// Describes a detected wallet
type Detection struct {
	Description string
}

type ProgressInfo struct {
	// Description of the target currently being scanned
	CurrentTarget string
	// Number of bytes scanned in the current target
	ScannedBytes int64
	// Bytes in the current target
	TotalBytes int64
	// Number of targets remaining to be scanned; this may grow dynamically as new targets
	// are discovered inside existing targets (eg. compressed files)
	UnscannedTargets int
}

type TargetReader interface {
	io.ReaderAt
	io.Reader
	io.Closer
	io.Seeker
}

type scanTarget interface {
	Describe() string
	StartOffset() int64
	Size() (int64, error)
	Open() (TargetReader, error)
}

type fileScanTarget struct {
	path string
	startOffset int64
}
func (t *fileScanTarget) Describe() string {
	return t.path
}
func (t *fileScanTarget) StartOffset() int64 {
	return t.startOffset
}
func (t *fileScanTarget) Size() (int64, error) {
	return FileSize(t.path)
}
func (t *fileScanTarget) Open() (TargetReader, error) {
	f, err := os.Open(t.path)
	if err != nil {
		return nil, err
	}
	return f, nil
}

var EOF *Block = &Block{};

// Bootstrap and run the detection system, scanning the given path
// for remnants of wallets. Normally, the path given would
// be a raw device file handle, like /dev/sdb or some such; the system
// would then scan every sector of that device
func Scan(startOffset int64, path string, onDetection func(Detection), onProgress func(ProgressInfo)) (error) {
	signals := make(chan error, 10)

	scanTargets := make(chan scanTarget, 10)

	emptyBlocks := make(chan *Block, 30)
	zipDetectionQueue := make(chan *Block, 30)
	gzipDetectionQueue := make(chan *Block, 30)
	walletDetectionQueue := make(chan *Block, 30)

	for i := 0; i<20; i++ {
		emptyBlocks <- &Block{
			offset:0,
			data:make([]byte, 16*1024),
		}
	}

	onError := errorHandler([]chan *Block{emptyBlocks, zipDetectionQueue, walletDetectionQueue}, signals)
	onComplete := func() {
		signals <- io.EOF
	}

	// 1. Scan target files, breaking them into blocks of data to work with
	go scanBlocks(scanTargets, emptyBlocks, zipDetectionQueue, onProgress, onError)

	// 2. Pass blocks to zipfile detection
	go scanZipFiles(zipDetectionQueue, gzipDetectionQueue, scanTargets)

	// 3. Pass blocks to gzip file detection
	go scanGzipFiles(gzipDetectionQueue, walletDetectionQueue, scanTargets)

	// 3. And, finally, pass raw and uncompressed blocks both to wallet detection
	go detectWallets(walletDetectionQueue, emptyBlocks, onDetection, onComplete)


	// Prime the system by starting a scan of the source path
	scanTargets <- &fileScanTarget{
		startOffset:startOffset,
		path: path,
	}

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


func scanBlocks(targets chan scanTarget, emptyBlocks chan *Block, out chan *Block,
onProgress func(ProgressInfo), onError func(error)) {
	outerLoop:
		for target := range targets {
			fmt.Printf("[scan] Starting new target: % v\n", target.Describe())
			totalBytes, err := target.Size()
			fmt.Printf("[scan] Target size: %d, % v\n", totalBytes, err)
			if err != nil {
				onError(err)
				return
			}

			f, err := target.Open()
			if err != nil {
				onError(err)
				return
			}
			defer f.Close()

			if _, err = f.Seek(target.StartOffset(), 0); err != nil {
				onError(err)
				return
			}

			remainingTargets := len(targets)
			currentOffset := target.StartOffset()
			for block := range emptyBlocks {
				if block == EOF {
					fmt.Println("[scan] got EOF, exiting")
					return
				}

				read, err := f.Read(block.data)
				if err == io.EOF {
					if read == 0 {
						// Signal that we completed a target file
						out <- EOF
						continue outerLoop
					}
				} else if err != nil {
					onError(err)
					return
				}

				// Got a block; send it to be scanned
				block.offset = currentOffset
				block.location = fmt.Sprintf("%s in %dkB block at byte offset %d", target.Describe(), len(block.data)/1024, currentOffset)
				block.source = target

				currentOffset += int64(len(block.data))
				onProgress(ProgressInfo{target.Describe(), currentOffset, totalBytes, remainingTargets})

				out <- block
			}
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
	for block := range in {
		if block == EOF {
			onComplete()
			return
		}
		for _, needle := range needles {
			if(bytes.Contains(block.data, needle)) {
				onDetection(Detection{
					Description: fmt.Sprintf("Found '%s' at %s", needle, block.location),
				})
			}
		}
		out <- block
	}
}