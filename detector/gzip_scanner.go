package detector

import (
	"bytes"
	"fmt"
	"compress/gzip"
	"io"
)

// GZIP format: https://tools.ietf.org/html/rfc1952

var GZIP_HEADER = []byte{0x1f, 0x8b}

type gzipScanTarget struct {
	source scanTarget
	gzipOffset int64
}
func (t *gzipScanTarget) Describe() string {
	return fmt.Sprintf("Gzipfile @ byte %d in [%s]", t.gzipOffset, t.source.Describe())
}
func (t *gzipScanTarget) StartOffset() int64 {
	return 0
}
func (t *gzipScanTarget) Size() (int64, error) {
	return -1, nil
}
func (t *gzipScanTarget) Open() (TargetReader, error) {
	f, err := t.source.Open()
	if err != nil {
		return nil, err
	}

	if _, err := f.Seek(t.gzipOffset, 0); err != nil {
		return nil, err
	}

	reader, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}

	return &gzipTargetReader{reader, f}, nil
}


type gzipTargetReader struct {
	r *gzip.Reader
	fc io.Closer
}
func (r *gzipTargetReader) ReadAt(p []byte, off int64) (n int, err error) {
	return -1, fmt.Errorf("Indexed reads of gzip files not yet implemented")
}
func (r *gzipTargetReader) Read(p []byte) (n int, err error) {
	return r.r.Read(p)
}
func (r *gzipTargetReader) Seek(offset int64, whence int) (int64, error) {
	if offset == 0 {
		return 0, nil
	}
	return 0, fmt.Errorf("Seeking not implemented for gzip files")
}
func (r *gzipTargetReader) Close() error {
	defer r.fc.Close()
	return r.r.Close()
}

func scanGzipFiles(in, out chan *Block, scanTargets chan scanTarget) {
	openedFiles := 0
	for block := range in {
		if block == EOF {
			if openedFiles > 0 {
				openedFiles -= 1
				continue
			}

			out <- EOF
			continue
		}

		gzipOffset := int64(bytes.Index(block.data, GZIP_HEADER))
		if gzipOffset != -1 {
			openedFiles += scanGzipFile(block.source, block.offset + gzipOffset, scanTargets)
		}

		// Forward the raw block for other scanners
		out <- block
	}
}


func scanGzipFile(source scanTarget, gzipOffset int64, scanTargets chan scanTarget) int {
	// Sanity check
	f, err := source.Open()
	if err != nil {
		return 0
	}
	defer f.Close()
	if _, err = f.Seek(gzipOffset, 0); err != nil {
		return 0
	}

	r, err := gzip.NewReader(f)
	if err != nil {
		return 0
	}
	defer r.Close()
	if _, err = r.Read(make([]byte, 1)); err != nil {
		return 0
	}

	scanTargets <- &gzipScanTarget{
		source:source,
		gzipOffset:gzipOffset,
	}

	return 1
}
