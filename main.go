package main

import (
	"flag"
	"fmt"
	"github.com/jakewins/wheres-wallet/detector"
	"time"
)

func main() {
	startOffset := flag.Int64("s", 0, "Start at byte offset")
	flag.Parse()
	path := flag.Arg(0)

	detector.Scan(*startOffset, path, func(detection detector.Detection) {
		fmt.Printf(
			"Found possible wallet trace:\n" +
			"  %s\n", detection.Description)
	}, (&progressReporter{}).onProgress)

	fmt.Println("[COMPLETE]")
}

const PROGRESS_REPORT_INTERVAL = 10

type progressReporter struct {
	lastReport int64
}
func (p *progressReporter) onProgress(pg detector.ProgressInfo) {
	now := time.Now().Unix()
	if now - PROGRESS_REPORT_INTERVAL > p.lastReport {
		p.lastReport = now
		if pg.TotalBytes <= 0 {
			fmt.Printf("[%dmb]\n", pg.ScannedBytes / 1024 * 1024)
		} else {
			fmt.Printf("[%.2f%%]\n", float64(pg.ScannedBytes) / float64(pg.TotalBytes))
		}
	}
}