package main

import (
	"flag"
	"fmt"
	"github.com/jakewins/findbtc/detector"
	"time"
)

func main() {
	startOffset := flag.Int64("s", 0, "Start at byte offset")
	flag.Parse()
	path := flag.Arg(0)

	err := detector.Scan(*startOffset, path, func(detection detector.Detection) {
		fmt.Printf(
			"[main] Found possible wallet trace:\n"+
				"  %s\n", detection.Description)
	}, (&progressReporter{}).onProgress)

	if err != nil {
		fmt.Printf("[main] Exiting due to error: %s\n", err.Error())
		return
	}

	fmt.Println("[COMPLETE]")
}

const PROGRESS_REPORT_INTERVAL = 10

type progressReporter struct {
	lastReport int64
}

func (p *progressReporter) onProgress(pg detector.ProgressInfo) {
	now := time.Now().Unix()
	if now-PROGRESS_REPORT_INTERVAL > p.lastReport {
		p.lastReport = now
		additionalTargets := ""
		if pg.UnscannedTargets > 0 {
			additionalTargets = fmt.Sprintf(" (%d additional targets)", pg.UnscannedTargets)
		}

		if pg.TotalBytes <= 0 {
			fmt.Printf("[%dmb/??mb]%s\n", pg.ScannedBytes/(1024*1024), additionalTargets)
		} else {
			fmt.Printf("[%.2f%%]%s\n", (float64(pg.ScannedBytes)/float64(pg.TotalBytes))*100, additionalTargets)
		}
	}
}
