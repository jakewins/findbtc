package main

import (
	"flag"
	"fmt"
	"github.com/jakewins/wheres-wallet/detector"
)



func main() {
	startOffset := flag.Int64("s", 0, "Start at byte offset")
	flag.Parse()
	path := flag.Arg(0)

	detector.Scan(startOffset, path, func(detection detector.Detection) {
		fmt.Printf(
			"Found possible wallet trace:\n" +
			"  %s\n", detection.Description)
	})
}