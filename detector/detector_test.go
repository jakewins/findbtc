package detector_test

import (
	"testing"
	"github.com/jakewins/wheres-wallet/detector"
	"reflect"
)

func TestFindsRegularWallet(t *testing.T) {
	recorder := &detectionRecorder{}

	detector.Scan(0, "./test_wallet.dat", recorder.OnDetection, recorder.OnProgress)

	expected := []detector.Detection{
		{"Found 'bestblock' at ./test_wallet.dat in 16kB block at byte offset 0"},
		{"Found 'defaultkey' at ./test_wallet.dat in 16kB block at byte offset 0"},
		{"Found 'bestblock' at ./test_wallet.dat in 16kB block at byte offset 0"},
	}
	if !reflect.DeepEqual(expected, recorder.detections) {
		t.Errorf("Expected %v to be %v", recorder.detections, expected)
	}
}

type detectionRecorder struct {
	detections []detector.Detection
}
func (r *detectionRecorder) OnDetection(detection detector.Detection) {
	r.detections = append(r.detections, detection)
}
func (r *detectionRecorder) OnProgress(pg detector.ProgressInfo) {
}