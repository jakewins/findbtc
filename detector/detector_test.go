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
		{"Found 'bestblock' at ./test_wallet.dat in 16kB block at byte offset 49152"},
		{"Found 'defaultkey' at ./test_wallet.dat in 16kB block at byte offset 49152"},
		{"Found 'bestblock' at ./test_wallet.dat in 16kB block at byte offset 81920"},
	}
	if !reflect.DeepEqual(expected, recorder.detections) {
		t.Errorf("Expected %v to be %v", recorder.detections, expected)
	}
}

func TestFindsWalletInZipFile(t *testing.T) {
	recorder := &detectionRecorder{}

	detector.Scan(0, "./test_wallet.dat.zip", recorder.OnDetection, recorder.OnProgress)

	expected := []detector.Detection{
		{"Found 'bestblock' at Zipfile #0 @ byte 0 in [./test_wallet.dat.zip] in 16kB block at byte offset 49152"},
		{"Found 'defaultkey' at Zipfile #0 @ byte 0 in [./test_wallet.dat.zip] in 16kB block at byte offset 49152"},
		{"Found 'bestblock' at Zipfile #0 @ byte 0 in [./test_wallet.dat.zip] in 16kB block at byte offset 81920"},
	}
	if !reflect.DeepEqual(expected, recorder.detections) {
		t.Errorf("Expected %v to be %v", recorder.detections, expected)
	}
}

func TestFindsWalletInGzipFile(t *testing.T) {
	recorder := &detectionRecorder{}

	detector.Scan(0, "./test_wallet.dat.tar.gz", recorder.OnDetection, recorder.OnProgress)

	expected := []detector.Detection{
		{"Found 'bestblock' at Gzipfile @ byte 0 in [./test_wallet.dat.tar.gz] in 16kB block at byte offset 49152"},
		{"Found 'defaultkey' at Gzipfile @ byte 0 in [./test_wallet.dat.tar.gz] in 16kB block at byte offset 49152"},
		{"Found 'bestblock' at Gzipfile @ byte 0 in [./test_wallet.dat.tar.gz] in 16kB block at byte offset 81920"},
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