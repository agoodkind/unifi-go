package integration_test

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jamesbraid/unifi-emu/inform"
)

// TestCapturedTraffic compares the new codec with the preserved pixiedust transcript.
func TestCapturedTraffic(t *testing.T) {
	run := os.Getenv("UNIFI_CAPTURE_RUN")
	if run == "" {
		t.Skip("set UNIFI_CAPTURE_RUN to verify private capture evidence")
	}
	key, err := os.ReadFile(filepath.Join(run, "post-db-authkey.txt"))
	if err != nil {
		t.Fatal(err)
	}
	transcript, err := os.Open(filepath.Join(run, "pixiedust-with-db-key.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer transcript.Close()
	want := make(map[[32]byte]int)
	scanner := bufio.NewScanner(transcript)
	scanner.Buffer(make([]byte, 4096), 8<<20)
	for scanner.Scan() {
		want[payloadHash(t, scanner.Bytes())]++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("tshark", "-r", filepath.Join(run, "physical-tcpdump.pcap"), "-Y", "http.file_data", "-T", "fields", "-e", "http.file_data")
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("extract HTTP bodies: %v", err)
	}
	count := 0
	for _, line := range strings.Fields(string(output)) {
		body, err := hex.DecodeString(strings.ReplaceAll(line, ":", ""))
		if err != nil {
			t.Fatal("invalid packet hex")
		}
		if !bytes.HasPrefix(body, []byte("TNBU")) {
			continue
		}
		packet, err := inform.Decode(body, strings.TrimSpace(string(key)))
		if err != nil {
			t.Fatalf("decode captured inform %d: %v", count+1, err)
		}
		hash := payloadHash(t, packet.Payload)
		if want[hash] == 0 {
			t.Fatalf("decoded inform %d has no matching pixiedust payload", count+1)
		}
		want[hash]--
		count++
	}
	if count == 0 {
		t.Fatal("no captured informs decoded")
	}
	for _, remaining := range want {
		if remaining != 0 {
			t.Fatal("capture did not reproduce the complete pixiedust transcript")
		}
	}
	t.Logf("verified %d captured messages against pixiedust", count)
}

func payloadHash(t *testing.T, data []byte) [32]byte {
	t.Helper()
	var compact bytes.Buffer
	if err := json.Compact(&compact, data); err != nil {
		t.Fatal("invalid captured JSON")
	}
	return sha256.Sum256(compact.Bytes())
}
