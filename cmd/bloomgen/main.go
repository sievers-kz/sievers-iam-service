// Command bloomgen builds a Bloom filter of compromised passwords from a plain-text list.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"unicode/utf8"

	"github.com/bits-and-blooms/bloom/v3"
)

// Same limits as domain.PlainPassword: shorter or longer passwords
// can never be submitted, so there is no point storing them.
const (
	minPasswordLen = 8
	maxPasswordLen = 64
)

func main() {
	in := flag.String("in", "", "path to the passwords list, one per line (required)")
	out := flag.String("out", "", "path of the generated filter (required)")
	fp := flag.Float64("fp", 0.01, "desired false-positive rate, e.g. 0.01 = 1%")
	flag.Parse()

	if *in == "" {
		log.Fatal("flag -in is required")
	}
	if *out == "" {
		log.Fatal("flag -out is required")
	}
	if *fp <= 0 || *fp >= 1 {
		log.Fatal("flag -fp must be between 0 and 1")
	}

	if err := run(*in, *out, *fp); err != nil {
		log.Fatalf("bloomgen: %v", err)
	}
}

func run(in, out string, fp float64) error {
	// The filter size depends on the number of items, so count them first.
	n, err := countPasswords(in)
	if err != nil {
		return fmt.Errorf("count passwords: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("no suitable passwords in %s", in)
	}

	filter := bloom.NewWithEstimates(uint(n), fp)
	err = forEachPassword(in, func(password []byte) {
		filter.Add(password)
	})
	if err != nil {
		return fmt.Errorf("fill filter: %w", err)
	}

	if err := save(filter, out); err != nil {
		return fmt.Errorf("save filter: %w", err)
	}

	log.Printf("wrote %s: %d passwords, false-positive rate %.4f", out, n, fp)
	return nil
}

func countPasswords(path string) (int, error) {
	n := 0
	err := forEachPassword(path, func([]byte) { n++ })
	return n, err
}

// forEachPassword calls fn for every line that fits the password length rules.
// The slice passed to fn is only valid during the call.
func forEachPassword(path string, fn func(password []byte)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if l := utf8.RuneCount(line); l < minPasswordLen || l > maxPasswordLen {
			continue
		}
		fn(line)
	}
	return scanner.Err()
}

// save writes to a temp file and renames it, so an interrupted run
// never leaves a half-written filter at the target path.
func save(filter *bloom.BloomFilter, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, "bloom-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename

	w := bufio.NewWriter(tmp)
	if _, err := filter.WriteTo(w); err != nil {
		tmp.Close()
		return err
	}
	if err := w.Flush(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
