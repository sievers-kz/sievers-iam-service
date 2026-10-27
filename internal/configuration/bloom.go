package configuration

import (
	"bufio"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/bits-and-blooms/bloom/v3"
)

func LoadBloom(bloomPath string) (*bloom.BloomFilter, error) {
	bloomFile, err := os.Open(bloomPath)
	if errors.Is(err, os.ErrNotExist) {
		slog.Warn("Failed to find Bloom filter, skip")
		return nil, nil // filter does not exist, skipping
	}

	if err != nil {
		return nil, fmt.Errorf("failed to open Bloom filter: %w", err)
	}
	defer bloomFile.Close()

	reader := bufio.NewReader(bloomFile)
	filter := &bloom.BloomFilter{}

	_, err = filter.ReadFrom(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read Bloom filter: %w", err)
	}

	return filter, nil
}
