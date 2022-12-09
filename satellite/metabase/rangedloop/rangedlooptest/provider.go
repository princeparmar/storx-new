// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package rangedlooptest

import (
	"context"
	"fmt"
	"math"
	"sort"

	"storj.io/storj/satellite/metabase/rangedloop"
	"storj.io/storj/satellite/metabase/segmentloop"
)

var _ rangedloop.RangeSplitter = (*RangeSplitter)(nil)

// RangeSplitter allows to iterate over segments from an in-memory source.
type RangeSplitter struct {
	Segments []segmentloop.Segment
}

var _ rangedloop.SegmentProvider = (*SegmentProvider)(nil)

// SegmentProvider allows to iterate over segments from an in-memory source.
type SegmentProvider struct {
	Segments []segmentloop.Segment

	batchSize int
}

// CreateRanges splits the segments into equal ranges.
func (m *RangeSplitter) CreateRanges(nRanges int, batchSize int) ([]rangedloop.SegmentProvider, error) {
	// The segments for a given stream must be handled by a single segment
	// provider. Split the segments into streams.
	streams := streamsFromSegments(m.Segments)

	// Break up the streams into ranges
	rangeSize := int(math.Ceil(float64(len(streams)) / float64(nRanges)))

	rangeProviders := []rangedloop.SegmentProvider{}
	for i := 0; i < nRanges; i++ {
		offset := min(i*rangeSize, len(streams))
		end := min(offset+rangeSize, len(streams))
		rangeProviders = append(rangeProviders, &SegmentProvider{
			Segments:  segmentsFromStreams(streams[offset:end]),
			batchSize: batchSize,
		})
	}

	return rangeProviders, nil
}

// Iterate allows to loop over the segments stored in the provider.
func (m *SegmentProvider) Iterate(ctx context.Context, fn func([]segmentloop.Segment) error) error {
	for offset := 0; offset < len(m.Segments); offset += m.batchSize {
		end := min(offset+m.batchSize, len(m.Segments))
		err := fn(m.Segments[offset:end])
		if err != nil {
			return err
		}
	}

	return nil
}

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

func streamsFromSegments(segments []segmentloop.Segment) [][]segmentloop.Segment {
	// Duplicate and sort the segments by stream ID
	segments = append([]segmentloop.Segment(nil), segments...)
	for i, segment := range segments {
		fmt.Println("BEFORE:", i, segment.StreamID, segment.Position)
	}
	sort.Slice(segments, func(i int, j int) bool {
		idcmp := segments[i].StreamID.Compare(segments[j].StreamID)
		switch {
		case idcmp < 0:
			return true
		case idcmp > 0:
			return false
		default:
			return segments[i].Position.Less(segments[j].Position)
		}
	})
	for i, segment := range segments {
		fmt.Println("AFTER:", i, segment.StreamID, segment.Position)
	}
	// Break up the sorted segments into streams
	var streams [][]segmentloop.Segment
	var stream []segmentloop.Segment
	for _, segment := range segments {
		if len(stream) > 0 && stream[0].StreamID != segment.StreamID {
			// Stream ID changed; push and reset stream
			streams = append(streams, stream)
			stream = nil
		}
		stream = append(stream, segment)
	}

	// Append the last stream (will be empty if there were no segments)
	if len(stream) > 0 {
		streams = append(streams, stream)
	}

	for i, stream := range streams {
		for j, segment := range stream {
			fmt.Println("STREAM:", i, j, segment.StreamID, segment.Position)
		}
	}

	return streams
}

func segmentsFromStreams(streams [][]segmentloop.Segment) []segmentloop.Segment {
	var segments []segmentloop.Segment
	for _, stream := range streams {
		segments = append(segments, stream...)
	}
	return segments
}
