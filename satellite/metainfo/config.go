// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package metainfo

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"storj.io/common/memory"
	"storj.io/common/uuid"
	"storj.io/storj/satellite/metabase"
	"storj.io/uplink/private/eestream"
)

const (
	// BoltPointerBucket is the string representing the bucket used for `PointerEntries` in BoltDB.
	BoltPointerBucket = "pointers"
)

// RSConfig is a configuration struct that keeps details about default
// redundancy strategy information.
//
// Can be used as a flag.
type RSConfig struct {
	ErasureShareSize memory.Size
	Min              int
	Repair           int
	Success          int
	Total            int
}

// Type implements pflag.Value.
func (RSConfig) Type() string { return "metainfo.RSConfig" }

// String is required for pflag.Value.
func (rs *RSConfig) String() string {
	return fmt.Sprintf("%d/%d/%d/%d-%s",
		rs.Min,
		rs.Repair,
		rs.Success,
		rs.Total,
		rs.ErasureShareSize.String())
}

// Set sets the value from a string in the format k/m/o/n-size (min/repair/optimal/total-erasuresharesize).
func (rs *RSConfig) Set(s string) error {
	// Split on dash. Expect two items. First item is RS numbers. Second item is memory.Size.
	info := strings.Split(s, "-")
	if len(info) != 2 {
		return Error.New("Invalid default RS config (expect format k/m/o/n-ShareSize, got %s)", s)
	}
	rsNumbersString := info[0]
	shareSizeString := info[1]

	// Attempt to parse "-size" part of config.
	shareSizeInt, err := memory.ParseString(shareSizeString)
	if err != nil {
		return Error.New("Invalid share size in RS config: '%s', %w", shareSizeString, err)
	}
	shareSize := memory.Size(shareSizeInt)

	// Split on forward slash. Expect exactly four positive non-decreasing integers.
	rsNumbers := strings.Split(rsNumbersString, "/")
	if len(rsNumbers) != 4 {
		return Error.New("Invalid default RS numbers (wrong size, expect 4): %s", rsNumbersString)
	}

	minValue := 1
	values := []int{}
	for _, nextValueString := range rsNumbers {
		nextValue, err := strconv.Atoi(nextValueString)
		if err != nil {
			return Error.New("Invalid default RS numbers (should all be valid integers): %s, %w", rsNumbersString, err)
		}
		if nextValue < minValue {
			return Error.New("Invalid default RS numbers (should be non-decreasing): %s", rsNumbersString)
		}
		values = append(values, nextValue)
		minValue = nextValue
	}

	rs.ErasureShareSize = shareSize
	rs.Min = values[0]
	rs.Repair = values[1]
	rs.Success = values[2]
	rs.Total = values[3]

	return nil
}

// RedundancyStrategy creates eestream.RedundancyStrategy from config values.
func (rs *RSConfig) RedundancyStrategy() (eestream.RedundancyStrategy, error) {
	fec, err := eestream.NewFEC(rs.Min, rs.Total)
	if err != nil {
		return eestream.RedundancyStrategy{}, err
	}
	erasureScheme := eestream.NewRSScheme(fec, rs.ErasureShareSize.Int())
	return eestream.NewRedundancyStrategy(erasureScheme, rs.Repair, rs.Success)
}

// RateLimiterConfig is a configuration struct for endpoint rate limiting.
type RateLimiterConfig struct {
	Enabled         bool          `help:"whether rate limiting is enabled." releaseDefault:"true" devDefault:"true"`
	Rate            float64       `help:"request rate per project per second." releaseDefault:"100" devDefault:"100" testDefault:"1000"`
	CacheCapacity   int           `help:"number of projects to cache." releaseDefault:"10000" devDefault:"10" testDefault:"100"`
	CacheExpiration time.Duration `help:"how long to cache the projects limiter." releaseDefault:"10m" devDefault:"10s"`
}

// UploadLimiterConfig is a configuration struct for endpoint upload limiting.
type UploadLimiterConfig struct {
	Enabled           bool          `help:"whether rate limiting is enabled." releaseDefault:"true" devDefault:"true"`
	SingleObjectLimit time.Duration `help:"how often we can upload to the single object (the same location) per API instance" default:"1s" devDefault:"1ms"`

	CacheCapacity int `help:"number of object locations to cache." releaseDefault:"10000" devDefault:"10" testDefault:"100"`
}

// ProjectLimitConfig is a configuration struct for default project limits.
type ProjectLimitConfig struct {
	MaxBuckets int `help:"max bucket count for a project." default:"100" testDefault:"10"`
}

// Config is a configuration struct that is everything you need to start a metainfo.
type Config struct {
	DatabaseURL          string      `help:"the database connection string to use" default:"postgres://"`
	MinRemoteSegmentSize memory.Size `default:"1240" testDefault:"0" help:"minimum remote segment size"` // TODO: fix tests to work with 1024
	MaxInlineSegmentSize memory.Size `default:"4KiB" help:"maximum inline segment size"`
	// we have such default value because max value for ObjectKey is 1024(1 Kib) but EncryptedObjectKey
	// has encryption overhead 16 bytes. So overall size is 1024 + 16 * 16.
	MaxEncryptedObjectKeyLength int                 `default:"4000" help:"maximum encrypted object key length"`
	MaxSegmentSize              memory.Size         `default:"64MiB" help:"maximum segment size"`
	MaxMetadataSize             memory.Size         `default:"2KiB" help:"maximum segment metadata size"`
	MaxCommitInterval           time.Duration       `default:"48h" testDefault:"1h" help:"maximum time allowed to pass between creating and committing a segment"`
	MinPartSize                 memory.Size         `default:"5MiB" testDefault:"0" help:"minimum allowed part size (last part has no minimum size limit)"`
	MaxNumberOfParts            int                 `default:"10000" help:"maximum number of parts object can contain"`
	Overlay                     bool                `default:"true" help:"toggle flag if overlay is enabled"`
	RS                          RSConfig            `releaseDefault:"29/35/80/110-256B" devDefault:"4/6/8/10-256B" help:"redundancy scheme configuration in the format k/m/o/n-sharesize"`
	RateLimiter                 RateLimiterConfig   `help:"rate limiter configuration"`
	UploadLimiter               UploadLimiterConfig `help:"object upload limiter configuration"`
	ProjectLimits               ProjectLimitConfig  `help:"project limit configuration"`

	// TODO remove this flag when server-side copy implementation will be finished
	ServerSideCopy         bool `help:"enable code for server-side copy, deprecated. please leave this to true." default:"true"`
	ServerSideCopyDisabled bool `help:"disable already enabled server-side copy. this is because once server side copy is enabled, delete code should stay changed, even if you want to disable server side copy" default:"false"`

	UseBucketLevelObjectVersioning bool `help:"enable the use of bucket level object versioning" default:"false"`
	// flag to simplify testing by enabling bucket level versioning feature only for specific projects
	UseBucketLevelObjectVersioningProjects []string `help:"list of projects which will have UseBucketLevelObjectVersioning feature flag enabled" default:"" hidden:"true"`

	// TODO remove when we benchmarking are done and decision is made.
	TestListingQuery bool `default:"false" help:"test the new query for non-recursive listing"`
}

// Metabase constructs Metabase configuration based on Metainfo configuration with specific application name.
func (c Config) Metabase(applicationName string) metabase.Config {
	return metabase.Config{
		ApplicationName:  applicationName,
		MinPartSize:      c.MinPartSize,
		MaxNumberOfParts: c.MaxNumberOfParts,
		ServerSideCopy:   c.ServerSideCopy,
	}
}

// ExtendedConfig extended config keeps additional helper fields and methods around Config.
type ExtendedConfig struct {
	Config

	useBucketLevelObjectVersioningProjects []uuid.UUID
}

// NewExtendedConfig creates new instance of extended config.
func NewExtendedConfig(config Config) (_ ExtendedConfig, err error) {
	extendedConfig := ExtendedConfig{Config: config}
	for _, projectIDString := range config.UseBucketLevelObjectVersioningProjects {
		projectID, err := uuid.FromString(projectIDString)
		if err != nil {
			return ExtendedConfig{}, err
		}
		extendedConfig.useBucketLevelObjectVersioningProjects = append(extendedConfig.useBucketLevelObjectVersioningProjects, projectID)
	}

	return extendedConfig, nil
}

// UseBucketLevelObjectVersioningByProject checks if UseBucketLevelObjectVersioning should be enabled for specific project.
func (ec ExtendedConfig) UseBucketLevelObjectVersioningByProject(projectID uuid.UUID) bool {
	// if its globally enabled don't look at projects
	if ec.UseBucketLevelObjectVersioning {
		return true
	}
	for _, p := range ec.useBucketLevelObjectVersioningProjects {
		if p == projectID {
			return true
		}
	}

	return false
}
