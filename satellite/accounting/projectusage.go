// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package accounting

import (
	"context"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"golang.org/x/sync/errgroup"

	"storj.io/common/memory"
	"storj.io/common/uuid"
	"storj.io/storj/satellite/metabase"
)

var mon = monkit.Package()

// ErrProjectUsage general error for project usage.
var ErrProjectUsage = errs.Class("project usage")

// ErrProjectLimitExceeded is used when the configured limits of a project are reached.
var ErrProjectLimitExceeded = errs.Class("project limit")

// Service is handling project usage related logic.
//
// architecture: Service
type Service struct {
	projectAccountingDB ProjectAccounting
	liveAccounting      Cache
	metabaseDB          metabase.DB
	bandwidthCacheTTL   time.Duration
	nowFn               func() time.Time

	defaultMaxStorage   memory.Size
	defaultMaxBandwidth memory.Size
	defaultMaxSegments  int64
	asOfSystemInterval  time.Duration
}

// NewService created new instance of project usage service.
func NewService(projectAccountingDB ProjectAccounting, liveAccounting Cache, metabaseDB metabase.DB, bandwidthCacheTTL time.Duration,
	defaultMaxStorage, defaultMaxBandwidth memory.Size, defaultMaxSegments int64, asOfSystemInterval time.Duration) *Service {
	return &Service{
		projectAccountingDB: projectAccountingDB,
		liveAccounting:      liveAccounting,
		metabaseDB:          metabaseDB,
		bandwidthCacheTTL:   bandwidthCacheTTL,

		defaultMaxStorage:   defaultMaxStorage,
		defaultMaxBandwidth: defaultMaxBandwidth,
		defaultMaxSegments:  defaultMaxSegments,

		asOfSystemInterval: asOfSystemInterval,
		nowFn:              time.Now,
	}
}

// ExceedsBandwidthUsage returns true if the bandwidth usage limits have been exceeded
// for a project in the past month (30 days). The usage limit is (e.g 25GB) multiplied by the redundancy
// expansion factor, so that the uplinks have a raw limit.
//
// Among others,it can return one of the following errors returned by
// storj.io/storj/satellite/accounting.Cache except the ErrKeyNotFound, wrapped
// by ErrProjectUsage.
func (usage *Service) ExceedsBandwidthUsage(ctx context.Context, projectID uuid.UUID, limits ProjectLimits) (_ bool, limit memory.Size, err error) {
	defer mon.Task()(&ctx)(&err)

	limit = usage.defaultMaxBandwidth
	if limits.Bandwidth != nil {
		limit = memory.Size(*limits.Bandwidth)
	}

	// Get the current bandwidth usage from cache.
	bandwidthUsage, err := usage.liveAccounting.GetProjectBandwidthUsage(ctx, projectID, usage.nowFn())
	if err != nil {
		// Verify If the cache key was not found
		if ErrKeyNotFound.Has(err) {

			// Get current bandwidth value from database.
			now := usage.nowFn()
			bandwidthUsage, err = usage.GetProjectBandwidth(ctx, projectID, now.Year(), now.Month(), now.Day())
			if err != nil {
				return false, 0, ErrProjectUsage.Wrap(err)
			}

			// Create cache key with database value.
			_, err = usage.liveAccounting.InsertProjectBandwidthUsage(ctx, projectID, bandwidthUsage, usage.bandwidthCacheTTL, usage.nowFn())
			if err != nil {
				return false, 0, ErrProjectUsage.Wrap(err)
			}
		}
	}

	// Verify the bandwidth usage cache.
	if bandwidthUsage >= limit.Int64() {
		return true, limit, nil
	}

	return false, limit, nil
}

// UploadLimit contains upload limit characteristics.
type UploadLimit struct {
	ExceedsStorage  bool
	StorageLimit    memory.Size
	ExceedsSegments bool
	SegmentsLimit   int64
}

// ExceedsUploadLimits returns combined checks for storage and segment limits.
// Supply nonzero headroom parameters to check if there is room for a new object.
func (usage *Service) ExceedsUploadLimits(
	ctx context.Context, projectID uuid.UUID, storageSizeHeadroom int64, segmentCountHeadroom int64, limits ProjectLimits) (limit UploadLimit, err error) {
	defer mon.Task()(&ctx)(&err)

	limit.SegmentsLimit = usage.defaultMaxSegments
	if limits.Segments != nil {
		limit.SegmentsLimit = *limits.Segments
	}

	limit.StorageLimit = usage.defaultMaxStorage
	if limits.Usage != nil {
		limit.StorageLimit = memory.Size(*limits.Usage)
	}

	var group errgroup.Group
	var segmentUsage, storageUsage int64

	group.Go(func() error {
		var err error
		segmentUsage, err = usage.liveAccounting.GetProjectSegmentUsage(ctx, projectID)
		// Verify If the cache key was not found
		if err != nil && ErrKeyNotFound.Has(err) {
			return nil
		}
		return err
	})

	group.Go(func() error {
		var err error
		storageUsage, err = usage.GetProjectStorageTotals(ctx, projectID)
		return err
	})

	err = group.Wait()
	if err != nil {
		return UploadLimit{}, ErrProjectUsage.Wrap(err)
	}

	limit.ExceedsSegments = (segmentUsage + segmentCountHeadroom) > limit.SegmentsLimit
	limit.ExceedsStorage = (storageUsage + storageSizeHeadroom) > limit.StorageLimit.Int64()

	return limit, nil
}

// AddProjectUsageUpToLimit increases segment and storage usage up to the projects limit.
// If the limit is exceeded, neither usage is increased and accounting.ErrProjectLimitExceeded is returned.
func (usage *Service) AddProjectUsageUpToLimit(ctx context.Context, projectID uuid.UUID, storage int64, segments int64, limits ProjectLimits) (err error) {
	defer mon.Task()(&ctx, projectID)(&err)

	segmentsLimit := usage.defaultMaxSegments
	if limits.Segments != nil {
		segmentsLimit = *limits.Segments
	}

	storageLimit := usage.defaultMaxStorage
	if limits.Usage != nil {
		storageLimit = memory.Size(*limits.Usage)
	}

	err = usage.liveAccounting.AddProjectStorageUsageUpToLimit(ctx, projectID, storage, storageLimit.Int64())
	if err != nil {
		return err
	}

	err = usage.liveAccounting.AddProjectSegmentUsageUpToLimit(ctx, projectID, segments, segmentsLimit)
	if ErrProjectLimitExceeded.Has(err) {
		// roll back storage increase
		err = usage.liveAccounting.AddProjectStorageUsage(ctx, projectID, -1*storage)
		if err != nil {
			return err
		}
	}

	return err
}

// GetProjectStorageTotals returns total amount of storage used by project.
//
// It can return one of the following errors returned by
// storj.io/storj/satellite/accounting.Cache.GetProjectStorageUsage except the
// ErrKeyNotFound, wrapped by ErrProjectUsage.
func (usage *Service) GetProjectStorageTotals(ctx context.Context, projectID uuid.UUID) (total int64, err error) {
	defer mon.Task()(&ctx, projectID)(&err)

	total, err = usage.liveAccounting.GetProjectStorageUsage(ctx, projectID)
	if ErrKeyNotFound.Has(err) {
		return 0, nil
	}

	return total, ErrProjectUsage.Wrap(err)
}

// GetProjectBandwidthTotals returns total amount of allocated bandwidth used for past 30 days.
func (usage *Service) GetProjectBandwidthTotals(ctx context.Context, projectID uuid.UUID) (_ int64, err error) {
	defer mon.Task()(&ctx, projectID)(&err)

	// from the beginning of the current month
	year, month, _ := usage.nowFn().Date()

	total, err := usage.projectAccountingDB.GetProjectBandwidth(ctx, projectID, year, month, 1, usage.asOfSystemInterval)
	return total, ErrProjectUsage.Wrap(err)
}

// GetProjectSettledBandwidth returns total amount of settled bandwidth used for past 30 days.
func (usage *Service) GetProjectSettledBandwidth(ctx context.Context, projectID uuid.UUID) (_ int64, err error) {
	defer mon.Task()(&ctx, projectID)(&err)

	// from the beginning of the current month
	year, month, _ := usage.nowFn().Date()

	total, err := usage.projectAccountingDB.GetProjectSettledBandwidth(ctx, projectID, year, month, usage.asOfSystemInterval)
	return total, ErrProjectUsage.Wrap(err)
}

// GetProjectSegmentTotals returns total amount of allocated segments used for past 30 days.
func (usage *Service) GetProjectSegmentTotals(ctx context.Context, projectID uuid.UUID) (total int64, err error) {
	defer mon.Task()(&ctx, projectID)(&err)

	total, err = usage.liveAccounting.GetProjectSegmentUsage(ctx, projectID)
	if ErrKeyNotFound.Has(err) {
		return 0, nil
	}

	return total, ErrProjectUsage.Wrap(err)
}

// GetProjectBandwidth returns project allocated bandwidth for the specified year, month and day.
func (usage *Service) GetProjectBandwidth(ctx context.Context, projectID uuid.UUID, year int, month time.Month, day int) (_ int64, err error) {
	defer mon.Task()(&ctx, projectID)(&err)

	total, err := usage.projectAccountingDB.GetProjectBandwidth(ctx, projectID, year, month, day, usage.asOfSystemInterval)
	return total, ErrProjectUsage.Wrap(err)
}

// GetProjectStorageLimit returns current project storage limit.
func (usage *Service) GetProjectStorageLimit(ctx context.Context, projectID uuid.UUID) (_ memory.Size, err error) {
	defer mon.Task()(&ctx, projectID)(&err)
	storageLimit, err := usage.projectAccountingDB.GetProjectStorageLimit(ctx, projectID)
	if err != nil {
		return 0, ErrProjectUsage.Wrap(err)
	}

	if storageLimit == nil {
		return usage.defaultMaxStorage, nil
	}

	return memory.Size(*storageLimit), nil
}

// GetProjectBandwidthLimit returns current project bandwidth limit.
func (usage *Service) GetProjectBandwidthLimit(ctx context.Context, projectID uuid.UUID) (_ memory.Size, err error) {
	defer mon.Task()(&ctx, projectID)(&err)
	bandwidthLimit, err := usage.projectAccountingDB.GetProjectBandwidthLimit(ctx, projectID)
	if err != nil {
		return 0, ErrProjectUsage.Wrap(err)
	}

	if bandwidthLimit == nil {
		return usage.defaultMaxBandwidth, nil
	}

	return memory.Size(*bandwidthLimit), nil
}

// GetProjectSegmentLimit returns current project segment limit.
func (usage *Service) GetProjectSegmentLimit(ctx context.Context, projectID uuid.UUID) (_ memory.Size, err error) {
	defer mon.Task()(&ctx, projectID)(&err)
	segmentLimit, err := usage.projectAccountingDB.GetProjectSegmentLimit(ctx, projectID)
	if err != nil {
		return 0, ErrProjectUsage.Wrap(err)
	}

	if segmentLimit == nil {
		return memory.Size(usage.defaultMaxSegments), nil
	}

	return memory.Size(*segmentLimit), nil
}

// GetProjectBandwidthUsage get the current bandwidth usage from cache.
//
// It can return one of the following errors returned by
// storj.io/storj/satellite/accounting.Cache.GetProjectBandwidthUsage, wrapped
// by ErrProjectUsage.
func (usage *Service) GetProjectBandwidthUsage(ctx context.Context, projectID uuid.UUID) (currentUsed int64, err error) {
	return usage.liveAccounting.GetProjectBandwidthUsage(ctx, projectID, usage.nowFn())
}

// UpdateProjectBandwidthUsage increments the bandwidth cache key for a specific project.
//
// It can return one of the following errors returned by
// storj.io/storj/satellite/accounting.Cache.UpdateProjectBandwidthUsage, wrapped
// by ErrProjectUsage.
func (usage *Service) UpdateProjectBandwidthUsage(ctx context.Context, projectID uuid.UUID, increment int64) (err error) {
	return usage.liveAccounting.UpdateProjectBandwidthUsage(ctx, projectID, increment, usage.bandwidthCacheTTL, usage.nowFn())
}

// GetProjectSegmentUsage get the current segment usage from cache.
//
// It can return one of the following errors returned by
// storj.io/storj/satellite/accounting.Cache.GetProjectSegmentUsage.
func (usage *Service) GetProjectSegmentUsage(ctx context.Context, projectID uuid.UUID) (currentUsed int64, err error) {
	return usage.liveAccounting.GetProjectSegmentUsage(ctx, projectID)
}

// UpdateProjectSegmentUsage increments the segment cache key for a specific project.
//
// It can return one of the following errors returned by
// storj.io/storj/satellite/accounting.Cache.UpdatProjectSegmentUsage.
func (usage *Service) UpdateProjectSegmentUsage(ctx context.Context, projectID uuid.UUID, increment int64) (err error) {
	return usage.liveAccounting.UpdateProjectSegmentUsage(ctx, projectID, increment)
}

// AddProjectStorageUsage lets the live accounting know that the given
// project has just added spaceUsed bytes of storage (from the user's
// perspective; i.e. segment size).
//
// It can return one of the following errors returned by
// storj.io/storj/satellite/accounting.Cache.AddProjectStorageUsage, wrapped by
// ErrProjectUsage.
func (usage *Service) AddProjectStorageUsage(ctx context.Context, projectID uuid.UUID, spaceUsed int64) (err error) {
	defer mon.Task()(&ctx, projectID)(&err)
	return usage.liveAccounting.AddProjectStorageUsage(ctx, projectID, spaceUsed)
}

// SetNow allows tests to have the Service act as if the current time is whatever they want.
func (usage *Service) SetNow(now func() time.Time) {
	usage.nowFn = now
}

// TestSetAsOfSystemInterval allows tests to set Service asOfSystemInterval value.
func (usage *Service) TestSetAsOfSystemInterval(asOfSystemInterval time.Duration) {
	usage.asOfSystemInterval = asOfSystemInterval
}
