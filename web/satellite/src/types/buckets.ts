// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

import { DEFAULT_PAGE_LIMIT } from '@/types/pagination';
import { Placement } from '@/types/placements';
import { Versioning } from '@/types/versioning';

/**
 * Exposes all bucket-related functionality.
 */
export interface BucketsApi {
    /**
     * Fetch buckets
     *
     * @returns BucketPage
     * @throws Error
     */
    get(projectId: string, before: Date, cursor: BucketCursor): Promise<BucketPage>;

    /**
     * Fetch all bucket names
     *
     * @returns string[]
     * @throws Error
     */
    getAllBucketNames(projectId: string): Promise<string[]>;

    /**
     *
     * Fetch all bucket placements
     *
     * @returns BucketPlacement[]
     * @throws Error
     */
    getAllBucketPlacements(projectId: string): Promise<BucketPlacement[]>
}

/**
 * Bucket class holds info for Bucket entity.
 */
export class Bucket {
    public constructor(
        public name: string = '',
        public versioning: Versioning = Versioning.NotSupported,
        public defaultPlacement: number = 0,
        public location: string = '',
        public storage: number = 0,
        public egress: number = 0,
        public objectCount: number = 0,
        public segmentCount: number = 0,
        public since: Date = new Date(),
        public before: Date = new Date(),
    ) { }
}

/**
 * BucketPage class holds bucket total usages and flag whether more usages available.
 */
export class BucketPage {
    public constructor(
        public buckets: Bucket[] = [],
        public search: string = '',
        public limit: number = 0,
        public offset: number = 0,
        public pageCount: number = 0,
        public currentPage: number = 0,
        public totalCount: number = 0,
    ) { }
}

/**
 * BucketCursor class holds cursor for bucket name and limit.
 */
export class BucketCursor {
    public constructor(
        public search: string = '',
        public limit: number = DEFAULT_PAGE_LIMIT,
        public page: number = 1,
    ) { }
}

/**
 * BucketPlacement class holds bucket name, placement ID, and location.
 */
export class BucketPlacement {
    public constructor(
        public name: string = '',
        public placement: Placement = new Placement(),
    ) { }
}