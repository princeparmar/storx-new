// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package metabase

import (
	"context"

	"go.uber.org/zap"

	"storj.io/common/uuid"
)

// UpdateObjectLastCommittedMetadata contains arguments necessary for replacing an object metadata.
type UpdateObjectLastCommittedMetadata struct {
	ObjectLocation
	StreamID uuid.UUID

	EncryptedMetadata             []byte
	EncryptedMetadataNonce        []byte
	EncryptedMetadataEncryptedKey []byte
}

// Verify object stream fields.
func (obj *UpdateObjectLastCommittedMetadata) Verify() error {
	if err := obj.ObjectLocation.Verify(); err != nil {
		return err
	}
	if obj.StreamID.IsZero() {
		return ErrInvalidRequest.New("StreamID missing")
	}
	return nil
}

// UpdateObjectLastCommittedMetadata updates an object metadata.
func (db *DB) UpdateObjectLastCommittedMetadata(ctx context.Context, opts UpdateObjectLastCommittedMetadata) (err error) {
	defer mon.Task()(&ctx)(&err)

	if err := opts.Verify(); err != nil {
		return err
	}

	// TODO So the issue is that during a multipart upload of an object,
	// uplink can update object metadata. If we add the arguments EncryptedMetadata
	// to CommitObject, they will need to account for them being optional.
	// Leading to scenarios where uplink calls update metadata, but wants to clear them
	// during commit object.
	result, err := db.db.ExecContext(ctx, `
		UPDATE objects SET
			encrypted_metadata_nonce         = $5,
			encrypted_metadata               = $6,
			encrypted_metadata_encrypted_key = $7
		WHERE
			(project_id, bucket_name, object_key) = ($1, $2, $3) AND
			version IN (SELECT version FROM objects WHERE
				(project_id, bucket_name, object_key) = ($1, $2, $3) AND
				status <> `+statusPending+` AND
				(expires_at IS NULL OR expires_at > now())
				ORDER BY version desc
				LIMIT 1
			) AND
			stream_id    = $4 AND
			status       IN `+statusesCommitted,
		opts.ProjectID, []byte(opts.BucketName), opts.ObjectKey, opts.StreamID,
		opts.EncryptedMetadataNonce, opts.EncryptedMetadata, opts.EncryptedMetadataEncryptedKey)
	if err != nil {
		return Error.New("unable to update object metadata: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return Error.New("failed to get rows affected: %w", err)
	}

	if affected == 0 {
		return ErrObjectNotFound.New("object with specified version and committed status is missing")
	}

	if affected > 1 {
		db.log.Warn("object with multiple committed versions were found!",
			zap.Stringer("Project ID", opts.ProjectID), zap.String("Bucket Name", opts.BucketName),
			zap.String("Object Key", string(opts.ObjectKey)), zap.Stringer("Stream ID", opts.StreamID))
		mon.Meter("multiple_committed_versions").Mark(1)
	}

	mon.Meter("object_update_metadata").Mark(int(affected))

	return nil
}
