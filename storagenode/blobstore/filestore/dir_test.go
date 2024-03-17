// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package filestore

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	"golang.org/x/exp/slices"

	"storj.io/common/memory"
	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/storj/storagenode/blobstore"
)

func TestDiskInfoFromPath(t *testing.T) {
	info, err := diskInfoFromPath(".")
	if err != nil {
		t.Fatal(err)
	}
	if info.AvailableSpace <= 0 {
		t.Fatal("expected to have some disk space")
	}
	if info.ID == "" {
		t.Fatal("didn't get filesystem id")
	}

	t.Logf("Got: %v %v", info.ID, info.AvailableSpace)
}

func BenchmarkDiskInfoFromPath(b *testing.B) {
	homedir, err := os.UserHomeDir()
	if err != nil {
		b.Fatal(err)
	}
	b.Run(fmt.Sprintf("dir=%q", homedir), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err = diskInfoFromPath(homedir)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestMigrateTrash(t *testing.T) {
	const (
		numNamespaces = 2
		numKeys       = 10
		namespaceSize = 32
		keySize       = 32
		dataSize      = 64
	)

	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	// build some data
	namespaces := make([][]byte, numNamespaces)
	keys := make([][][]byte, numNamespaces)
	data := make([][][]byte, numNamespaces)
	for n := range namespaces {
		namespaces[n] = testrand.Bytes(namespaceSize)
		keys[n] = make([][]byte, numKeys)
		data[n] = make([][]byte, numKeys)
		for k := range keys[n] {
			keys[n][k] = testrand.Bytes(keySize)
			data[n][k] = testrand.Bytes(dataSize)
		}
	}

	// build a storage dir and mimic the old trash hierarchy. We won't use NewDir()
	// for this, as it would create the dir as though it was already migrated.
	storeDir := ctx.Dir("store")
	trashDir := filepath.Join(storeDir, "trash")
	require.NoError(t, os.Mkdir(trashDir, dirPermission))
	require.NoError(t, os.Mkdir(filepath.Join(storeDir, "blobs"), dirPermission))
	require.NoError(t, os.Mkdir(filepath.Join(storeDir, "temp"), dirPermission))

	for n, namespace := range namespaces {
		namespaceStr := pathEncoding.EncodeToString(namespace)
		for k, key := range keys[n] {
			keyStr := pathEncoding.EncodeToString(key)
			storageDir := filepath.Join(trashDir, namespaceStr, keyStr[:2])
			require.NoError(t, os.MkdirAll(storageDir, 0700))
			require.NoError(t, os.WriteFile(filepath.Join(storageDir, keyStr[2:]+".sj1"), data[n][k], 0600))
		}
	}

	// now open that storage dir as though it was a storage dir from an older build
	// of storagenode.
	log := zaptest.NewLogger(t)
	trashTime := time.Now()
	dir, err := OpenDir(log, storeDir, trashTime)
	require.NoError(t, err)

	// expect that everything has been migrated and all pre-existing trash has been
	// put into a day dir.
	for n, namespace := range namespaces {
		namespaceStr := pathEncoding.EncodeToString(namespace)
		expectedDayDir := filepath.Join(trashDir, namespaceStr, trashTime.Format("2006-01-02"))
		for k, key := range keys[n] {
			keyStr := pathEncoding.EncodeToString(key)
			storageDir := filepath.Join(expectedDayDir, keyStr[:2])
			contents, err := os.ReadFile(filepath.Join(storageDir, keyStr[2:]+".sj1"))
			require.NoError(t, err)
			require.Equal(t, data[n][k], contents)
		}
	}

	foundNamespaces, err := dir.listNamespacesInTrash(ctx)
	require.NoError(t, err)
	slices.SortFunc(foundNamespaces, bytes.Compare)
	slices.SortFunc(namespaces, bytes.Compare)
	assert.Equal(t, namespaces, foundNamespaces)

	for _, namespace := range namespaces {
		expectTime := time.Date(trashTime.Year(), trashTime.Month(), trashTime.Day(), 0, 0, 0, 0, time.UTC)

		dayDirs, err := dir.listTrashDayDirs(ctx, namespace)
		require.NoError(t, err)
		require.Len(t, dayDirs, 1)
		assert.True(t, expectTime.Equal(dayDirs[0]),
			"expected %s but got %s", expectTime, dayDirs[0])

		var foundDirTimes []time.Time
		require.NoError(t, dir.forEachTrashDayDir(ctx, namespace, func(dirTime time.Time) error {
			foundDirTimes = append(foundDirTimes, dirTime)
			return nil
		}))
		require.Len(t, foundDirTimes, 1)
		assert.True(t, expectTime.Equal(foundDirTimes[0]),
			"expected %s but got %s", expectTime, foundDirTimes[0])
	}
}

// ensure that opening an already-migrated dir doesn't cause another attempt to migrate.
func TestNotMigrating(t *testing.T) {
	ctx := testcontext.New(t)
	storeDir := ctx.Dir("store")
	log := zaptest.NewLogger(t)
	blobContent := testrand.Bytes(1024)
	blobRef := blobstore.BlobRef{Namespace: testrand.Bytes(16), Key: testrand.Bytes(24)}
	trashNow := time.Now()

	{
		dir1, err := NewDir(log.Named("dir1"), storeDir)
		require.NoError(t, err)

		// write something and trash it
		writeTestBlob(ctx, t, dir1, blobRef, blobContent, FormatV1)
		err = dir1.Trash(ctx, blobRef, trashNow)
		require.NoError(t, err)

		// ensure we see the blob in the trash
		var seenInfos []blobstore.BlobRef
		var seenDirTimes []time.Time
		err = dir1.walkNamespaceInTrash(ctx, blobRef.Namespace, func(info blobstore.BlobInfo, dirTime time.Time) error {
			seenInfos = append(seenInfos, info.BlobRef())
			seenDirTimes = append(seenDirTimes, dirTime)
			return nil
		})
		require.NoError(t, err)
		require.Len(t, seenInfos, 1)
		require.Len(t, seenDirTimes, 1)
		require.Equal(t, blobRef, seenInfos[0])
		require.Equal(t, trashNow.UTC().Truncate(24*time.Hour), seenDirTimes[0])
	}

	{
		// open the dir again
		dir2, err := OpenDir(log.Named("dir2"), storeDir, time.Now())
		require.NoError(t, err)

		// expect we see still see the blob
		var seenInfos []blobstore.BlobRef
		var seenDirTimes []time.Time
		err = dir2.walkNamespaceInTrash(ctx, blobRef.Namespace, func(info blobstore.BlobInfo, dirTime time.Time) error {
			seenInfos = append(seenInfos, info.BlobRef())
			seenDirTimes = append(seenDirTimes, dirTime)
			return nil
		})
		require.NoError(t, err)
		require.Len(t, seenInfos, 1)
		require.Len(t, seenDirTimes, 1)
		require.Equal(t, blobRef, seenInfos[0])
		require.Equal(t, trashNow.UTC().Truncate(24*time.Hour), seenDirTimes[0])
	}
}

// ensure that NewDir() creates a dir that is marked as having being already
// migrated to using per-day trash directories.
func TestNewDirCreation(t *testing.T) {
	ctx := testcontext.New(t)
	storeDir := ctx.Dir("store")
	log := zaptest.NewLogger(t)

	dir, err := NewDir(log, storeDir)
	require.NoError(t, err)

	stat, err := os.Stat(filepath.Join(dir.trashdir(), TrashUsesDayDirsIndicator))
	require.NoError(t, err)
	assert.False(t, stat.IsDir())
	assert.Greater(t, stat.Size(), int64(0))
}

// ensure that checking for a blob in the trash still works when there are
// multiple per-day trash dirs.
func TestTrashRecoveryWithMultipleDayDirs(t *testing.T) {
	ctx := testcontext.New(t)
	storeDir := ctx.Dir("store")
	log := zaptest.NewLogger(t)

	const days = 7

	dir, err := NewDir(log, storeDir)
	require.NoError(t, err)
	trashNow := time.Now().Add(-days * 24 * time.Hour)

	blobRefs := make([]blobstore.BlobRef, days)
	blobContents := make([][]byte, days)
	for n := range blobRefs {
		blobRefs[n] = blobstore.BlobRef{Namespace: testrand.Bytes(16), Key: testrand.Bytes(24)}
		blobContents[n] = testrand.Bytes(memory.Size(testrand.Intn(1024)))
	}

	// write the blobs and trash them
	for n := range blobRefs {
		writeTestBlob(ctx, t, dir, blobRefs[n], blobContents[n], FormatV1)
		require.NoError(t, dir.Trash(ctx, blobRefs[n], trashNow))
		trashNow = trashNow.Add(24 * time.Hour)
	}

	// check that we can't Open them normally
	for n := range blobRefs {
		f, _, err := dir.Open(ctx, blobRefs[n])
		require.Error(t, err)
		require.True(t, os.IsNotExist(err))
		require.Nil(t, f)
	}

	// recover them
	for n := range blobRefs {
		err = dir.TryRestoreTrashBlob(ctx, blobRefs[n])
		require.NoError(t, err)
	}

	// check that they are all intact
	for n := range blobRefs {
		f, formatVersion, err := dir.Open(ctx, blobRefs[n])
		require.NoError(t, err)
		require.Equal(t, FormatV1, formatVersion)
		gotContents, err := io.ReadAll(f)
		require.NoError(t, err)
		require.Equal(t, blobContents[n], gotContents)
		require.NoError(t, f.Close())
	}
}

// check that trash emptying works as expected with per-day trash directories.
func TestEmptyTrash(t *testing.T) {
	ctx := testcontext.New(t)
	storeDir := ctx.Dir("store")
	log := zaptest.NewLogger(t)

	const (
		days           = 7
		emptyTrashDays = 3
	)

	dir, err := NewDir(log, storeDir)
	require.NoError(t, err)
	originalTime := time.Now()
	trashNow := originalTime.Add(-days * 24 * time.Hour)
	emptyCutoff := originalTime.Add(-emptyTrashDays * 24 * time.Hour)
	ns := testrand.Bytes(16)

	blobRefs := make([]blobstore.BlobRef, days)
	blobContents := make([][]byte, days)
	for n := range blobRefs {
		blobRefs[n] = blobstore.BlobRef{Namespace: ns, Key: testrand.Bytes(24)}
		blobContents[n] = testrand.Bytes(memory.Size(testrand.Intn(1024)))
	}

	var expectDeletedKeys [][]byte
	var expectDeletedBytes int64
	var expectSurvivingRefs []blobstore.BlobRef
	var expectSurvivingContents [][]byte
	var expectSurvivingTimes []time.Time

	// write the blobs and trash them on different 'days'
	for n := range blobRefs {
		writeTestBlob(ctx, t, dir, blobRefs[n], blobContents[n], FormatV1)
		require.NoError(t, dir.Trash(ctx, blobRefs[n], trashNow))
		trashDay := trashNow.Truncate(24 * time.Hour)
		if !trashDay.Add(24 * time.Hour).After(emptyCutoff) {
			expectDeletedKeys = append(expectDeletedKeys, blobRefs[n].Key)
			expectDeletedBytes += int64(len(blobContents[n]))
		} else {
			expectSurvivingRefs = append(expectSurvivingRefs, blobRefs[n])
			expectSurvivingContents = append(expectSurvivingContents, blobContents[n])
			expectSurvivingTimes = append(expectSurvivingTimes, trashNow)
		}
		trashNow = trashNow.Add(24 * time.Hour)
	}
	require.True(t, trashNow.Equal(originalTime))

	// empty the trash (partially)
	bytesEmptied, keysDeleted, err := dir.EmptyTrash(ctx, ns, originalTime.Add(-emptyTrashDays*24*time.Hour))
	require.NoError(t, err)

	// check that the keys we expect to be deleted were reported as deleted
	slices.SortFunc(expectDeletedKeys, bytes.Compare)
	slices.SortFunc(keysDeleted, bytes.Compare)
	require.Equal(t, expectDeletedKeys, keysDeleted)
	require.Equal(t, expectDeletedBytes, bytesEmptied)

	// check that the keys we expect to be deleted were actually deleted (can't open them anymore)
	for n := range expectDeletedKeys {
		_, _, err := dir.Open(ctx, blobstore.BlobRef{Namespace: ns, Key: expectDeletedKeys[n]})
		require.Error(t, err)
		require.True(t, os.IsNotExist(err))
	}

	// and check that the keys which we _don't_ expect to be deleted are still present
	for n := range expectSurvivingRefs {
		err := dir.TryRestoreTrashBlob(ctx, expectSurvivingRefs[n])
		require.NoError(t, err)
		f, formatVersion, err := dir.Open(ctx, expectSurvivingRefs[n])
		require.NoError(t, err, "key trashed on %s not present (trash cutoff was %s)", expectSurvivingTimes[n], emptyCutoff)
		require.Equal(t, FormatV1, formatVersion)
		contents, err := io.ReadAll(f)
		require.NoError(t, err)
		require.Equal(t, expectSurvivingContents[n], contents)
		require.NoError(t, f.Close())
	}
}

func writeTestBlob(ctx context.Context, t *testing.T, dir *Dir, ref blobstore.BlobRef, contents []byte, format blobstore.FormatVersion) {
	f, err := dir.CreateTemporaryFile(ctx, 0)
	require.NoError(t, err)
	_, err = f.Write(contents)
	require.NoError(t, err)
	err = dir.Commit(ctx, f, ref, FormatV1)
	require.NoError(t, err)
}
