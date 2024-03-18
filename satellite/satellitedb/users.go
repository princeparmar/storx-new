// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package satellitedb

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zeebo/errs"

	"storj.io/common/memory"
	"storj.io/common/storj"
	"storj.io/common/uuid"
	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/satellitedb/dbx"
)

// ensures that users implements console.Users.
var _ console.Users = (*users)(nil)

// implementation of Users interface repository using spacemonkeygo/dbx orm.
type users struct {
	db *satelliteDB
}

// UpdateFailedLoginCountAndExpiration increments failed_login_count and sets login_lockout_expiration appropriately.
func (users *users) UpdateFailedLoginCountAndExpiration(ctx context.Context, failedLoginPenalty *float64, id uuid.UUID) (err error) {
	if failedLoginPenalty != nil {
		// failed_login_count exceeded config.FailedLoginPenalty
		_, err = users.db.ExecContext(ctx, users.db.Rebind(`
		UPDATE users
		SET failed_login_count = COALESCE(failed_login_count, 0) + 1,
		login_lockout_expiration = CURRENT_TIMESTAMP + POWER(?, failed_login_count-1) * INTERVAL '1 minute'
		WHERE id = ?
	`), failedLoginPenalty, id.Bytes())
	} else {
		_, err = users.db.ExecContext(ctx, users.db.Rebind(`
		UPDATE users
		SET failed_login_count = COALESCE(failed_login_count, 0) + 1
		WHERE id = ?
	`), id.Bytes())
	}
	return
}

// Get is a method for querying user from the database by id.
func (users *users) Get(ctx context.Context, id uuid.UUID) (_ *console.User, err error) {
	defer mon.Task()(&ctx)(&err)
	user, err := users.db.Get_User_By_Id(ctx, dbx.User_Id(id[:]))

	if err != nil {
		return nil, err
	}

	return userFromDBX(ctx, user)
}

// GetByEmailWithUnverified is a method for querying users by email from the database.
func (users *users) GetByEmailWithUnverified(ctx context.Context, email string) (verified *console.User, unverified []console.User, err error) {
	defer mon.Task()(&ctx)(&err)
	usersDbx, err := users.db.All_User_By_NormalizedEmail(ctx, dbx.User_NormalizedEmail(normalizeEmail(email)))

	if err != nil {
		return nil, nil, err
	}

	var errors errs.Group
	for _, userDbx := range usersDbx {
		u, err := userFromDBX(ctx, userDbx)
		if err != nil {
			errors.Add(err)
			continue
		}

		if u.Status == console.Active {
			verified = u
		} else {
			unverified = append(unverified, *u)
		}
	}

	return verified, unverified, errors.Err()
}

func (users *users) GetByEmailWithUnverified_google(ctx context.Context, email string) (verified *console.User, unverified []console.User, err error) {
	defer mon.Task()(&ctx)(&err)
	usersDbx, err := users.db.All_User_By_NormalizedEmail(ctx, dbx.User_NormalizedEmail(normalizeEmail(email)))

	if err != nil {
		return nil, nil, err
	}

	var errors errs.Group
	for _, userDbx := range usersDbx {
		u, err := userFromDBX(ctx, userDbx)
		if err != nil {
			errors.Add(err)
			continue
		}
		verified = u
	}

	return verified, unverified, errors.Err()
}

// GetByEmail is a method for querying user by verified email from the database.
func (users *users) GetByEmail(ctx context.Context, email string) (_ *console.User, err error) {
	defer mon.Task()(&ctx)(&err)
	user, err := users.db.Get_User_By_NormalizedEmail_And_Status_Not_Number(ctx, dbx.User_NormalizedEmail(normalizeEmail(email)))

	if err != nil {
		return nil, err
	}

	return userFromDBX(ctx, user)
}

// boris: Get all users from the database
func (users *users) GetAllUsers(ctx context.Context) (usersFromDB []*console.User, err error) {
	defer mon.Task()(&ctx)(&err)

	allUsers, err := users.db.Get_All_Users(ctx)
	if err != nil {
		return nil, err
	}

	// var usersFromDB []*console.User
	for _, user := range allUsers {
		userFromDB, err := userFromDBX(ctx, user)
		if err != nil {
			return nil, err
		}
		usersFromDB = append(usersFromDB, userFromDB)
	}

	return usersFromDB, nil
}

// GetUnverifiedNeedingReminder returns users in need of a reminder to verify their email.
func (users *users) GetUnverifiedNeedingReminder(ctx context.Context, firstReminder, secondReminder, cutoff time.Time) (usersNeedingReminder []*console.User, err error) {
	defer mon.Task()(&ctx)(&err)

	rows, err := users.db.Query(ctx, `
		SELECT id, email, full_name, short_name
		FROM users
		WHERE status = 0
			AND created_at > $3
			AND (
				(verification_reminders = 0 AND created_at < $1)
				OR (verification_reminders = 1 AND created_at < $2)
			)
	`, firstReminder, secondReminder, cutoff)
	if err != nil {
		return nil, err
	}
	defer func() { err = errs.Combine(err, rows.Close()) }()

	for rows.Next() {
		var user console.User
		err = rows.Scan(&user.ID, &user.Email, &user.FullName, &user.ShortName)
		if err != nil {
			return nil, err
		}
		usersNeedingReminder = append(usersNeedingReminder, &user)
	}

	return usersNeedingReminder, rows.Err()
}

// UpdateVerificationReminders increments verification_reminders.
func (users *users) UpdateVerificationReminders(ctx context.Context, id uuid.UUID) error {
	_, err := users.db.ExecContext(ctx, `
		UPDATE users
		SET verification_reminders = verification_reminders + 1
		WHERE id = $1
	`, id.Bytes())
	return err
}

// Insert is a method for inserting user into the database.
func (users *users) Insert(ctx context.Context, user *console.User) (_ *console.User, err error) {
	defer mon.Task()(&ctx)(&err)

	if user.ID.IsZero() {
		return nil, errs.New("user id is not set")
	}

	optional := dbx.User_Create_Fields{
		ShortName:       dbx.User_ShortName(user.ShortName),
		IsProfessional:  dbx.User_IsProfessional(user.IsProfessional),
		SignupPromoCode: dbx.User_SignupPromoCode(user.SignupPromoCode),
	}
	if user.UserAgent != nil {
		optional.UserAgent = dbx.User_UserAgent(user.UserAgent)
	}
	if user.ProjectLimit != 0 {
		optional.ProjectLimit = dbx.User_ProjectLimit(user.ProjectLimit)
	}
	if user.ProjectStorageLimit != 0 {
		optional.ProjectStorageLimit = dbx.User_ProjectStorageLimit(user.ProjectStorageLimit)
	}
	if user.ProjectBandwidthLimit != 0 {
		optional.ProjectBandwidthLimit = dbx.User_ProjectBandwidthLimit(user.ProjectBandwidthLimit)
	}
	if user.ProjectSegmentLimit != 0 {
		optional.ProjectSegmentLimit = dbx.User_ProjectSegmentLimit(user.ProjectSegmentLimit)
	}
	if user.IsProfessional {
		optional.Position = dbx.User_Position(user.Position)
		optional.CompanyName = dbx.User_CompanyName(user.CompanyName)
		optional.WorkingOn = dbx.User_WorkingOn(user.WorkingOn)
		optional.EmployeeCount = dbx.User_EmployeeCount(user.EmployeeCount)
		optional.HaveSalesContact = dbx.User_HaveSalesContact(user.HaveSalesContact)
	}
	if user.SignupCaptcha != nil {
		optional.SignupCaptcha = dbx.User_SignupCaptcha(*user.SignupCaptcha)
	}

	createdUser, err := users.db.Create_User(ctx,
		dbx.User_Id(user.ID[:]),
		dbx.User_Email(user.Email),
		dbx.User_NormalizedEmail(normalizeEmail(user.Email)),
		dbx.User_FullName(user.FullName),
		dbx.User_PasswordHash(user.PasswordHash),
		optional,
	)

	if err != nil {
		return nil, err
	}

	if user.Status == console.Active {
		fmt.Println("updating user status in create request")
		err := users.Update(ctx, user.ID, console.UpdateUserRequest{Status: &user.Status})
		if err != nil {
			return nil, err
		}
	}

	return userFromDBX(ctx, createdUser)
}

// Delete is a method for deleting user by ID from the database.
func (users *users) Delete(ctx context.Context, id uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)
	_, err = users.db.Delete_User_By_Id(ctx, dbx.User_Id(id[:]))

	return err
}

// DeleteUnverifiedBefore deletes unverified users created prior to some time from the database.
func (users *users) DeleteUnverifiedBefore(
	ctx context.Context, before time.Time, asOfSystemTimeInterval time.Duration, pageSize int) (err error) {
	defer mon.Task()(&ctx)(&err)

	if pageSize <= 0 {
		return Error.New("expected page size to be positive; got %d", pageSize)
	}

	var pageCursor, pageEnd uuid.UUID
	aost := users.db.impl.AsOfSystemInterval(asOfSystemTimeInterval)
	for {
		// Select the ID beginning this page of records
		err = users.db.QueryRowContext(ctx, `
			SELECT id FROM users
			`+aost+`
			WHERE id > $1 AND users.status = $2 AND users.created_at < $3
			ORDER BY id LIMIT 1
		`, pageCursor, console.Inactive, before).Scan(&pageCursor)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return Error.Wrap(err)
		}

		// Select the ID ending this page of records
		err = users.db.QueryRowContext(ctx, `
			SELECT id FROM users
			`+aost+`
			WHERE id >= $1
			ORDER BY id LIMIT 1 OFFSET $2
		`, pageCursor, pageSize).Scan(&pageEnd)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				return Error.Wrap(err)
			}
			// Since this is the last page, we want to return all remaining IDs
			pageEnd = uuid.Max()
		}

		// Delete all old, unverified users in the range between the beginning and ending IDs
		_, err = users.db.ExecContext(ctx, `
			DELETE FROM users
			WHERE id IN (
				SELECT id FROM users
				`+aost+`
				WHERE id >= $1 AND id <= $2
				AND users.status = $3 AND users.created_at < $4
				ORDER BY id
			)
		`, pageCursor, pageEnd, console.Inactive, before)
		if err != nil {
			return Error.Wrap(err)
		}

		if pageEnd == uuid.Max() {
			return nil
		}

		// Advance the cursor to the next page
		pageCursor = pageEnd
	}
}

// Update is a method for updating user entity.
func (users *users) Update(ctx context.Context, userID uuid.UUID, updateRequest console.UpdateUserRequest) (err error) {
	defer mon.Task()(&ctx)(&err)

	updateFields, err := toUpdateUser(updateRequest)
	if err != nil {
		return err
	}

	_, err = users.db.Update_User_By_Id(
		ctx,
		dbx.User_Id(userID[:]),
		*updateFields,
	)

	return err
}

// UpdatePaidTier sets whether the user is in the paid tier.
func (users *users) UpdatePaidTier(ctx context.Context, id uuid.UUID, paidTier bool, projectBandwidthLimit, projectStorageLimit memory.Size, projectSegmentLimit int64, projectLimit int) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = users.db.Update_User_By_Id(
		ctx,
		dbx.User_Id(id[:]),
		dbx.User_Update_Fields{
			PaidTier:              dbx.User_PaidTier(paidTier),
			ProjectLimit:          dbx.User_ProjectLimit(projectLimit),
			ProjectBandwidthLimit: dbx.User_ProjectBandwidthLimit(projectBandwidthLimit.Int64()),
			ProjectStorageLimit:   dbx.User_ProjectStorageLimit(projectStorageLimit.Int64()),
			ProjectSegmentLimit:   dbx.User_ProjectSegmentLimit(projectSegmentLimit),
		},
	)

	return err
}

// boris
func (users *users) UpdatePaidTiers(ctx context.Context, id uuid.UUID, paidTier bool) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = users.db.Update_User_By_Id(
		ctx,
		dbx.User_Id(id[:]),
		dbx.User_Update_Fields{
			PaidTier: dbx.User_PaidTier(paidTier),
		},
	)

	return err
}

// UpdateUserAgent is a method to update the user's user agent.
func (users *users) UpdateUserAgent(ctx context.Context, id uuid.UUID, userAgent []byte) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = users.db.Update_User_By_Id(
		ctx,
		dbx.User_Id(id[:]),
		dbx.User_Update_Fields{
			UserAgent: dbx.User_UserAgent(userAgent),
		},
	)

	return err
}

// UpdateUserProjectLimits is a method to update the user's usage limits for new projects.
func (users *users) UpdateUserProjectLimits(ctx context.Context, id uuid.UUID, limits console.UsageLimits) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = users.db.Update_User_By_Id(
		ctx,
		dbx.User_Id(id[:]),
		dbx.User_Update_Fields{
			ProjectBandwidthLimit: dbx.User_ProjectBandwidthLimit(limits.Bandwidth),
			ProjectStorageLimit:   dbx.User_ProjectStorageLimit(limits.Storage),
			ProjectSegmentLimit:   dbx.User_ProjectSegmentLimit(limits.Segment),
		},
	)

	return err
}

// GetProjectLimit is a method to get the users project limit.
func (users *users) GetProjectLimit(ctx context.Context, id uuid.UUID) (limit int, err error) {
	defer mon.Task()(&ctx)(&err)

	row, err := users.db.Get_User_ProjectLimit_By_Id(ctx, dbx.User_Id(id[:]))
	if err != nil {
		return 0, err
	}
	return row.ProjectLimit, nil
}

// GetUserProjectLimits is a method to get the users storage and bandwidth limits for new projects.
func (users *users) GetUserProjectLimits(ctx context.Context, id uuid.UUID) (limits *console.ProjectLimits, err error) {
	defer mon.Task()(&ctx)(&err)

	row, err := users.db.Get_User_ProjectStorageLimit_User_ProjectBandwidthLimit_User_ProjectSegmentLimit_By_Id(ctx, dbx.User_Id(id[:]))
	if err != nil {
		return nil, err
	}

	return limitsFromDBX(ctx, row)
}

func (users *users) GetUserPaidTier(ctx context.Context, id uuid.UUID) (isPaid bool, err error) {
	defer mon.Task()(&ctx)(&err)

	row, err := users.db.Get_User_PaidTier_By_Id(ctx, dbx.User_Id(id[:]))
	if err != nil {
		return false, err
	}
	return row.PaidTier, nil
}

// GetSettings is a method for returning a user's set of configurations.
func (users *users) GetSettings(ctx context.Context, userID uuid.UUID) (settings *console.UserSettings, err error) {
	defer mon.Task()(&ctx)(&err)

	row, err := users.db.Get_UserSettings_By_UserId(ctx, dbx.UserSettings_UserId(userID[:]))
	if err != nil {
		return nil, err
	}

	settings = &console.UserSettings{}
	settings.OnboardingStart = row.OnboardingStart
	settings.OnboardingEnd = row.OnboardingEnd
	settings.OnboardingStep = row.OnboardingStep
	settings.PassphrasePrompt = true
	if row.PassphrasePrompt != nil {
		settings.PassphrasePrompt = *row.PassphrasePrompt
	}
	if row.SessionMinutes != nil {
		dur := time.Duration(*row.SessionMinutes) * time.Minute
		settings.SessionDuration = &dur
	}

	return settings, nil
}

// UpsertSettings is a method for updating a user's set of configurations if it exists and inserting it otherwise.
func (users *users) UpsertSettings(ctx context.Context, userID uuid.UUID, settings console.UpsertUserSettingsRequest) (err error) {
	defer mon.Task()(&ctx)(&err)

	dbID := dbx.UserSettings_UserId(userID[:])
	update := dbx.UserSettings_Update_Fields{}
	fieldCount := 0

	if settings.SessionDuration != nil {
		if *settings.SessionDuration == nil {
			update.SessionMinutes = dbx.UserSettings_SessionMinutes_Null()
		} else {
			update.SessionMinutes = dbx.UserSettings_SessionMinutes(uint((*settings.SessionDuration).Minutes()))
		}
		fieldCount++
	}
	if settings.OnboardingStart != nil {
		update.OnboardingStart = dbx.UserSettings_OnboardingStart(*settings.OnboardingStart)
		fieldCount++
	}
	if settings.OnboardingEnd != nil {
		update.OnboardingEnd = dbx.UserSettings_OnboardingEnd(*settings.OnboardingEnd)
		fieldCount++
	}
	if settings.PassphrasePrompt != nil {
		update.PassphrasePrompt = dbx.UserSettings_PassphrasePrompt(*settings.PassphrasePrompt)
		fieldCount++
	}
	if settings.OnboardingStep != nil {
		update.OnboardingStep = dbx.UserSettings_OnboardingStep(*settings.OnboardingStep)
		fieldCount++
	}

	return users.db.WithTx(ctx, func(ctx context.Context, tx *dbx.Tx) error {
		_, err := tx.Get_UserSettings_By_UserId(ctx, dbID)
		if errors.Is(err, sql.ErrNoRows) {
			if settings.OnboardingStart == nil {
				// temporarily inserting as false for new users until we make default for this column false.
				update.OnboardingStart = dbx.UserSettings_OnboardingStart(false)
			}
			if settings.OnboardingEnd == nil {
				// temporarily inserting as false for new users until we make default for this column false.
				update.OnboardingEnd = dbx.UserSettings_OnboardingEnd(false)
			}
			return tx.CreateNoReturn_UserSettings(ctx, dbID, dbx.UserSettings_Create_Fields(update))
		}
		if err != nil {
			return err
		}
		if fieldCount > 0 {
			_, err := tx.Update_UserSettings_By_UserId(ctx, dbID, update)
			return err
		}
		return nil
	})
}

// toUpdateUser creates dbx.User_Update_Fields with only non-empty fields as updatable.
func toUpdateUser(request console.UpdateUserRequest) (*dbx.User_Update_Fields, error) {
	update := dbx.User_Update_Fields{}
	if request.FullName != nil {
		update.FullName = dbx.User_FullName(*request.FullName)
	}
	if request.ShortName != nil {
		if *request.ShortName == nil {
			update.ShortName = dbx.User_ShortName_Null()
		} else {
			update.ShortName = dbx.User_ShortName(**request.ShortName)
		}
	}
	if request.Email != nil {
		update.Email = dbx.User_Email(*request.Email)
		update.NormalizedEmail = dbx.User_NormalizedEmail(normalizeEmail(*request.Email))
	}
	if request.PasswordHash != nil {
		if len(request.PasswordHash) > 0 {
			update.PasswordHash = dbx.User_PasswordHash(request.PasswordHash)
		}
	}
	if request.Status != nil {
		update.Status = dbx.User_Status(int(*request.Status))
	}
	if request.ProjectLimit != nil {
		update.ProjectLimit = dbx.User_ProjectLimit(*request.ProjectLimit)
	}
	if request.ProjectStorageLimit != nil {
		update.ProjectStorageLimit = dbx.User_ProjectStorageLimit(*request.ProjectStorageLimit)
	}
	if request.ProjectBandwidthLimit != nil {
		update.ProjectBandwidthLimit = dbx.User_ProjectBandwidthLimit(*request.ProjectBandwidthLimit)
	}
	if request.ProjectSegmentLimit != nil {
		update.ProjectSegmentLimit = dbx.User_ProjectSegmentLimit(*request.ProjectSegmentLimit)
	}
	if request.PaidTier != nil {
		update.PaidTier = dbx.User_PaidTier(*request.PaidTier)
	}
	if request.MFAEnabled != nil {
		update.MfaEnabled = dbx.User_MfaEnabled(*request.MFAEnabled)
	}
	if request.MFASecretKey != nil {
		if *request.MFASecretKey == nil {
			update.MfaSecretKey = dbx.User_MfaSecretKey_Null()
		} else {
			update.MfaSecretKey = dbx.User_MfaSecretKey(**request.MFASecretKey)
		}
	}
	if request.MFARecoveryCodes != nil {
		if *request.MFARecoveryCodes == nil {
			update.MfaRecoveryCodes = dbx.User_MfaRecoveryCodes_Null()
		} else {
			recoveryBytes, err := json.Marshal(*request.MFARecoveryCodes)
			if err != nil {
				return nil, err
			}
			update.MfaRecoveryCodes = dbx.User_MfaRecoveryCodes(string(recoveryBytes))
		}
	}
	if request.FailedLoginCount != nil {
		update.FailedLoginCount = dbx.User_FailedLoginCount(*request.FailedLoginCount)
	}
	if request.LoginLockoutExpiration != nil {
		if *request.LoginLockoutExpiration == nil {
			update.LoginLockoutExpiration = dbx.User_LoginLockoutExpiration_Null()
		} else {
			update.LoginLockoutExpiration = dbx.User_LoginLockoutExpiration(**request.LoginLockoutExpiration)
		}
	}
	update.DefaultPlacement = dbx.User_DefaultPlacement(int(request.DefaultPlacement))

	return &update, nil
}

// userFromDBX is used for creating User entity from autogenerated dbx.User struct.
func userFromDBX(ctx context.Context, user *dbx.User) (_ *console.User, err error) {
	defer mon.Task()(&ctx)(&err)
	if user == nil {
		return nil, errs.New("user parameter is nil")
	}

	id, err := uuid.FromBytes(user.Id)
	if err != nil {
		return nil, err
	}

	var recoveryCodes []string
	if user.MfaRecoveryCodes != nil {
		err = json.Unmarshal([]byte(*user.MfaRecoveryCodes), &recoveryCodes)
		if err != nil {
			return nil, err
		}
	}

	result := console.User{
		ID:                    id,
		FullName:              user.FullName,
		Email:                 user.Email,
		PasswordHash:          user.PasswordHash,
		Status:                console.UserStatus(user.Status),
		CreatedAt:             user.CreatedAt,
		ProjectLimit:          user.ProjectLimit,
		ProjectBandwidthLimit: user.ProjectBandwidthLimit,
		ProjectStorageLimit:   user.ProjectStorageLimit,
		ProjectSegmentLimit:   user.ProjectSegmentLimit,
		PaidTier:              user.PaidTier,
		IsProfessional:        user.IsProfessional,
		HaveSalesContact:      user.HaveSalesContact,
		MFAEnabled:            user.MfaEnabled,
		VerificationReminders: user.VerificationReminders,
		SignupCaptcha:         user.SignupCaptcha,
	}

	if user.DefaultPlacement != nil {
		result.DefaultPlacement = storj.PlacementConstraint(*user.DefaultPlacement)
	}

	if user.UserAgent != nil {
		result.UserAgent = user.UserAgent
	}

	if user.ShortName != nil {
		result.ShortName = *user.ShortName
	}

	if user.Position != nil {
		result.Position = *user.Position
	}

	if user.CompanyName != nil {
		result.CompanyName = *user.CompanyName
	}

	if user.WorkingOn != nil {
		result.WorkingOn = *user.WorkingOn
	}

	if user.EmployeeCount != nil {
		result.EmployeeCount = *user.EmployeeCount
	}

	if user.MfaSecretKey != nil {
		result.MFASecretKey = *user.MfaSecretKey
	}

	if user.MfaRecoveryCodes != nil {
		result.MFARecoveryCodes = recoveryCodes
	}

	if user.SignupPromoCode != nil {
		result.SignupPromoCode = *user.SignupPromoCode
	}

	if user.FailedLoginCount != nil {
		result.FailedLoginCount = *user.FailedLoginCount
	}

	if user.LoginLockoutExpiration != nil {
		result.LoginLockoutExpiration = *user.LoginLockoutExpiration
	}

	return &result, nil
}

// limitsFromDBX is used for creating user project limits entity from autogenerated dbx.User struct.
func limitsFromDBX(ctx context.Context, limits *dbx.ProjectStorageLimit_ProjectBandwidthLimit_ProjectSegmentLimit_Row) (_ *console.ProjectLimits, err error) {
	defer mon.Task()(&ctx)(&err)
	if limits == nil {
		return nil, errs.New("user parameter is nil")
	}

	result := console.ProjectLimits{
		ProjectBandwidthLimit: memory.Size(limits.ProjectBandwidthLimit),
		ProjectStorageLimit:   memory.Size(limits.ProjectStorageLimit),
		ProjectSegmentLimit:   limits.ProjectSegmentLimit,
	}
	return &result, nil
}

func normalizeEmail(email string) string {
	return strings.ToUpper(email)
}
