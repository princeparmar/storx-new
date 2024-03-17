// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package consoleapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"storj.io/common/memory"
	"storj.io/common/storj"
	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/common/uuid"
	"storj.io/storj/private/testplanet"
	"storj.io/storj/satellite"
	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/console/consoleweb/consoleapi"
)

func createTestMembers(ctx context.Context, t *testing.T, db console.DB, p uuid.UUID, owner *uuid.UUID) (_ map[uuid.UUID]console.User, _ map[string]console.User) {
	members := make(map[uuid.UUID]console.User)
	invitees := make(map[string]console.User)
	for i := 0; i < 3; i++ {
		memberID := testrand.UUID()
		member, err := db.Users().Insert(ctx, &console.User{
			ID:                    memberID,
			FullName:              fmt.Sprintf("Member FullName%c", rune('A'+i)),
			ShortName:             fmt.Sprintf("Member ShortName%c", rune('A'+i)),
			Email:                 fmt.Sprintf("member%d@storj.test", i),
			ProjectLimit:          1,
			ProjectStorageLimit:   (memory.GB * 150).Int64(),
			ProjectBandwidthLimit: (memory.GB * 150).Int64(),
			PasswordHash:          []byte("test"),
		})
		require.NoError(t, err)
		members[memberID] = *member

		status := console.UserStatus(1)

		err = db.Users().Update(ctx, memberID, console.UpdateUserRequest{
			Status: &status,
		})
		require.NoError(t, err)

		_, err = db.ProjectMembers().Insert(ctx, member.ID, p)
		require.NoError(t, err)

		inviteeID := testrand.UUID()
		inviteeEmail := fmt.Sprintf("invitee%d@storj.test", i)
		invitee, err := db.Users().Insert(ctx, &console.User{
			ID:                    inviteeID,
			FullName:              fmt.Sprintf("Invitee FullName%c", rune('A'+i)),
			ShortName:             fmt.Sprintf("Invitee ShortName%c", rune('A'+i)),
			Email:                 inviteeEmail,
			ProjectLimit:          1,
			ProjectStorageLimit:   (memory.GB * 150).Int64(),
			ProjectBandwidthLimit: (memory.GB * 150).Int64(),
			PasswordHash:          []byte("test"),
		})
		require.NoError(t, err)

		invitees[inviteeEmail] = *invitee

		_, err = db.ProjectInvitations().Upsert(ctx, &console.ProjectInvitation{
			ProjectID: p,
			Email:     inviteeEmail,
			InviterID: owner,
			CreatedAt: time.Now(),
		})
		require.NoError(t, err)
	}
	return members, invitees
}

func TestGetProjectMembersAndInvitationsOrdering(t *testing.T) {
	testplanet.Run(t, testplanet.Config{
		SatelliteCount: 1, StorageNodeCount: 0, UplinkCount: 1,
	}, func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet) {
		sat := planet.Satellites[0]
		p := planet.Uplinks[0].Projects[0].ID

		user, err := sat.DB.Console().Users().GetByEmail(ctx, planet.Uplinks[0].User[sat.ID()].Email)
		require.NoError(t, err)

		members, invitees := createTestMembers(ctx, t, sat.DB.Console(), p, &user.ID)
		members[user.ID] = *user

		tests := []struct {
			order, orderDir int
		}{
			{ // ascending by name
				order:    1,
				orderDir: 1,
			},
			{ // descending by name
				order:    1,
				orderDir: 2,
			},
			{ // ascending by email
				order:    2,
				orderDir: 1,
			},
			{ // descending by email
				order:    2,
				orderDir: 2,
			},
			{ // ascending by created at
				order:    3,
				orderDir: 1,
			},
			{ // descending by created at
				order:    3,
				orderDir: 2,
			},
		}

		for _, tt := range tests {
			endpoint := fmt.Sprintf("projects/%s/members?limit=100&page=1&order=%d&order-direction=%d", p.String(), tt.order, tt.orderDir)
			body, status, err := doRequestWithAuth(ctx, t, sat, user, http.MethodGet, endpoint, nil)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, status)

			var membersAndInvitations consoleapi.ProjectMembersPage
			require.NoError(t, json.Unmarshal(body, &membersAndInvitations))

			respMembers := membersAndInvitations.Members
			respInvitees := membersAndInvitations.Invitations
			for i := 1; i < len(respMembers); i++ {
				switch tt.orderDir {
				case int(console.Ascending):
					switch tt.order {
					case int(console.Name):
						require.Less(t, members[respMembers[i-1].ID].FullName, members[respMembers[i].ID].FullName)
					case int(console.Email):
						require.Less(t, members[respMembers[i-1].ID].Email, members[respMembers[i].ID].Email)
					case int(console.Created):
						require.Less(t, members[respMembers[i-1].ID].CreatedAt, members[respMembers[i].ID].CreatedAt)
					default:
						t.Error("invalid order", tt.order)
					}
				case int(console.Descending):
					switch tt.order {
					case int(console.Name):
						require.Greater(t, members[respMembers[i-1].ID].FullName, members[respMembers[i].ID].FullName)
					case int(console.Email):
						require.Greater(t, members[respMembers[i-1].ID].Email, members[respMembers[i].ID].Email)
					case int(console.Created):
						require.Greater(t, members[respMembers[i-1].ID].CreatedAt, members[respMembers[i].ID].CreatedAt)
					default:
						t.Error("invalid order", tt.order)
					}
				default:
					t.Error("invalid order direction", tt.orderDir)
				}
			}
			for i := 1; i < len(respInvitees); i++ {
				switch tt.orderDir {
				case int(console.Ascending):
					switch tt.order {
					case int(console.Name):
						require.Less(t, invitees[respInvitees[i-1].Email].FullName, invitees[respInvitees[i].Email].FullName)
					case int(console.Email):
						require.Less(t, invitees[respInvitees[i-1].Email].Email, invitees[respInvitees[i].Email].Email)
					case int(console.Created):
						require.Less(t, invitees[respInvitees[i-1].Email].CreatedAt, invitees[respInvitees[i].Email].CreatedAt)
					default:
						t.Error("invalid order", tt.order)
					}
				case int(console.Descending):
					switch tt.order {
					case int(console.Name):
						require.Greater(t, invitees[respInvitees[i-1].Email].FullName, invitees[respInvitees[i].Email].FullName)
					case int(console.Email):
						require.Greater(t, invitees[respInvitees[i-1].Email].Email, invitees[respInvitees[i].Email].Email)
					case int(console.Created):
						require.Greater(t, invitees[respInvitees[i-1].Email].CreatedAt, invitees[respInvitees[i].Email].CreatedAt)
					default:
						t.Error("invalid order", tt.order)
					}
				default:
					t.Error("invalid order direction", tt.orderDir)
				}
			}
		}
	})
}

func TestGetProjectMembersAndInvitationsSearch(t *testing.T) {
	testplanet.Run(t, testplanet.Config{
		SatelliteCount: 1, StorageNodeCount: 0, UplinkCount: 1,
	}, func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet) {
		sat := planet.Satellites[0]
		p := planet.Uplinks[0].Projects[0].ID

		user, err := sat.DB.Console().Users().GetByEmail(ctx, planet.Uplinks[0].User[sat.ID()].Email)
		require.NoError(t, err)

		members, invitees := createTestMembers(ctx, t, sat.DB.Console(), p, &user.ID)
		members[user.ID] = *user

		tests := []struct {
			search                            string
			expectedMembers, expectedInvitees int
		}{
			{ // all members and invitees
				"",
				4,
				3,
			},
			{ // zero members zero invitees
				"asdf",
				0,
				0,
			},
			{ // one member one invitee by email
				"1",
				1,
				1,
			},
			{ // three members by full name
				"Member FullName",
				3,
				0,
			},
			{ // three invitees by email
				"invitee",
				0,
				3,
			},
			{ // one member by short name
				"Member ShortNameA",
				1,
				0,
			},
		}

		for _, tt := range tests {
			endpoint := fmt.Sprintf("projects/%s/members?limit=100&page=1&order=1&order-direction=1&", p.String())
			params := url.Values{}
			params.Add("search", tt.search)
			endpoint += params.Encode()

			body, status, err := doRequestWithAuth(ctx, t, sat, user, http.MethodGet, endpoint, nil)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, status)

			var membersAndInvitations consoleapi.ProjectMembersPage
			require.NoError(t, json.Unmarshal(body, &membersAndInvitations))

			respMembers := membersAndInvitations.Members
			respInvitees := membersAndInvitations.Invitations
			require.Equal(t, tt.expectedMembers, len(respMembers))
			require.Equal(t, tt.expectedInvitees, len(respInvitees))
			if tt.search != "" {
				for _, m := range respMembers {
					containsSearch := strings.Contains(members[m.ID].Email, tt.search) || strings.Contains(members[m.ID].FullName, tt.search) || strings.Contains(members[m.ID].ShortName, tt.search)
					require.True(t, containsSearch)
				}
				for _, inv := range respInvitees {
					containsSearch := strings.Contains(inv.Email, tt.search) || strings.Contains(invitees[inv.Email].FullName, tt.search) || strings.Contains(invitees[inv.Email].ShortName, tt.search)
					require.True(t, containsSearch)
				}
			}
		}
	})
}

func TestGetProjectMembersAndInvitationsLimitAndPage(t *testing.T) {
	testplanet.Run(t, testplanet.Config{
		SatelliteCount: 1, StorageNodeCount: 0, UplinkCount: 1,
	}, func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet) {
		sat := planet.Satellites[0]
		p := planet.Uplinks[0].Projects[0].ID

		user, err := sat.DB.Console().Users().GetByEmail(ctx, planet.Uplinks[0].User[sat.ID()].Email)
		require.NoError(t, err)

		members, _ := createTestMembers(ctx, t, sat.DB.Console(), p, &user.ID)
		members[user.ID] = *user

		limit := 1
		page := 1
		var previousResult console.ProjectMembersPage
		for i := 0; i < 2; i++ {
			endpoint := fmt.Sprintf("projects/%s/members?order=1&order-direction=1&", p.String())
			params := url.Values{}
			params.Add("limit", fmt.Sprint(limit))
			params.Add("page", fmt.Sprint(page))
			endpoint += params.Encode()

			body, status, err := doRequestWithAuth(ctx, t, sat, user, http.MethodGet, endpoint, nil)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, status)

			var membersAndInvitations console.ProjectMembersPage
			require.NoError(t, json.Unmarshal(body, &membersAndInvitations))

			respMembers := membersAndInvitations.ProjectMembers
			respInvitees := membersAndInvitations.ProjectInvitations
			length := len(respMembers) + len(respInvitees)
			require.Equal(t, limit, length)
			require.Equal(t, page, int(membersAndInvitations.CurrentPage))
			if i != 0 {
				require.NotEqual(t, previousResult, membersAndInvitations)
			}
			previousResult = membersAndInvitations
			limit++
			page++
		}
	})
}

func TestDeleteProjectMembers(t *testing.T) {
	testplanet.Run(t, testplanet.Config{
		SatelliteCount: 1, StorageNodeCount: 0, UplinkCount: 1,
	}, func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet) {
		sat := planet.Satellites[0]
		p := planet.Uplinks[0].Projects[0].ID

		user, err := sat.DB.Console().Users().GetByEmail(ctx, planet.Uplinks[0].User[sat.ID()].Email)
		require.NoError(t, err)

		members, invitees := createTestMembers(ctx, t, sat.DB.Console(), p, &user.ID)

		var emails string
		var firstAppendDone bool
		for _, m := range members {
			if firstAppendDone {
				emails += ","
			} else {
				firstAppendDone = true
			}
			emails += m.Email
		}
		for e := range invitees {
			if len(members) > 0 {
				emails += ","
			}
			emails += e
		}

		endpoint := fmt.Sprintf("projects/%s/members?", p.String())
		params := url.Values{}
		params.Add("emails", emails)
		endpoint += params.Encode()

		body, status, err := doRequestWithAuth(ctx, t, sat, user, http.MethodDelete, endpoint, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
		require.NotContains(t, string(body), "error")

		page, err := sat.DB.Console().ProjectMembers().GetPagedWithInvitationsByProjectID(ctx, p, console.ProjectMembersCursor{Limit: 1, Page: 1})
		require.NoError(t, err)
		require.Len(t, page.ProjectMembers, 1)
		require.Equal(t, user.ID, page.ProjectMembers[0].MemberID)

		// test error
		endpoint = fmt.Sprintf("projects/%s/members?", p.String())
		params = url.Values{}
		params.Add("emails", "nonmember@storj.test")
		endpoint += params.Encode()

		body, status, err = doRequestWithAuth(ctx, t, sat, user, http.MethodDelete, endpoint, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusInternalServerError, status)
		require.Contains(t, string(body), "error")
	})
}

func TestEdgeURLOverrides(t *testing.T) {
	var (
		noOverridePlacementID      storj.PlacementConstraint
		partialOverridePlacementID storj.PlacementConstraint = 1
		fullOverridePlacementID    storj.PlacementConstraint = 2

		authServiceURL         = "auth.storj.io"
		publicLinksharingURL   = "public-link.storj.io"
		internalLinksharingURL = "link.storj.io"
	)

	testplanet.Run(t, testplanet.Config{
		SatelliteCount: 1, UplinkCount: 1,
		Reconfigure: testplanet.Reconfigure{
			Satellite: func(log *zap.Logger, index int, config *satellite.Config) {
				err := config.Console.PlacementEdgeURLOverrides.Set(
					fmt.Sprintf(
						`{
							"%d": {"authService": "%s"},
							"%d": {
								"authService": "%s",
								"publicLinksharing": "%s",
								"internalLinksharing": "%s"
							}
						}`,
						partialOverridePlacementID, authServiceURL,
						fullOverridePlacementID, authServiceURL, publicLinksharingURL, internalLinksharingURL,
					),
				)
				require.NoError(t, err)
			},
		},
	}, func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet) {
		sat := planet.Satellites[0]

		project, err := sat.DB.Console().Projects().Get(ctx, planet.Uplinks[0].Projects[0].ID)
		require.NoError(t, err)

		user, err := sat.API.Console.Service.GetUser(ctx, project.OwnerID)
		require.NoError(t, err)

		for _, tt := range []struct {
			name             string
			placement        *storj.PlacementConstraint
			expectedEdgeURLs *console.EdgeURLOverrides
		}{
			{"nil placement", nil, nil},
			{"placement with no overrides", &noOverridePlacementID, nil},
			{
				"placement with partial override",
				&partialOverridePlacementID,
				&console.EdgeURLOverrides{AuthService: authServiceURL},
			}, {
				"placement with full override",
				&fullOverridePlacementID,
				&console.EdgeURLOverrides{
					AuthService:         authServiceURL,
					PublicLinksharing:   publicLinksharingURL,
					InternalLinksharing: internalLinksharingURL,
				},
			},
		} {
			t.Run(tt.name, func(t *testing.T) {
				result, err := sat.DB.Testing().RawDB().ExecContext(ctx,
					"UPDATE projects SET default_placement = $1 WHERE id = $2",
					tt.placement, project.ID,
				)
				require.NoError(t, err)

				count, err := result.RowsAffected()
				require.NoError(t, err)
				require.EqualValues(t, 1, count)

				body, status, err := doRequestWithAuth(ctx, t, sat, user, http.MethodGet, "projects", nil)
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, status)

				var infos []console.ProjectInfo
				require.NoError(t, json.Unmarshal(body, &infos))
				require.NotEmpty(t, infos)

				if tt.expectedEdgeURLs == nil {
					require.Nil(t, infos[0].EdgeURLOverrides)
					return
				}
				require.NotNil(t, infos[0].EdgeURLOverrides)
				require.Equal(t, *tt.expectedEdgeURLs, *infos[0].EdgeURLOverrides)
			})
		}
	})
}
