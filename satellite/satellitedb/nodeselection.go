// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package satellitedb

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/zeebo/errs"

	"storj.io/common/dbutil/pgutil"
	"storj.io/common/pb"
	"storj.io/common/storj"
	"storj.io/common/version"
	"storj.io/storj/satellite/nodeselection"
	"storj.io/storj/satellite/overlay"
)

func (cache *overlaycache) SelectStorageNodes(ctx context.Context, totalNeededNodes, newNodeCount int, criteria *overlay.NodeCriteria) (nodes []*nodeselection.SelectedNode, err error) {
	defer mon.Task()(&ctx)(&err)
	if totalNeededNodes == 0 {
		return nil, nil
	}

	if newNodeCount > totalNeededNodes {
		return nil, Error.New("requested new node count can't exceed requested total node count")
	}

	needNewNodes := newNodeCount
	needReputableNodes := totalNeededNodes - needNewNodes

	receivedNewNodes := 0
	receivedNodeNetworks := make(map[string]struct{})

	excludedIDs := append([]storj.NodeID{}, criteria.ExcludedIDs...)
	excludedNetworks := append([]string{}, criteria.ExcludedNetworks...)

	for i := 0; i < 3; i++ {
		reputableNodes, newNodes, err := cache.selectStorageNodesOnce(ctx, needReputableNodes, needNewNodes, criteria, excludedIDs, excludedNetworks)
		if err != nil {
			return nil, err
		}

		for _, node := range newNodes {
			// checking for last net collision among reputable and new nodes since we can't check within the query
			if _, ok := receivedNodeNetworks[node.LastNet]; ok {
				continue
			}

			excludedIDs = append(excludedIDs, node.ID)
			excludedNetworks = append(excludedNetworks, node.LastNet)

			nodes = append(nodes, node)
			needNewNodes--
			receivedNewNodes++

			receivedNodeNetworks[node.LastNet] = struct{}{}
		}
		for _, node := range reputableNodes {
			if _, ok := receivedNodeNetworks[node.LastNet]; ok {
				continue
			}

			excludedIDs = append(excludedIDs, node.ID)
			excludedNetworks = append(excludedNetworks, node.LastNet)

			nodes = append(nodes, node)
			needReputableNodes--

			receivedNodeNetworks[node.LastNet] = struct{}{}
		}

		// when we did not find new nodes, then return all as reputable
		if needNewNodes > 0 && receivedNewNodes == 0 {
			needReputableNodes += needNewNodes
			needNewNodes = 0
		}

		if needReputableNodes <= 0 && needNewNodes <= 0 {
			break
		}
	}
	return nodes, nil
}

func (cache *overlaycache) selectStorageNodesOnce(ctx context.Context, reputableNodeCount, newNodeCount int, criteria *overlay.NodeCriteria, excludedIDs []storj.NodeID, excludedNetworks []string) (reputableNodes, newNodes []*nodeselection.SelectedNode, err error) {
	defer mon.Task()(&ctx)(&err)

	newNodesCondition, err := nodeSelectionCondition(ctx, criteria, excludedIDs, excludedNetworks, true)
	if err != nil {
		return nil, nil, err
	}
	reputableNodesCondition, err := nodeSelectionCondition(ctx, criteria, excludedIDs, excludedNetworks, false)
	if err != nil {
		return nil, nil, err
	}

	var reputableNodeQuery, newNodeQuery partialQuery

	// Note: the true/false at the end of each selection string indicates if the selection is for new nodes or not.
	// Later, the flag allows us to distinguish if a node is new when scanning the db rows.
	reputableNodeQuery = partialQuery{
		selection: `SELECT DISTINCT ON (last_net) last_net, id, address, last_ip_port, country_code, noise_proto, noise_public_key, debounce_limit, features, false FROM nodes`,
		condition: reputableNodesCondition,
		distinct:  true,
		limit:     reputableNodeCount,
		orderBy:   "last_net",
	}
	newNodeQuery = partialQuery{
		selection: `SELECT DISTINCT ON (last_net) last_net, id, address, last_ip_port, country_code, noise_proto, noise_public_key, debounce_limit, features, true FROM nodes`,
		condition: newNodesCondition,
		distinct:  true,
		limit:     newNodeCount,
		orderBy:   "last_net",
	}

	query := unionAll(newNodeQuery, reputableNodeQuery)
	query.query = cache.db.impl.WrapAsOfSystemInterval(query.query, criteria.AsOfSystemInterval)

	rows, err := cache.db.Query(ctx, cache.db.Rebind(query.query), query.args...)
	if err != nil {
		return nil, nil, Error.Wrap(err)
	}
	defer func() { err = errs.Combine(err, rows.Close()) }()

	for rows.Next() {
		var node nodeselection.SelectedNode
		node.Address = &pb.NodeAddress{}
		var lastIPPort sql.NullString
		var isNew bool
		var noise noiseScanner

		err = rows.Scan(&node.LastNet, &node.ID, &node.Address.Address, &node.LastIPPort, &node.CountryCode, &noise.Proto, &noise.PublicKey, &node.Address.DebounceLimit, &node.Address.Features, &isNew)
		if err != nil {
			return nil, nil, err
		}

		if lastIPPort.Valid {
			node.LastIPPort = lastIPPort.String
		}
		node.Address.NoiseInfo = noise.Convert()

		if isNew {
			newNodes = append(newNodes, &node)
		} else {
			reputableNodes = append(reputableNodes, &node)
		}
		// node.Exiting and node.Suspended are always false here, as we filter those nodes out unconditionally in nodeSelectionCondition.
		// By similar logic, all nodes selected here are "online" in terms of the specified criteria (specifically, OnlineWindow).
		node.Online = true

		if len(newNodes) >= newNodeCount && len(reputableNodes) >= reputableNodeCount {
			break
		}
	}
	return reputableNodes, newNodes, Error.Wrap(rows.Err())
}

// nodeSelectionCondition creates a condition with arguments that corresponds to the arguments.
func nodeSelectionCondition(ctx context.Context, criteria *overlay.NodeCriteria, excludedIDs []storj.NodeID, excludedNetworks []string, isNewNodeQuery bool) (condition, error) {
	var conds conditions
	conds.add(`disqualified IS NULL`)
	conds.add(`unknown_audit_suspended IS NULL`)
	conds.add(`offline_suspended IS NULL`)
	conds.add(`exit_initiated_at IS NULL`)

	conds.add(`free_disk >= ?`, criteria.FreeDisk)
	conds.add(`last_contact_success > ?`, time.Now().UTC().Add(-criteria.OnlineWindow))

	if isNewNodeQuery {
		conds.add(
			`vetted_at IS NULL`,
		)
	} else {
		conds.add(
			`vetted_at is NOT NULL`,
		)
	}

	if criteria.MinimumVersion != "" {
		v, err := version.NewSemVer(criteria.MinimumVersion)
		if err != nil {
			return condition{}, Error.New("invalid node selection criteria version: %v", err)
		}
		conds.add(
			`(major > ? OR (major = ? AND (minor > ? OR (minor = ? AND patch >= ?)))) AND release`,
			v.Major, v.Major, v.Minor, v.Minor, v.Patch,
		)
	}

	if len(excludedIDs) > 0 {
		conds.add(
			`NOT (id = ANY(?::bytea[]))`,
			pgutil.NodeIDArray(excludedIDs),
		)
	}
	if len(excludedNetworks) > 0 {
		conds.add(
			`NOT (last_net = ANY(?::text[]))`,
			pgutil.TextArray(excludedNetworks),
		)
	}
	conds.add(`last_net <> ''`)
	return conds.combine(), nil
}

// partialQuery corresponds to a query.
//
//	distinct=false
//
//	   $selection WHERE $condition ORDER BY $orderBy, RANDOM() LIMIT $limit
//
//	distinct=true
//
//	   SELECT * FROM ($selection WHERE $condition ORDER BY $orderBy, RANDOM()) filtered ORDER BY RANDOM() LIMIT $limit
type partialQuery struct {
	selection string
	condition condition
	distinct  bool
	orderBy   string
	limit     int
}

// isEmpty returns whether the result for the query is definitely empty.
func (partial partialQuery) isEmpty() bool {
	return partial.limit == 0
}

// asQuery combines partialQuery parameters into a single select query.
func (partial partialQuery) asQuery() query {
	var q strings.Builder
	var args []interface{}

	if partial.distinct {
		// For distinct queries we need to redo randomized ordering.
		fmt.Fprintf(&q, "SELECT * FROM (")
	}

	fmt.Fprint(&q, partial.selection, " WHERE ", partial.condition.query)
	args = append(args, partial.condition.args...)

	if partial.orderBy != "" {
		fmt.Fprintf(&q, " ORDER BY %s, RANDOM() ", partial.orderBy)
	} else {
		fmt.Fprint(&q, " ORDER BY RANDOM() ")
	}

	if !partial.distinct {
		fmt.Fprint(&q, " LIMIT ? ")
		args = append(args, partial.limit)
	} else {
		fmt.Fprint(&q, ") filtered ORDER BY RANDOM() LIMIT ?")
		args = append(args, partial.limit)
	}

	return query{query: q.String(), args: args}
}

// unionAll combines multiple partial queries into a single query.
func unionAll(partials ...partialQuery) query {
	var queries []string
	var args []interface{}
	for _, partial := range partials {
		if partial.isEmpty() {
			continue
		}

		q := partial.asQuery()
		queries = append(queries, q.query)
		args = append(args, q.args...)
	}

	if len(queries) == 0 {
		return query{}
	}
	if len(queries) == 1 {
		return query{query: queries[0], args: args}
	}

	return query{
		query: "(" + strings.Join(queries, ") UNION ALL (") + ")",
		args:  args,
	}
}

type condition struct {
	query string
	args  []interface{}
}

type conditions []condition

func (conds *conditions) add(q string, args ...interface{}) {
	*conds = append(*conds, condition{query: q, args: args})
}

func (conds conditions) combine() condition {
	var qs []string
	var args []interface{}
	for _, c := range conds {
		qs = append(qs, c.query)
		args = append(args, c.args...)
	}
	return condition{query: " " + strings.Join(qs, " AND ") + " ", args: args}
}

type query struct {
	query string
	args  []interface{}
}
