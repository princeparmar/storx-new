// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package nodeselection_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"storj.io/common/identity/testidentity"
	"storj.io/common/storj"
	"storj.io/common/storj/location"
	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/storj/satellite/nodeselection"
)

func TestSelectByID(t *testing.T) {
	// create 3 nodes, 2 with same subnet
	// perform many node selections that selects 2 nodes
	// expect that the all node are selected ~33% of the time.
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	// create 3 nodes, 2 with same subnet
	lastNetDuplicate := "1.0.1"
	subnetA1 := &nodeselection.SelectedNode{
		ID:         testrand.NodeID(),
		LastNet:    lastNetDuplicate,
		LastIPPort: lastNetDuplicate + ".4:8080",
	}
	subnetA2 := &nodeselection.SelectedNode{
		ID:         testrand.NodeID(),
		LastNet:    lastNetDuplicate,
		LastIPPort: lastNetDuplicate + ".5:8080",
	}

	lastNetSingle := "1.0.2"
	subnetB1 := &nodeselection.SelectedNode{
		ID:         testrand.NodeID(),
		LastNet:    lastNetSingle,
		LastIPPort: lastNetSingle + ".5:8080",
	}

	nodes := []*nodeselection.SelectedNode{subnetA1, subnetA2, subnetB1}
	selector := nodeselection.RandomSelector()(nodes, nil)

	const (
		reqCount       = 2
		executionCount = 10000
	)

	var selectedNodeCount = map[storj.NodeID]int{}

	// perform many node selections that selects 2 nodes
	for i := 0; i < executionCount; i++ {
		selectedNodes, err := selector(reqCount, nil, nil)
		require.NoError(t, err)
		require.Len(t, selectedNodes, reqCount)
		for _, node := range selectedNodes {
			selectedNodeCount[node.ID]++
		}
	}

	subnetA1Count := float64(selectedNodeCount[subnetA1.ID])
	subnetA2Count := float64(selectedNodeCount[subnetA2.ID])
	subnetB1Count := float64(selectedNodeCount[subnetB1.ID])
	total := subnetA1Count + subnetA2Count + subnetB1Count
	assert.Equal(t, total, float64(reqCount*executionCount))

	const selectionEpsilon = 0.1
	const percent = 1.0 / 3.0
	assert.InDelta(t, subnetA1Count/total, percent, selectionEpsilon)
	assert.InDelta(t, subnetA2Count/total, percent, selectionEpsilon)
	assert.InDelta(t, subnetB1Count/total, percent, selectionEpsilon)
}

func TestSelectBySubnet(t *testing.T) {
	// create 3 nodes, 2 with same subnet
	// perform many node selections that selects 2 nodes
	// expect that the single node is selected 50% of the time
	// expect the 2 nodes with same subnet should each be selected 25% of time
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	// create 3 nodes, 2 with same subnet
	lastNetDuplicate := "1.0.1"
	subnetA1 := &nodeselection.SelectedNode{
		ID:         testrand.NodeID(),
		LastNet:    lastNetDuplicate,
		LastIPPort: lastNetDuplicate + ".4:8080",
	}
	subnetA2 := &nodeselection.SelectedNode{
		ID:         testrand.NodeID(),
		LastNet:    lastNetDuplicate,
		LastIPPort: lastNetDuplicate + ".5:8080",
	}

	lastNetSingle := "1.0.2"
	subnetB1 := &nodeselection.SelectedNode{
		ID:         testrand.NodeID(),
		LastNet:    lastNetSingle,
		LastIPPort: lastNetSingle + ".5:8080",
	}

	nodes := []*nodeselection.SelectedNode{subnetA1, subnetA2, subnetB1}
	attribute, err := nodeselection.CreateNodeAttribute("last_net")
	require.NoError(t, err)
	selector := nodeselection.AttributeGroupSelector(attribute)(nodes, nil)

	const (
		reqCount       = 2
		executionCount = 1000
	)

	var selectedNodeCount = map[storj.NodeID]int{}

	// perform many node selections that selects 2 nodes
	for i := 0; i < executionCount; i++ {
		selectedNodes, err := selector(reqCount, nil, nil)
		require.NoError(t, err)
		require.Len(t, selectedNodes, reqCount)
		for _, node := range selectedNodes {
			selectedNodeCount[node.ID]++
		}
	}

	subnetA1Count := float64(selectedNodeCount[subnetA1.ID])
	subnetA2Count := float64(selectedNodeCount[subnetA2.ID])
	subnetB1Count := float64(selectedNodeCount[subnetB1.ID])
	total := subnetA1Count + subnetA2Count + subnetB1Count
	assert.Equal(t, total, float64(reqCount*executionCount))

	// expect that the single node is selected 50% of the time
	// expect the 2 nodes with same subnet should each be selected 25% of time
	nodeID1total := subnetA1Count / total
	nodeID2total := subnetA2Count / total

	const (
		selectionEpsilon = 0.1
		uniqueSubnet     = 0.5
	)

	// we expect that the 2 nodes from the same subnet should be
	// selected roughly the same percent of the time
	assert.InDelta(t, nodeID2total, nodeID1total, selectionEpsilon)

	// the node from the unique subnet should be selected exactly half of the time
	nodeID3total := subnetB1Count / total
	assert.Equal(t, nodeID3total, uniqueSubnet)
}

func TestSelectBySubnetOneAtATime(t *testing.T) {
	// create 3 nodes, 2 with same subnet
	// perform many node selections that selects 1 node
	// expect that the single node is selected 50% of the time
	// expect the 2 nodes with same subnet should each be selected 25% of time
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	// create 3 nodes, 2 with same subnet
	lastNetDuplicate := "1.0.1"
	subnetA1 := &nodeselection.SelectedNode{
		ID:         testrand.NodeID(),
		LastNet:    lastNetDuplicate,
		LastIPPort: lastNetDuplicate + ".4:8080",
	}
	subnetA2 := &nodeselection.SelectedNode{
		ID:         testrand.NodeID(),
		LastNet:    lastNetDuplicate,
		LastIPPort: lastNetDuplicate + ".5:8080",
	}

	lastNetSingle := "1.0.2"
	subnetB1 := &nodeselection.SelectedNode{
		ID:         testrand.NodeID(),
		LastNet:    lastNetSingle,
		LastIPPort: lastNetSingle + ".5:8080",
	}

	nodes := []*nodeselection.SelectedNode{subnetA1, subnetA2, subnetB1}
	attribute, err := nodeselection.CreateNodeAttribute("last_net")
	require.NoError(t, err)
	selector := nodeselection.AttributeGroupSelector(attribute)(nodes, nil)

	const (
		reqCount       = 1
		executionCount = 1000
	)

	var selectedNodeCount = map[storj.NodeID]int{}

	// perform many node selections that selects 1 node
	for i := 0; i < executionCount; i++ {
		selectedNodes, err := selector(reqCount, nil, nil)
		require.NoError(t, err)
		require.Len(t, selectedNodes, reqCount)
		for _, node := range selectedNodes {
			selectedNodeCount[node.ID]++
		}
	}

	subnetA1Count := float64(selectedNodeCount[subnetA1.ID])
	subnetA2Count := float64(selectedNodeCount[subnetA2.ID])
	subnetB1Count := float64(selectedNodeCount[subnetB1.ID])
	total := subnetA1Count + subnetA2Count + subnetB1Count
	assert.Equal(t, total, float64(reqCount*executionCount))

	const (
		selectionEpsilon = 0.1
		uniqueSubnet     = 0.5
	)

	// we expect that the 2 nodes from the same subnet should be
	// selected roughly the same ~25% percent of the time
	assert.InDelta(t, subnetA2Count/total, subnetA1Count/total, selectionEpsilon)

	// expect that the single node is selected ~50% of the time
	assert.InDelta(t, subnetB1Count/total, uniqueSubnet, selectionEpsilon)
}

func TestSelectFiltered(t *testing.T) {

	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	// create 3 nodes, 2 with same subnet
	lastNetDuplicate := "1.0.1"
	firstID := testrand.NodeID()
	subnetA1 := &nodeselection.SelectedNode{
		ID:         firstID,
		LastNet:    lastNetDuplicate,
		LastIPPort: lastNetDuplicate + ".4:8080",
	}

	secondID := testrand.NodeID()
	subnetA2 := &nodeselection.SelectedNode{
		ID:         secondID,
		LastNet:    lastNetDuplicate,
		LastIPPort: lastNetDuplicate + ".5:8080",
	}

	thirdID := testrand.NodeID()
	lastNetSingle := "1.0.2"
	subnetB1 := &nodeselection.SelectedNode{
		ID:         thirdID,
		LastNet:    lastNetSingle,
		LastIPPort: lastNetSingle + ".5:8080",
	}

	nodes := []*nodeselection.SelectedNode{subnetA1, subnetA2, subnetB1}

	selector := nodeselection.RandomSelector()(nodes, nil)
	selected, err := selector(3, nil, nil)
	require.NoError(t, err)
	assert.Len(t, selected, 3)
	selected, err = selector(3, nil, nil)
	require.NoError(t, err)
	assert.Len(t, selected, 3)

	selector = nodeselection.RandomSelector()(nodes, nodeselection.NodeFilters{}.WithExcludedIDs([]storj.NodeID{firstID, secondID}))
	selected, err = selector(3, nil, nil)
	require.NoError(t, err)
	assert.Len(t, selected, 1)
}

func TestSelectFilteredMulti(t *testing.T) {
	// four subnets with 3 nodes in each. Only one per subnet is located in Germany.
	// Algorithm should pick the German one from each subnet, and 4 nodes should be possible to be picked.

	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	var nodes []*nodeselection.SelectedNode

	for i := 0; i < 12; i++ {
		nodes = append(nodes, &nodeselection.SelectedNode{
			ID:          testidentity.MustPregeneratedIdentity(i, storj.LatestIDVersion()).ID,
			LastNet:     fmt.Sprintf("68.0.%d", i/3),
			LastIPPort:  fmt.Sprintf("68.0.%d.%d:1000", i/3, i),
			CountryCode: location.Germany + location.CountryCode(i%3),
		})

	}

	filter := nodeselection.NodeFilters{}.WithCountryFilter(location.NewSet(location.Germany))
	attribute, err := nodeselection.CreateNodeAttribute("last_net")
	require.NoError(t, err)
	selector := nodeselection.AttributeGroupSelector(attribute)(nodes, filter)
	for i := 0; i < 100; i++ {
		selected, err := selector(4, nil, nil)
		require.NoError(t, err)
		assert.Len(t, selected, 4)
	}
}

func TestFilterSelector(t *testing.T) {
	list := nodeselection.AllowedNodesFilter([]storj.NodeID{
		testidentity.MustPregeneratedIdentity(1, storj.LatestIDVersion()).ID,
		testidentity.MustPregeneratedIdentity(2, storj.LatestIDVersion()).ID,
		testidentity.MustPregeneratedIdentity(3, storj.LatestIDVersion()).ID,
	})

	selector := nodeselection.FilterSelector(nodeselection.NewExcludeFilter(list), nodeselection.RandomSelector())

	// initialize the node space
	var nodes []*nodeselection.SelectedNode
	for i := 0; i < 10; i++ {
		nodes = append(nodes, &nodeselection.SelectedNode{
			ID: testidentity.MustPregeneratedIdentity(i, storj.LatestIDVersion()).ID,
		})
	}

	initialized := selector(nodes, nil)
	for i := 0; i < 100; i++ {
		selected, err := initialized(3, []storj.NodeID{}, nil)
		require.NoError(t, err)
		for _, s := range selected {
			for _, w := range list {
				// make sure we didn't choose from the white list, as they are excluded
				require.NotEqual(t, s.ID, w)
			}
		}
	}
}

func TestBalancedSelector(t *testing.T) {
	attribute, err := nodeselection.CreateNodeAttribute("tag:owner")
	require.NoError(t, err)

	ownerCounts := map[string]int{"A": 3, "B": 30, "C": 30, "D": 5}
	var nodes []*nodeselection.SelectedNode

	idIndex := 0
	for owner, count := range ownerCounts {
		for i := 0; i < count; i++ {
			nodes = append(nodes, &nodeselection.SelectedNode{
				ID: testidentity.MustPregeneratedIdentity(idIndex, storj.LatestIDVersion()).ID,
				Tags: nodeselection.NodeTags{
					{
						Name:  "owner",
						Value: []byte(owner),
					},
				},
			})
			idIndex++
		}
	}

	selector := nodeselection.BalancedGroupBasedSelector(attribute)(nodes, nil)

	badSelection := 0
	for i := 0; i < 1000; i++ {
		selectedNodes, err := selector(10, nil, nil)
		require.NoError(t, err)

		require.Len(t, selectedNodes, 10)

		histogram := map[string]int{}
		for _, node := range selectedNodes {
			histogram[attribute(*node)] = histogram[attribute(*node)] + 1
		}
		for _, c := range histogram {
			if c > 5 {
				badSelection++
				break
			}
		}
	}
	// there is a very-very low chance to have wrong selection if we select one from A
	// and all the other random selection will select the same node again
	require.True(t, badSelection < 5)
}

func TestBalancedSelectorWithExisting(t *testing.T) {
	attribute, err := nodeselection.CreateNodeAttribute("tag:owner")
	require.NoError(t, err)

	ownerCounts := map[string]int{"A": 3, "B": 10, "C": 30, "D": 5, "E": 1}
	var nodes []*nodeselection.SelectedNode

	var excluded []storj.NodeID
	var alreadySelected []*nodeselection.SelectedNode

	idIndex := 0
	for owner, count := range ownerCounts {
		for i := 0; i < count; i++ {
			nodes = append(nodes, &nodeselection.SelectedNode{
				ID: testidentity.MustPregeneratedIdentity(idIndex, storj.LatestIDVersion()).ID,
				Tags: nodeselection.NodeTags{
					{
						Name:  "owner",
						Value: []byte(owner),
					},
				},
			})
			idIndex++
			if owner == "A" {
				excluded = append(excluded, nodes[len(nodes)-1].ID)
			}
			if owner == "B" && len(alreadySelected) < 9 {
				alreadySelected = append(alreadySelected, nodes[len(nodes)-1])
			}
		}
	}

	selector := nodeselection.BalancedGroupBasedSelector(attribute)(nodes, nil)

	histogram := map[string]int{}
	for i := 0; i < 1000; i++ {
		selectedNodes, err := selector(7, excluded, alreadySelected)
		require.NoError(t, err)

		require.Len(t, selectedNodes, 7)

		for _, node := range selectedNodes {
			histogram[attribute(*node)]++
		}
	}
	// from the initial {"A": 3, "B": 10, "C": 30, "D": 5, "E": 1}

	// A is fully excluded
	require.Equal(t, 0, histogram["A"])

	require.Greater(t, histogram["B"], 100)
	require.Less(t, histogram["B"], 800)

	require.Greater(t, histogram["C"], 1000)
	require.Greater(t, histogram["D"], 1000)

	require.Equal(t, 1000, histogram["E"])

}
