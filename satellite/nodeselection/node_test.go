// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package nodeselection

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"storj.io/common/identity/testidentity"
	"storj.io/common/storj"
	"storj.io/common/storj/location"
)

func TestNodeAttribute(t *testing.T) {
	must := func(a NodeAttribute, err error) NodeAttribute {
		require.NoError(t, err)
		return a
	}

	assert.Equal(t, "127.0.0.1", must(CreateNodeAttribute("last_net"))(SelectedNode{
		LastNet: "127.0.0.1",
	}))

	assert.Equal(t, "0xCAFEBABE", must(CreateNodeAttribute("wallet"))(SelectedNode{
		Wallet: "0xCAFEBABE",
	}))

	assert.Equal(t, "ahoj@storj.io", must(CreateNodeAttribute("email"))(SelectedNode{
		Email: "ahoj@storj.io",
	}))

	assert.Equal(t, "DE", must(CreateNodeAttribute("country"))(SelectedNode{
		CountryCode: location.Germany,
	}))

	signerID := testidentity.MustPregeneratedIdentity(1, storj.LatestIDVersion()).ID
	otherSignerID := testidentity.MustPregeneratedIdentity(2, storj.LatestIDVersion()).ID

	assert.Equal(t, "bar", must(CreateNodeAttribute(fmt.Sprintf("tag:%s/foo", signerID)))(SelectedNode{
		Tags: NodeTags{
			{
				Signer: signerID,
				Name:   "foo",
				Value:  []byte("bar"),
			},
		},
	}))
	assert.Equal(t, "", must(CreateNodeAttribute(fmt.Sprintf("tag:%s/foo", signerID)))(SelectedNode{
		Tags: NodeTags{
			{
				Signer: otherSignerID,
				Name:   "foo",
				Value:  []byte("bar"),
			},
		},
	}))

	assert.Equal(t, "bar", must(CreateNodeAttribute("tag:foo"))(SelectedNode{
		Tags: NodeTags{
			{
				Signer: otherSignerID,
				Name:   "foo",
				Value:  []byte("bar"),
			},
		},
	}))

	assert.Equal(t, "true", must(CreateNodeAttribute("vetted"))(SelectedNode{
		Vetted: true,
	}))

	_, err := CreateNodeAttribute("tag:xxx/foo")
	require.ErrorContains(t, err, "has invalid NodeID")

	_, err = CreateNodeAttribute("tag:a/b/c")
	require.ErrorContains(t, err, "should be defined")
}
