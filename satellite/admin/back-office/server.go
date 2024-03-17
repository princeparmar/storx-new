// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package admin

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"storj.io/common/errs2"
	"storj.io/storj/private/emptyfs"
)

// Assets contains either the built admin/back-office/ui or it is nil.
var Assets fs.FS = emptyfs.FS{}

// PathPrefix is the path that will be prefixed to the router passed to the NewServer constructor.
// This is temporary until this server will replace the storj.io/storj/satellite/admin/server.go.
const PathPrefix = "/back-office/"

var (
	// Error is the error class that wraps all the errors returned by this package.
	Error = errs.Class("satellite-admin")

	mon = monkit.Package()
)

// Config defines configuration for the satellite administration server.
type Config struct {
	StaticDir string `help:"an alternate directory path which contains the static assets for the satellite administration web app. When empty, it uses the embedded assets" releaseDefault:"" devDefault:""`

	UserGroupsRoleAdmin           []string `help:"the list of groups whose users has the administration role"   releaseDefault:"" devDefault:""`
	UserGroupsRoleViewer          []string `help:"the list of groups whose users has the viewer role"           releaseDefault:"" devDefault:""`
	UserGroupsRoleCustomerSupport []string `help:"the list of groups whose users has the customer support role" releaseDefault:"" devDefault:""`
	UserGroupsRoleFinanceManager  []string `help:"the list of groups whose users has the finance manager role"  releaseDefault:"" devDefault:""`
}

// Server serves the API endpoints and the web application to allow preforming satellite
// administration tasks.
type Server struct {
	log      *zap.Logger
	listener net.Listener

	config Config

	server http.Server
}

// NewServer creates a satellite administration server instance with the provided dependencies and
// configurations.
//
// When listener is nil, Server.Run is a noop.
func NewServer(
	log *zap.Logger,
	listener net.Listener,
	service *Service,
	root *mux.Router,
	config Config,
) *Server {
	server := &Server{
		log:      log,
		listener: listener,
		config:   config,
	}

	if root == nil {
		root = mux.NewRouter()
	}

	auth := NewAuthorizer(
		log,
		config.UserGroupsRoleAdmin,
		config.UserGroupsRoleViewer,
		config.UserGroupsRoleCustomerSupport,
		config.UserGroupsRoleFinanceManager,
	)

	// API endpoints.
	// API generator already add the PathPrefix.
	NewPlacementManagement(log, mon, service, root)
	NewUserManagement(log, mon, service, root, auth)
	NewProjectManagement(log, mon, service, root, auth)
	NewSettings(log, mon, service, root)

	root = root.PathPrefix(PathPrefix).Subrouter()
	// Static assets for the web interface.
	// This handler must be the last one because it uses the root as prefix, otherwise, it will serve
	// all the paths defined by the handlers set after this one.
	var staticHandler http.Handler
	if config.StaticDir == "" {
		staticHandler = http.StripPrefix(PathPrefix, http.FileServer(http.FS(Assets)))
	} else {
		staticHandler = http.StripPrefix(PathPrefix, http.FileServer(http.Dir(config.StaticDir)))
	}

	root.PathPrefix("/").Handler(staticHandler).Methods("GET")

	return server
}

// Run starts the administration HTTP server using the provided listener.
// If listener is nil, it does nothing and return nil.
func (server *Server) Run(ctx context.Context) error {
	if server.listener == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	var group errgroup.Group
	group.Go(func() error {
		<-ctx.Done()
		return Error.Wrap(server.server.Shutdown(context.Background()))
	})
	group.Go(func() error {
		defer cancel()
		err := server.server.Serve(server.listener)
		if errs2.IsCanceled(err) || errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		return Error.Wrap(err)
	})
	return group.Wait()
}

// Close closes server and underlying listener.
func (server *Server) Close() error {
	return Error.Wrap(server.server.Close())
}
