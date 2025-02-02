package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/xerrors"

	"github.com/NYTimes/gziphandler"
	"github.com/an1kelesh/trivy-db/pkg/db"
	"github.com/an1kelesh/trivy-db/pkg/metadata"
	dbc "github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	"github.com/aquasecurity/trivy/pkg/version"
	rpcCache "github.com/aquasecurity/trivy/rpc/cache"
	rpcScanner "github.com/aquasecurity/trivy/rpc/scanner"
	"github.com/twitchtv/twirp"
)

const updateInterval = 1 * time.Hour

// Server represents Trivy server
type Server struct {
	appVersion   string
	addr         string
	cacheDir     string
	token        string
	tokenHeader  string
	dbRepository string

	// For OCI registries
	types.RegistryOptions
}

// NewServer returns an instance of Server
func NewServer(appVersion, addr, cacheDir, token, tokenHeader, dbRepository string, opt types.RegistryOptions) Server {
	return Server{
		appVersion:      appVersion,
		addr:            addr,
		cacheDir:        cacheDir,
		token:           token,
		tokenHeader:     tokenHeader,
		dbRepository:    dbRepository,
		RegistryOptions: opt,
	}
}

// ListenAndServe starts Trivy server
func (s Server) ListenAndServe(serverCache cache.Cache, skipDBUpdate bool) error {
	requestWg := &sync.WaitGroup{}
	dbUpdateWg := &sync.WaitGroup{}

	go func() {
		worker := newDBWorker(dbc.NewClient(s.cacheDir, true, dbc.WithDBRepository(s.dbRepository)))
		ctx := context.Background()
		for {
			time.Sleep(updateInterval)
			if err := worker.update(ctx, s.appVersion, s.cacheDir, skipDBUpdate, dbUpdateWg, requestWg, s.RegistryOptions); err != nil {
				log.Logger.Errorf("%+v\n", err)
			}
		}
	}()

	mux := newServeMux(serverCache, dbUpdateWg, requestWg, s.token, s.tokenHeader, s.cacheDir)
	log.Logger.Infof("Listening %s...", s.addr)

	return http.ListenAndServe(s.addr, mux)
}

func newServeMux(serverCache cache.Cache, dbUpdateWg, requestWg *sync.WaitGroup,
	token, tokenHeader, cacheDir string) *http.ServeMux {
	withWaitGroup := func(base http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Stop processing requests during DB update
			dbUpdateWg.Wait()

			// Wait for all requests to be processed before DB update
			requestWg.Add(1)
			defer requestWg.Done()

			base.ServeHTTP(w, r)

		})
	}

	mux := http.NewServeMux()

	scanServer := rpcScanner.NewScannerServer(initializeScanServer(serverCache), nil)
	scanHandler := withToken(withWaitGroup(scanServer), token, tokenHeader)
	mux.Handle(rpcScanner.ScannerPathPrefix, gziphandler.GzipHandler(scanHandler))

	layerServer := rpcCache.NewCacheServer(NewCacheServer(serverCache), nil)
	layerHandler := withToken(withWaitGroup(layerServer), token, tokenHeader)
	mux.Handle(rpcCache.CachePathPrefix, gziphandler.GzipHandler(layerHandler))

	mux.HandleFunc("/healthz", func(rw http.ResponseWriter, r *http.Request) {
		if _, err := rw.Write([]byte("ok")); err != nil {
			log.Logger.Errorf("health check error: %s", err)
		}
	})

	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(version.NewVersionInfo(cacheDir)); err != nil {
			log.Logger.Errorf("get version error: %s", err)
		}
	})

	return mux
}

func withToken(base http.Handler, token, tokenHeader string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token != "" && token != r.Header.Get(tokenHeader) {
			rpcScanner.WriteError(w, twirp.NewError(twirp.Unauthenticated, "invalid token"))
			return
		}
		base.ServeHTTP(w, r)
	})
}

type dbWorker struct {
	dbClient dbc.Operation
}

func newDBWorker(dbClient dbc.Operation) dbWorker {
	return dbWorker{dbClient: dbClient}
}

func (w dbWorker) update(ctx context.Context, appVersion, cacheDir string,
	skipDBUpdate bool, dbUpdateWg, requestWg *sync.WaitGroup, opt types.RegistryOptions) error {
	log.Logger.Debug("Check for DB update...")
	needsUpdate, err := w.dbClient.NeedsUpdate(appVersion, skipDBUpdate)
	if err != nil {
		return xerrors.Errorf("failed to check if db needs an update")
	} else if !needsUpdate {
		return nil
	}

	log.Logger.Info("Updating DB...")
	if err = w.hotUpdate(ctx, cacheDir, dbUpdateWg, requestWg, opt); err != nil {
		return xerrors.Errorf("failed DB hot update: %w", err)
	}
	return nil
}

func (w dbWorker) hotUpdate(ctx context.Context, cacheDir string, dbUpdateWg, requestWg *sync.WaitGroup, opt types.RegistryOptions) error {
	tmpDir, err := os.MkdirTemp("", "db")
	if err != nil {
		return xerrors.Errorf("failed to create a temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err = w.dbClient.Download(ctx, tmpDir, opt); err != nil {
		return xerrors.Errorf("failed to download vulnerability DB: %w", err)
	}

	log.Logger.Info("Suspending all requests during DB update")
	dbUpdateWg.Add(1)
	defer dbUpdateWg.Done()

	log.Logger.Info("Waiting for all requests to be processed before DB update...")
	requestWg.Wait()

	if err = db.Close(); err != nil {
		return xerrors.Errorf("failed to close DB: %w", err)
	}

	// Copy trivy.db
	if _, err = fsutils.CopyFile(db.Path(tmpDir), db.Path(cacheDir)); err != nil {
		return xerrors.Errorf("failed to copy the database file: %w", err)
	}

	// Copy metadata.json
	if _, err = fsutils.CopyFile(metadata.Path(tmpDir), metadata.Path(cacheDir)); err != nil {
		return xerrors.Errorf("failed to copy the metadata file: %w", err)
	}

	log.Logger.Info("Reopening DB...")
	if err = db.Init(cacheDir); err != nil {
		return xerrors.Errorf("failed to open DB: %w", err)
	}

	return nil
}
