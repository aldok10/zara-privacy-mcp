package bootstrap

import (
	"os"

	"go.uber.org/fx"

	"github.com/aldok10/zara-privacy-mcp/internal/ai"
	"github.com/aldok10/zara-privacy-mcp/internal/classify"
	"github.com/aldok10/zara-privacy-mcp/internal/compress"
	"github.com/aldok10/zara-privacy-mcp/internal/db"
	"github.com/aldok10/zara-privacy-mcp/internal/detector"
	"github.com/aldok10/zara-privacy-mcp/internal/audit"
	"github.com/aldok10/zara-privacy-mcp/internal/engine"
	httpproxy "github.com/aldok10/zara-privacy-mcp/internal/http"
	"github.com/aldok10/zara-privacy-mcp/internal/observe"
	"github.com/aldok10/zara-privacy-mcp/internal/store"

	"github.com/aldok10/zara-privacy-mcp/application/tools"
	"github.com/aldok10/zara-privacy-mcp/config"
	"github.com/aldok10/zara-privacy-mcp/transport"
)

// Module wires all dependencies using uber-go/fx.
var Module = fx.Module("zara",
	fx.Provide(
		provideDetectors,
		provideStore,
		provideAuditLogger,
		provideEngine,
		provideCompressor,
		provideClassifier,
		provideDBRegistry,
		provideMongoRegistry,
		provideRedisRegistry,
		provideAPIRegistry,
		provideAIRegistry,
		provideAIRouter,
		provideObserve,
		provideHandlers,
		provideMCPServer,
	),
)

type detectors struct {
	Secret *detector.SecretDetector
	PII    *detector.PIIDetector
}

func provideDetectors() detectors {
	return detectors{
		Secret: detector.NewSecretDetector(),
		PII:    detector.NewPIIDetector(),
	}
}

func provideStore(cfg *config.Config) (*store.MappingStore, error) {
	dbPath := expandHome(cfg.DBPath)
	return store.NewMappingStore(dbPath, []byte(cfg.EncryptionKey))
}

func provideEngine(d detectors, s *store.MappingStore) *engine.RedactEngine {
	return engine.NewRedactEngine(d.Secret, d.PII, s)
}

func provideCompressor(cfg *config.Config) *compress.Compressor {
	return compress.NewCompressor(cfg.MaxTokens)
}

func provideClassifier() *classify.Classifier {
	return classify.NewClassifier()
}

func provideDBRegistry(cfg *config.Config, d detectors) *db.Registry {
	reg := db.NewRegistry()
	for _, dbc := range cfg.Databases {
		reg.Add(db.Config{
			Name: dbc.Name, Driver: dbc.Driver, DSN: dbc.DSN,
			MaxConns: dbc.MaxConns, MaxIdleConns: dbc.MaxIdleConns,
		}, d.Secret, d.PII)
	}
	return reg
}

func provideMongoRegistry(cfg *config.Config, d detectors) *db.MongoRegistry {
	reg := db.NewMongoRegistry()
	for _, mc := range cfg.MongoDBs {
		reg.Add(db.MongoConfig{Name: mc.Name, URI: mc.URI, Database: mc.Database}, d.Secret, d.PII)
	}
	return reg
}

func provideRedisRegistry(cfg *config.Config, d detectors) *db.RedisRegistry {
	reg := db.NewRedisRegistry()
	for _, rc := range cfg.RedisDBs {
		reg.Add(db.RedisConfig{
			Name: rc.Name, Addr: rc.Addr, Username: rc.Username,
			Password: rc.Password, DB: rc.DB,
		}, d.Secret, d.PII)
	}
	return reg
}

func provideAPIRegistry(cfg *config.Config, d detectors) *httpproxy.Registry {
	reg := httpproxy.NewRegistry(d.Secret, d.PII)
	for _, apic := range cfg.APIs {
		reg.Add(httpproxy.APIConfig{
			Name: apic.Name, BaseURL: apic.BaseURL,
			AuthType: apic.AuthType, AuthEnv: apic.AuthEnv, Headers: apic.Headers,
		})
	}
	return reg
}

func provideAIRegistry(cfg *config.Config) *ai.Registry {
	reg := ai.NewRegistry()
	for _, aic := range cfg.AIProviders {
		reg.Add(ai.Provider{Name: aic.Name, BaseURL: aic.BaseURL, APIKey: aic.APIKey, Models: aic.Models})
	}
	// Register free providers as fallback
	for _, fp := range ai.FreeProviders() {
		if _, exists := reg.Get(fp.Name); !exists {
			reg.Add(fp)
		}
	}
	return reg
}

func provideAIRouter(reg *ai.Registry, eng *engine.RedactEngine, cfg *config.Config) *ai.Router {
	router := ai.NewRouter(reg, eng, ai.RouterConfig{
		Fallback:   reg.List(),
		MaxRetries: 2,
	})

	// Create pools for providers with multiple API keys
	for _, aic := range cfg.AIProviders {
		if len(aic.APIKeys) > 1 {
			accounts := make([]ai.Provider, 0, len(aic.APIKeys))
			for _, key := range aic.APIKeys {
				accounts = append(accounts, ai.Provider{
					Name: aic.Name, BaseURL: aic.BaseURL, APIKey: key, Models: aic.Models,
				})
			}
			router.AddPool(ai.NewPool(aic.Name, accounts...))
		}
	}

	return router
}

func provideObserve(cfg *config.Config) *observe.Client {
	return observe.New(observe.Config{
		URL: cfg.ObserveURL, User: cfg.ObserveUser,
		Key: cfg.ObserveKey, Stream: cfg.ObserveStream,
	})
}

func provideHandlers(
	eng *engine.RedactEngine,
	comp *compress.Compressor,
	cls *classify.Classifier,
	st *store.MappingStore,
	dbReg *db.Registry,
	mongoReg *db.MongoRegistry,
	redisReg *db.RedisRegistry,
	apiReg *httpproxy.Registry,
	aiReg *ai.Registry,
	router *ai.Router,
	cfg *config.Config,
) *tools.Handlers {
	return &tools.Handlers{
		Engine:         eng,
		Compressor:     comp,
		Classifier:     cls,
		Store:          st,
		DBRegistry:     dbReg,
		MongoRegistry:  mongoReg,
		RedisRegistry:  redisReg,
		APIRegistry:    apiReg,
		AIRegistry:     aiReg,
		AIRouter:       router,
		AppConfig:      cfg,
		DefaultLocales: cfg.DefaultLocales,
	}
}

func provideMCPServer(h *tools.Handlers, obs *observe.Client) *transport.MCPServer {
	return transport.NewMCPServer(h, obs)
}

func provideAuditLogger(cfg *config.Config) *audit.Logger {
	path := os.Getenv("ZARA_AUDIT_LOG")
	return audit.New(path)
}
