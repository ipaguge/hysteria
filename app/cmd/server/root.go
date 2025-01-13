package server

import (
	"github.com/apernet/hysteria/app/v2/cmd/common"
	"go.uber.org/zap"
	"os"
)

const (
	appACMEDirEnv = "HYSTERIA_ACME_DIR"
)

var (
	logger *zap.Logger
)

func InitLog(customLog *common.CustomCore) {
	logger = common.InitLog(customLog)
}

func envOrDefaultString(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
