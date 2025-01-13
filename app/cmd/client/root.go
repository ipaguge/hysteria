package client

import (
	"github.com/apernet/hysteria/app/v2/cmd/common"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	logger *zap.Logger
)

// InitLog 初始化自定义日志
func InitLog(customLog zapcore.Core) {
	logger = common.InitLog(customLog)
}
