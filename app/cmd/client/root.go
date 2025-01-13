package client

import (
	"github.com/apernet/hysteria/app/v2/cmd/common"
	"go.uber.org/zap"
)

var (
	logger *zap.Logger
)

// InitLog 初始化自定义日志
func InitLog(customLog *common.CustomCore) {
	logger = common.InitLog(customLog)
}
