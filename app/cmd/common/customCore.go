package common

import (
	"context"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"os"
)

// CustomCore 是自定义的 zapcore.Core
type CustomCore interface {
	zapcore.Core // 原始 Core
}

// InitLog 初始化自定义日志
func InitLog(customLog zapcore.Core) *zap.Logger {
	logLevel := zapcore.DebugLevel

	// 定义编码器
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "time"
	encoderConfig.LevelKey = "level"
	encoderConfig.MessageKey = "msg"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder

	encoder := zapcore.NewConsoleEncoder(encoderConfig)

	// 构建原始 Core
	core := zapcore.NewCore(encoder, zapcore.AddSync(os.Stdout), logLevel)

	if customLog != nil {
		//return zap.New(customLog)
		return zap.New(customLog)
	} else {
		return zap.New(core)
	}
}

func IsContextCancelled(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		// 上下文被取消或超时
		return true
	default:
		// 上下文仍然有效
		return false
	}
}
