package common

import (
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"os"
	"time"
)

// CustomCore 是自定义的 zapcore.Core
type CustomCore struct {
	OriginalCore zapcore.Core // 原始 Core
}

// With 增强原始 Core
func (c *CustomCore) With(fields []zapcore.Field) zapcore.Core {
	return &CustomCore{OriginalCore: c.OriginalCore.With(fields)}
}

// Check 拦截日志记录
func (c *CustomCore) Check(entry zapcore.Entry, checkedEntry *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(entry.Level) {
		// 通过原始 Core 检查
		return c.OriginalCore.Check(entry, checkedEntry)
	}
	return checkedEntry
}

// Write 实现日志的自定义处理
func (c *CustomCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	// 自定义处理日志，例如打印到控制台
	fmt.Printf("[Custom Logger] Level: %s | Time: %s | Msg: %s\n", entry.Level.String(), entry.Time.Format(time.RFC3339), entry.Message)

	// 打印字段
	for _, field := range fields {
		fmt.Printf("\tField: %s\n", field.Key)
	}

	// 将日志传递给原始 Core
	return nil
}

// Sync 同步日志
func (c *CustomCore) Sync() error {
	return c.OriginalCore.Sync()
}

// Enabled 判断日志级别是否启用
func (c *CustomCore) Enabled(level zapcore.Level) bool {
	return c.OriginalCore.Enabled(level)
}

// InitLog 初始化自定义日志
func InitLog(customLog *CustomCore) *zap.Logger {
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
		customLog.OriginalCore = core
		return zap.New(customLog)
	} else {
		return zap.New(&CustomCore{OriginalCore: core})
	}
}
