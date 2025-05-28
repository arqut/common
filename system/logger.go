package system

import "github.com/antigloss/go/logger"

var Logger *logger.Logger

func InitLogger(prefix string) {
	var err error
	Logger, err = logger.New(&logger.Config{
		LogDir:            Env("SYS_LOG_DIR", "./logs"),
		LogFileMaxSize:    200,
		LogFileMaxNum:     500,
		LogFileNumToDel:   50,
		LogFilenamePrefix: prefix,
		LogLevel:          logger.LogLevel(EnvInt("SYS_LOG_LEVEL", 1)), // sysLogger.LogLevelTrace,
		LogDest:           logger.LogDestConsole,                       // sysLogger.LogDestConsole | logger.LogDestFile
		Flag:              logger.ControlFlagLogDate | logger.ControlFlagLogLineNum,
	})
	if err != nil {
		panic(err)
	}
}
