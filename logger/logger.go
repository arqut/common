// package logger

// import (
// 	goLogger "github.com/antigloss/go/logger"
// 	"github.com/arqut/common/system"
// )

// var (
// 	instance *goLogger.Logger
// )

// func InitLogger(prefix string) {
// 	var err error
// 	instance, err = goLogger.New(&goLogger.Config{
// 		LogDir:            system.Env("SYS_LOG_LEVEL", "./logs"),
// 		LogFileMaxSize:    200,
// 		LogFileMaxNum:     500,
// 		LogFileNumToDel:   50,
// 		LogFilenamePrefix: prefix,
// 		LogLevel:          goLogger.LogLevel(system.EnvInt("SYS_LOG_LEVEL", 2)), // goLogger.LogLevelTrace,
// 		LogDest:           goLogger.LogDestConsole,                              // goLogger.LogDestConsole | goLogger.LogDestFile
// 		Flag:              goLogger.ControlFlagLogDate | goLogger.ControlFlagLogLineNum,
// 	})
// 	if err != nil {
// 		panic(err)
// 	}
// }

// func logger() *goLogger.Logger {
// 	if instance == nil {
// 		InitLogger("")
// 	}
// 	return instance
// }

// // Trace writes a log with trace levelogger().
// func Trace(args ...interface{}) {
// 	logger().Trace(args)
// }

// // Tracef writes a log with trace levelogger().
// func Tracef(format string, args ...interface{}) {
// 	logger().Tracef(format, args)
// }

// // Info writes a log with info levelogger().
// func Info(args ...interface{}) {
// 	logger().Info(args)
// }

// // Infof writes a log with info levelogger().
// func Infof(format string, args ...interface{}) {
// 	logger().Infof(format, args)
// }

// // Warn writes a log with warning levelogger().
// func Warn(args ...interface{}) {
// 	logger().Warn(args)
// }

// // Warnf writes a log with warning levelogger().
// func Warnf(format string, args ...interface{}) {
// 	logger().Warnf(format, args)
// }

// // Error writes a log with error levelogger().
// func Error(args ...interface{}) {
// 	logger().Error(args)
// }

// // Errorf writes a log with error levelogger().
// func Errorf(format string, args ...interface{}) {
// 	logger().Errorf(format, args)
// }

// // Panic writes a log with panic level followed by a call to panic("Panic").
// func Panic(args ...interface{}) {
// 	logger().Panic(args)
// }

// // Panicf writes a log with panic level followed by a call to panic("Panicf").
// func Panicf(format string, args ...interface{}) {
// 	logger().Panicf(format, args)
// }

// // Fatal writes a log with fatal level followed by a call to os.Exit(-1).
// func Fatal(args ...interface{}) {
// 	logger().Fatal(args)
// }

// // Fatalf writes a log with fatal level followed by a call to os.Exit(-1).
// func Fatalf(format string, args ...interface{}) {
// 	logger().Fatalf(format, args)
// }
