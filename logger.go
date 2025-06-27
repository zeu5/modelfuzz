package modelfuzz

import (
	"os"

	"github.com/sirupsen/logrus"
)

// DefaultLogger stores the instance of the DefaultLogger
var DefaultLogger *Logger

// LogParams wrapper around key values used for logging
type LogParams map[string]interface{}

// Logger for logging
type Logger struct {
	entry *logrus.Entry
}

// NewLogger instantiates logger based on the config
func NewLogger() *Logger {
	l := logrus.New()
	l.SetOutput(os.Stdout)
	l.SetFormatter(&logrus.JSONFormatter{})
	return &Logger{
		entry: logrus.NewEntry(l),
	}
}

// Debug logs a debug message with the default logger
func Debug(s string) {
	DefaultLogger.Debug(s)
}

// Fatal logs the message and exits with non-zero exit code with the default logger
func Fatal(s string) {
	DefaultLogger.Fatal(s)
}

// Info logs a message with level `info` with the default logger
func Info(s string) {
	DefaultLogger.Info(s)
}

// Warn logs a message with level `warning` with the default logger
func Warn(s string) {
	DefaultLogger.Warn(s)
}

// Errors logs a message with level `error` with the default logger
func Error(s string) {
	DefaultLogger.Error(s)
}

// With returns a logger with the specified parameters
func With(params LogParams) *Logger {
	return DefaultLogger.With(params)
}

// SetLevel sets the level of the default logger
func SetLevel(l string) {
	DefaultLogger.SetLevel(l)
}

// Debug logs a debug message
func (l *Logger) Debug(s string) {
	l.entry.Debug(s)
}

// Fatal logs the message and exits with non-zero exit code
func (l *Logger) Fatal(s string) {
	l.entry.Fatal(s)
}

// Info logs a message with level `info`
func (l *Logger) Info(s string) {
	l.entry.Info(s)
}

// Warn logs a message with level `warning`
func (l *Logger) Warn(s string) {
	l.entry.Warn(s)
}

// Error logs a message with level `error`
func (l *Logger) Error(s string) {
	l.entry.Error(s)
}

// With returns a logger initialized with the parameters
func (l *Logger) With(params LogParams) *Logger {
	fields := logrus.Fields{}
	for k, v := range params {
		fields[k] = v
	}

	entry := l.entry.WithFields(fields)
	return &Logger{
		entry: entry,
	}
}

// SetLevel sets the level of the logger
func (l *Logger) SetLevel(level string) {
	levelL, err := logrus.ParseLevel(level)
	if err != nil {
		return
	}
	l.entry.Logger.SetLevel(levelL)
}

func init() {
	DefaultLogger = NewLogger()
	DefaultLogger.SetLevel("debug")
}
