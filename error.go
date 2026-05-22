package main

import (
	"fmt"
	"os"
	"time"
)

var errorLogFile *os.File

// InitErrorLogger initializes error logging
func InitErrorLogger(logPath string) error {
	if logPath == "" {
		return nil
	}

	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open error log file: %v", err)
	}
	errorLogFile = f
	return nil
}

// CloseErrorLogger closes the error logger
func CloseErrorLogger() {
	if errorLogFile != nil {
		errorLogFile.Close()
	}
}

// LogError logs an error with timestamp
func LogError(severity string, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fullMsg := fmt.Sprintf("[%s] [%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), severity, msg)

	// Always print to stderr
	fmt.Fprint(os.Stderr, fullMsg)

	// Also write to error log file if available
	if errorLogFile != nil {
		fmt.Fprint(errorLogFile, fullMsg)
	}
}

// LogWarning logs a warning
func LogWarning(format string, args ...interface{}) {
	LogError("WARN", format, args...)
}

// LogInfo logs info
func LogInfo(format string, args ...interface{}) {
	LogError("INFO", format, args...)
}

// LogDebug logs debug info
func LogDebug(format string, args ...interface{}) {
	LogError("DEBUG", format, args...)
}

// LogFatal logs fatal error and exits
func LogFatal(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fullMsg := fmt.Sprintf("[%s] [FATAL] %s\n", time.Now().Format("2006-01-02 15:04:05"), msg)
	fmt.Fprint(os.Stderr, fullMsg)
	if errorLogFile != nil {
		fmt.Fprint(errorLogFile, fullMsg)
		errorLogFile.Close()
	}
	os.Exit(1)
}
