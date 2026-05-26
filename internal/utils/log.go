package utils

import (
	"fmt"
	"os"

	"github.com/Xwal13/VulcanEye/internal/config"
)

var errorLogFile *os.File

func InitErrorLogger(filename string) {
	if filename == "" {
		return
	}
	var err error
	errorLogFile, err = os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("%s[!] Could not create error log file: %v%s\n", config.ColorRed, err, config.ColorReset)
		errorLogFile = nil
	}
}

func CloseErrorLogger() {
	if errorLogFile != nil {
		errorLogFile.Close()
	}
}

func LogError(format string, args ...interface{}) {
	msg := fmt.Sprintf("[2006-01-02 15:04:05] [ERROR] "+format+"\n", args...)
	fmt.Fprint(os.Stderr, msg)
	if errorLogFile != nil {
		fmt.Fprint(errorLogFile, msg)
	}
}

func LogWarning(format string, args ...interface{}) {
	msg := fmt.Sprintf("[2006-01-02 15:04:05] [WARN] "+format+"\n", args...)
	fmt.Fprint(os.Stderr, msg)
	if errorLogFile != nil {
		fmt.Fprint(errorLogFile, msg)
	}
}

func LogInfo(format string, args ...interface{}) {
	msg := fmt.Sprintf("[2006-01-02 15:04:05] [INFO] "+format+"\n", args...)
	if errorLogFile != nil {
		fmt.Fprint(errorLogFile, msg)
	}
}

func LogDebug(format string, args ...interface{}) {
	msg := fmt.Sprintf("[2006-01-02 15:04:05] [DEBUG] "+format+"\n", args...)
	fmt.Fprint(os.Stderr, msg)
	if errorLogFile != nil {
		fmt.Fprint(errorLogFile, msg)
	}
}

func LogFatal(format string, args ...interface{}) {
	msg := fmt.Sprintf("[2006-01-02 15:04:05] [FATAL] "+format+"\n", args...)
	fmt.Fprint(os.Stderr, msg)
	if errorLogFile != nil {
		fmt.Fprint(errorLogFile, msg)
	}
	os.Exit(1)
}
