package main

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
)

var (
	scanMutex      sync.Mutex
	isScanRunning  bool
	scanCancelled  bool
	shutdownChan   = make(chan struct{})
)

// InitGracefulShutdown sets up signal handlers for graceful shutdown
func InitGracefulShutdown(cfg *ScanConfig) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		LogWarning("Received signal: %v", sig)
		scanCancelled = true
		LogInfo("Gracefully shutting down scan...")

		// Finalize output with current findings
		if err := FinalizeOutput(cfg); err != nil {
			LogError("ERROR", "Error writing final output: %v", err)
		}

		close(shutdownChan)
		os.Exit(0)
	}()
}

// MarkScanStarted marks the scan as running
func MarkScanStarted() {
	scanMutex.Lock()
	defer scanMutex.Unlock()
	isScanRunning = true
	scanCancelled = false
}

// MarkScanCompleted marks the scan as completed
func MarkScanCompleted() {
	scanMutex.Lock()
	defer scanMutex.Unlock()
	isScanRunning = false
}

// IsScanCancelled checks if scan was cancelled
func IsScanCancelled() bool {
	scanMutex.Lock()
	defer scanMutex.Unlock()
	return scanCancelled
}

// IsScanRunning checks if scan is running
func IsScanRunning() bool {
	scanMutex.Lock()
	defer scanMutex.Unlock()
	return isScanRunning
}

// WaitForShutdown waits for shutdown signal
func WaitForShutdown() {
	<-shutdownChan
}
