package config

import "fmt"

func DebugPrintf(cfg *ScanConfig, s string, args ...interface{}) {
	if cfg.Debug {
		fmt.Printf(ColorCyan+"[DEBUG] "+s+ColorReset+"\n", args...)
	}
}
