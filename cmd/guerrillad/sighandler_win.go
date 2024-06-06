//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd
// +build !darwin,!dragonfly,!freebsd,!linux,!netbsd,!openbsd

package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	// enable the Redis redigo driver
	_ "github.com/phires/go-guerrilla/backends/storage/redigo"

	// Choose iconv or mail/encoding package which uses golang.org/x/net/html/charset
	//_ "github.com/phires/go-guerrilla/mail/iconv"
	_ "github.com/phires/go-guerrilla/mail/encoding"

	_ "github.com/go-sql-driver/mysql"
)

func sigHandler() {
	signal.Notify(signalChannel,
		syscall.SIGHUP,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		syscall.SIGINT,
		syscall.SIGKILL,
		os.Kill,
	)
	for sig := range signalChannel {
		if sig == syscall.SIGHUP {
			if ac, err := readConfig(configPath, pidFile); err == nil {
				_ = d.ReloadConfig(*ac)
			} else {
				mainlog.WithError(err).Error("Could not reload config")
			}
		} else if sig == syscall.SIGTERM || sig == syscall.SIGQUIT || sig == syscall.SIGINT || sig == os.Kill {
			mainlog.Infof("Shutdown signal caught")
			go func() {
				select {
				// exit if graceful shutdown not finished in 60 sec.
				case <-time.After(time.Second * 60):
					mainlog.Error("graceful shutdown timed out")
					os.Exit(1)
				}
			}()
			d.Shutdown()
			mainlog.Infof("Shutdown completed, exiting.")
			return
		} else {
			mainlog.Infof("Shutdown, unknown signal caught")
			return
		}
	}
}
