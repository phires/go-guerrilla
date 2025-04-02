package main

import (
	"fmt"
	"os"

	"github.com/phires/go-guerrilla"
	"github.com/phires/go-guerrilla/log"

	// enable the Redis redigo driver
	_ "github.com/phires/go-guerrilla/backends/storage/redigo"

	// Choose iconv or mail/encoding package which uses golang.org/x/net/html/charset
	//_ "github.com/phires/go-guerrilla/mail/iconv"
	_ "github.com/phires/go-guerrilla/mail/encoding"

	"github.com/spf13/cobra"

	_ "github.com/go-sql-driver/mysql"
)

const (
	defaultPidFile = "/var/run/go-guerrilla.pid"
)

var (
	configPath string
	pidFile    string

	serveCmd = &cobra.Command{
		Use:   "serve",
		Short: "start the daemon and start all available servers",
		Run:   serve,
	}

	signalChannel = make(chan os.Signal, 1) // for trapping SIGHUP and friends
	mainlog       log.Logger

	d guerrilla.Daemon
)

func init() {
	// log to stderr on startup
	var err error
	mainlog, err = log.GetLogger(log.OutputStderr.String(), log.InfoLevel.String())
	if err != nil && mainlog != nil {
		mainlog.WithError(err).Errorf("Failed creating a logger to %s", log.OutputStderr)
	}
	cfgFile := "goguerrilla.conf" // deprecated default name
	if _, err := os.Stat(cfgFile); err != nil {
		cfgFile = "goguerrilla.conf.json" // use the new name
	}
	serveCmd.PersistentFlags().StringVarP(&configPath, "config", "c",
		cfgFile, "Path to the configuration file")
	// intentionally didn't specify default pidFile; value from config is used if flag is empty
	serveCmd.PersistentFlags().StringVarP(&pidFile, "pidFile", "p",
		"", "Path to the pid file")
	rootCmd.AddCommand(serveCmd)
}

func serve(cmd *cobra.Command, args []string) {
	logVersion()
	d = guerrilla.Daemon{Logger: mainlog}
	c, err := readConfig(configPath, pidFile)
	if err != nil {
		mainlog.WithError(err).Fatal("Error while reading config")
	}
	_ = d.SetConfig(*c)

	// Check that max clients is not greater than system open file limit.
	if ok, maxClients, fileLimit := guerrilla.CheckFileLimit(c); !ok {
		mainlog.Fatalf("Combined max clients for all servers (%d) is greater than open file limit (%d). "+
			"Please increase your open file limit or decrease max clients.", maxClients, fileLimit)
	}

	err = d.Start()
	if err != nil {
		mainlog.WithError(err).Error("Error(s) when creating new server(s)")
		os.Exit(1)
	}
	sigHandler()

}

// ReadConfig is called at startup, or when a SIG_HUP is caught
func readConfig(path string, pidFile string) (*guerrilla.AppConfig, error) {
	// Load in the config.
	// Note here is the only place we can make an exception to the
	// "treat config values as immutable". For example, here the
	// command line flags can override config values
	appConfig, err := d.LoadConfig(path)
	if err != nil {
		return &appConfig, fmt.Errorf("could not read config file: %s", err.Error())
	}
	// override config pidFile with with flag from the command line
	if len(pidFile) > 0 {
		appConfig.PidFile = pidFile
	} else if len(appConfig.PidFile) == 0 {
		appConfig.PidFile = defaultPidFile
	}
	if verbose {
		appConfig.LogLevel = "debug"
	}
	return &appConfig, nil
}
