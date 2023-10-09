package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	sslcheck "github.com/iobear/sslcheck/lib"
	logmodule "github.com/iobear/sslcheck/log"
)

var runAs = filepath.Base(os.Args[0])
var version string
var logger *logmodule.Logger

type CLIArgs struct {
	IPAddress  string
	DomainName string
	Port       string
	Help       bool
	LogLevel   logmodule.LogLevel
	IsServer   bool
}

func parseCLIArgs() CLIArgs {
	var args CLIArgs
	var logLevelString string

	flag.StringVar(&args.IPAddress, "ip", "", "IP Address")
	flag.StringVar(&args.DomainName, "domain", "", "Domain Name")
	flag.StringVar(&args.Port, "port", "443", "Port Number")
	flag.BoolVar(&args.Help, "help", false, "Help")
	flag.StringVar(&logLevelString, "loglevel", "error", "Log level (debug, info, warning, error, critical)")
	flag.BoolVar(&args.IsServer, "serv", false, "Run as HTTP service")

	flag.Parse()

	switch logLevelString {
	case "debug":
		args.LogLevel = logmodule.DEBUG
	case "info":
		args.LogLevel = logmodule.INFO
	case "warn":
		args.LogLevel = logmodule.WARNING
	case "warning":
		args.LogLevel = logmodule.WARNING
	case "error":
		args.LogLevel = logmodule.ERROR
	case "critical":
		args.LogLevel = logmodule.CRITICAL
	default:
		log.Fatalf("Unknown log level: %s", logLevelString)
	}

	if args.DomainName == "" && len(flag.Args()) > 0 {
		args.DomainName = flag.Args()[0]
	}

	return args
}

func checkSSL(args CLIArgs) {
	logger = logmodule.NewLogger(args.LogLevel)
	checker := &sslcheck.SSLChecker{Logger: logger}

	if args.DomainName == "" && args.IPAddress == "" {
		logger.Error("Either domain name or IP address is required.")
		os.Exit(1)
	}

	info := sslcheck.SSLInfo{
		IPAddress:  args.IPAddress,
		DomainName: args.DomainName,
		Port:       args.Port,
	}
	result, err := checker.CheckSSL(info)

	if err != nil {
		logger.Error("Error: %v", err)
		os.Exit(1)
	}

	logger.Info("Is Valid: %v", result.IsValid)
	logger.Info("Details: %v", result.Details)
}

// Usage is what is run if the right parameters are not met upon startup.
func Usage() {
	// To embed the bot user and password comment the line above and uncomment the line below
	fmt.Printf("Usage: %v -i <ip address>  -p <port> -d <domain name> -loglevel <log level>\n", runAs)

	flag.PrintDefaults()
	fmt.Println(version)
}

func main() {
	args := parseCLIArgs()

	if args.Help {
		Usage()
		os.Exit(0)
	}

	if args.IsServer {
		StartServer()
		return
	}

	checkSSL(args)
}
