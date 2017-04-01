// Package main
//
// Purpose of this program:
// I firewall off several ports where only whitelisted IPs may access them. I
// want to automatically permit IPs that login via SSH.
//
// This program tails the ssh auth log and records IPs as they log in. A
// separate program (iptables-manage) ingests these IPs and updates the
// firewall.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"time"

	"github.com/horgh/iptables-manage/cidrlist"
	"github.com/hpcloud/tail"
)

// Args are command line arguments.
type Args struct {
	LogFile  string
	CIDRFile string
	Verbose  bool
}

func main() {
	args, err := getArgs()
	if err != nil {
		flag.PrintDefaults()
		os.Exit(1)
	}

	tailConfig := tail.Config{
		ReOpen: true,
		Follow: true,
	}

	tailer, err := tail.TailFile(args.LogFile, tailConfig)
	if err != nil {
		log.Fatalf("Unable to tail file: %s", err)
	}

	// Sep 21 14:52:13 beast sshd[31281]: Accepted publickey for username from 127.0.0.1 port 43970 ssh2: RSA hex:here
	// Sep 21 15:22:31 beast sshd[31860]: Accepted password for username from 127.0.0.1 port 40917 ssh2
	re := regexp.MustCompile("^\\S+\\s+\\d+\\s+\\d+:\\d+:\\d+\\s+\\S+\\s+sshd\\[\\d+\\]: Accepted (?:publickey|password) for (\\S+) from (\\S+)")

	for line := range tailer.Lines {
		matches := re.FindStringSubmatch(line.Text)
		if matches == nil {
			if args.Verbose {
				log.Printf("Line did not match: %s", line.Text)
			}
			continue
		}

		user := matches[1]
		ip := matches[2]

		comment := fmt.Sprintf("SSH: %s @ %s", user,
			time.Now().Format(time.RFC1123))
		err := cidrlist.RecordIP(args.CIDRFile, ip, comment)
		if err != nil {
			log.Fatalf("Unable to record IP: %s: User: %s: %s", ip, user, err)
		}

		if args.Verbose {
			log.Printf("Recorded: User: %s IP: %s", user, ip)
		}
	}
}

func getArgs() (Args, error) {
	logFile := flag.String("log-file", "", "SSH log file to watch.")
	cidrFile := flag.String("cidr-file", "", "File to record to.")
	verbose := flag.Bool("verbose", false, "Enable verbose output.")

	flag.Parse()

	if len(*logFile) == 0 {
		return Args{}, fmt.Errorf("you must specify a log file")
	}
	if len(*cidrFile) == 0 {
		return Args{}, fmt.Errorf("you must specify a CIDR IPs")
	}

	return Args{
		LogFile:  *logFile,
		CIDRFile: *cidrFile,
		Verbose:  *verbose,
	}, nil
}
