package main

import (
	"flag"
	"log"
	"os"
)

func main() {
	listenSpec := flag.String("listen", envOr("AJ_LISTEN", "vsock:5000"), "vsock:<port> or unix:<path>")
	maxConc := flag.Int("max-concurrent", 16, "maximum concurrent exec requests")
	allowRoot := flag.Bool("allow-root", false, "permit running workloads as uid 0 (never in production)")
	noDrop := flag.Bool("insecure-no-drop-privileges", false, "TEST ONLY: do not switch uid")
	flag.Parse()

	if os.Getpid() == 1 {
		setupInit()
	}
	if err := hardenSelf(); err != nil {
		log.Fatalf("refusing to start without no_new_privs on every thread: %v (build with CGO_ENABLED=0)", err)
	}
	shutdownOn()

	cfg := defaultExecConfig()
	cfg.allowRoot = *allowRoot
	cfg.dropCredentials = !*noDrop
	if *noDrop && os.Getpid() == 1 {
		log.Fatal("refusing -insecure-no-drop-privileges as PID 1")
	}

	l, err := listen(*listenSpec)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("aijailer-agent %s listening on %s", version, *listenSpec)
	newServer(cfg, *maxConc).serve(l, nil)
	if os.Getpid() == 1 {
		select {} // PID 1 must never exit
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
