package serv

import (
	"encoding/json"
	"net/http"
	"os"

	sslcheck "github.com/iobear/sslcheck/lib"
	logmodule "github.com/iobear/sslcheck/log"
)

// webserver for sslcheck
func handler(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	port := r.URL.Query().Get("port")
	ip := r.URL.Query().Get("ip")

	if domain == "" && ip == "" {
		http.Error(w, "Either domain name or IP address is required.", http.StatusBadRequest)
		return
	}

	if port == "" {
		port = "443"
	}

	checker := &sslcheck.SSLChecker{Logger: logmodule.NewLogger(logmodule.ERROR)}

	info := sslcheck.SSLInfo{
		IPAddress:  ip,
		DomainName: domain,
		Port:       port,
	}
	result, err := checker.CheckSSL(info)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data, err := json.Marshal(result)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func StartServer() {
	listen_addr := ":8080"
	if val, ok := os.LookupEnv("FUNCTIONS_CUSTOMHANDLER_PORT"); ok {
		listen_addr = ":" + val
	}
	http.HandleFunc("/api/check", handler)
	http.ListenAndServe(listen_addr, nil)
}
