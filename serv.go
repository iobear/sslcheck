package main

import (
	"encoding/json"
	"net/http"

	sslcheck "github.com/iobear/sslcheck/lib"
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

	checker := &sslcheck.SSLChecker{Logger: logger}
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
	http.HandleFunc("/check", handler)
	http.ListenAndServe(":8080", nil)
}
