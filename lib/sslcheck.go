package sslcheck

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	logmodule "github.com/iobear/sslcheck/log"
)

type SSLInfo struct {
	IPAddress  string
	DomainName string
	Port       string
}

type SSLDetail struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type SSLChecker struct {
	Logger *logmodule.Logger
}

type CertInfo struct {
	IsValid bool
	Details []SSLDetail
}

func ParseInput(info SSLInfo) (string, string, error) {
	if info.Port == "" {
		info.Port = "443"
	}

	domainName := info.DomainName
	passedPort := info.Port

	domainName = strings.TrimPrefix(domainName, "https://")

	target := info.IPAddress
	if target == "" {
		ip, err := net.ResolveIPAddr("ip4", domainName)
		if err != nil {
			return "", "", fmt.Errorf("could not resolve domain name %v: %v", domainName, err)
		}
		target = ip.String()
	}

	if passedPort != "" {
		target = target + ":" + passedPort
	} else {
		target = target + ":443"
	}

	return target, domainName, nil
}

func ConnectToServer(target string, domainName string) (*tls.Conn, error) {
	ipConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("could not connect to %v: %v", target, err)
	}

	config := tls.Config{ServerName: domainName}
	conn := tls.Client(ipConn, &config)

	if err := conn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("TLS Handshake failed for %v - %v: %v", target, domainName, err)
	}

	return conn, nil
}

func CertDetails(conn *tls.Conn) []SSLDetail {
	state := conn.ConnectionState()

	var details []SSLDetail

	for _, v := range state.PeerCertificates {
		switch v.Version {
		case 3:
			details = append(details, SSLDetail{"Version", "TLS v1.2"})
		case 2:
			details = append(details, SSLDetail{"Version", "TLS v1.1"})
		case 1:
			details = append(details, SSLDetail{"Version", "TLS v1.0"})
		case 0:
			details = append(details, SSLDetail{"Version", "SSL v3"})
		}

		// Adding individual fields, which avoids making assumptions about their presence
		if v.Subject.CommonName != "" {
			details = append(details, SSLDetail{"CN", v.Subject.CommonName})
		}

		for _, ou := range v.Subject.OrganizationalUnit {
			details = append(details, SSLDetail{"OU", ou})
		}

		for _, org := range v.Subject.Organization {
			details = append(details, SSLDetail{"Org", org})
		}

		for _, loc := range v.Subject.Locality {
			details = append(details, SSLDetail{"City", loc})
		}

		for _, prov := range v.Subject.Province {
			details = append(details, SSLDetail{"State", prov})
		}

		for _, country := range v.Subject.Country {
			details = append(details, SSLDetail{"Country", country})
		}

		details = append(details, SSLDetail{"Valid From", v.NotBefore.String()})
		details = append(details, SSLDetail{"Valid To", v.NotAfter.String()})

		for _, dnsName := range v.DNSNames {
			details = append(details, SSLDetail{"DNS Name", dnsName})
		}
	}

	return details
}

func CheckCertificateValidity(conn *tls.Conn, days int) bool {
	state := conn.ConnectionState()

	now := time.Now()
	for _, cert := range state.PeerCertificates {
		if now.After(cert.NotBefore) && now.AddDate(0, 0, days).Before(cert.NotAfter) {
			continue
		} else {
			return false
		}
	}

	return true
}

func (s *SSLChecker) CheckSSL(info SSLInfo) (CertInfo, error) {
	var result CertInfo

	target, domainName, err := ParseInput(info)
	if err != nil {
		s.Logger.Error("Failed to check SSL for: %v", info.DomainName)
		return result, err
	}

	conn, err := ConnectToServer(target, domainName)
	if err != nil {
		return result, err
	}
	defer conn.Close()

	isValidForDays := CheckCertificateValidity(conn, 10)
	if !isValidForDays {
		return result, fmt.Errorf("certificate(s) not valid for at least 10 days")
	}

	result.Details = CertDetails(conn)

	return result, nil
}
