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

type SSLChecker struct {
	Logger *logmodule.Logger
}

type CertInfo struct {
	IsValid bool
	Details string // This could be a struct with specific fields, but for simplicity, I'm using a string
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

func CertDetails(conn *tls.Conn) {
	state := conn.ConnectionState()
	for i, v := range state.PeerCertificates {
		switch i {
		case 0:
			fmt.Printf("Server key information:")
			switch v.Version {
			case 3:
				fmt.Printf("\tVersion: TLS v1.2\n")
			case 2:
				fmt.Printf("\tVersion: TLS v1.1\n")
			case 1:
				fmt.Printf("\tVersion: TLS v1.0\n")
			case 0:
				fmt.Printf("\tVersion: SSL v3\n")
			}
			fmt.Printf("\tCN:\t %v\n\tOU:\t %v\n\tOrg:\t %v\n", v.Subject.CommonName, v.Subject.OrganizationalUnit, v.Subject.Organization)
			fmt.Printf("\tCity:\t %v\n\tState:\t %v\n\tCountry: %v\n", v.Subject.Locality, v.Subject.Province, v.Subject.Country)
			fmt.Printf("SSL Certificate Valid:\n\tFrom:\t %v\n\tTo:\t %v\n", v.NotBefore, v.NotAfter)
			fmt.Printf("Valid Certificate DNS:\n")
			if len(v.DNSNames) >= 1 {
				for dns := range v.DNSNames {
					fmt.Printf("\t%v\n", v.DNSNames[dns])
				}
			} else {
				fmt.Printf("\t%v\n", v.Subject.CommonName)
			}
		case 1:
			fmt.Printf("Issued by:\n\t%v\n\t%v\n\t%v\n", v.Subject.CommonName, v.Subject.OrganizationalUnit, v.Subject.Organization)
		}
	}
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

	CertDetails(conn)

	return result, nil
}
