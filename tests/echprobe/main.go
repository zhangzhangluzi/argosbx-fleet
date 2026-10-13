// ECH acceptance observer. Uses native TLS/QUIC and the server's Salamander library.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	quic "github.com/sagernet/quic-go"
	hy2 "github.com/sagernet/sing-quic/hysteria2"
)

type Case struct {
	Name, Address, ServerName, Config, QueryName, ObfsPassword, Network string
	ALPN                                                                []string
}
type Result struct {
	Name     string `json:"name"`
	Accepted bool   `json:"ech_accepted"`
	Verified bool   `json:"certificate_verified"`
	Version  uint16 `json:"tls_version,omitempty"`
	Error    string `json:"error,omitempty"`
}

func query(ctx context.Context, name string, qtype uint16) ([]dns.RR, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.Id = 0
	b, e := m.Pack()
	if e != nil {
		return nil, e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", "https://dns.alidns.com/dns-query", bytes.NewReader(b))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	client := http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}}
	res, e := client.Do(req)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("DoH status %d", res.StatusCode)
	}
	b, e = io.ReadAll(io.LimitReader(res.Body, 65536))
	if e != nil {
		return nil, e
	}
	answer := new(dns.Msg)
	if e = answer.Unpack(b); e != nil {
		return nil, e
	}
	return answer.Answer, nil
}
func check(c Case) (r Result) {
	r.Name = c.Name
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
	defer cancel()
	fail := func(e error) Result { r.Error = e.Error(); return r }
	config, e := base64.StdEncoding.DecodeString(c.Config)
	if e != nil {
		return fail(e)
	}
	if c.QueryName != "" {
		records, e := query(ctx, c.QueryName, dns.TypeHTTPS)
		if e != nil {
			return fail(e)
		}
		for _, rr := range records {
			if h, ok := rr.(*dns.HTTPS); ok {
				for _, v := range h.Value {
					if v, ok := v.(*dns.SVCBECHConfig); ok {
						config = v.ECH
					}
				}
			}
		}
	}
	if len(config) == 0 {
		return fail(fmt.Errorf("ECH config missing"))
	}
	host, port, e := net.SplitHostPort(c.Address)
	if e != nil {
		return fail(e)
	}
	if net.ParseIP(host) == nil {
		records, e := query(ctx, host, dns.TypeA)
		if e != nil {
			return fail(e)
		}
		for _, rr := range records {
			if a, ok := rr.(*dns.A); ok {
				host = a.A.String()
				break
			}
		}
		if net.ParseIP(host) == nil {
			return fail(fmt.Errorf("no IPv4 address"))
		}
	}
	address := net.JoinHostPort(host, port)
	tc := &tls.Config{ServerName: c.ServerName, MinVersion: tls.VersionTLS13, EncryptedClientHelloConfigList: config, NextProtos: c.ALPN}
	var state tls.ConnectionState
	if c.Network == "udp" {
		if len(tc.NextProtos) == 0 {
			tc.NextProtos = []string{"h3"}
		}
		family, bind := "udp4", "0.0.0.0:0"
		if strings.Contains(host, ":") {
			family, bind = "udp6", "[::]:0"
		}
		pc, e := net.ListenPacket(family, bind)
		if e != nil {
			return fail(e)
		}
		defer pc.Close()
		if c.ObfsPassword != "" {
			// Hide the raw socket fast path: its vector writer assumes a dual-stack
			// socket, while this observer deliberately binds the selected IP family.
			pc = hy2.NewSalamanderConn(struct{ net.PacketConn }{pc}, []byte(c.ObfsPassword))
		}
		addr, e := net.ResolveUDPAddr(family, address)
		if e != nil {
			return fail(e)
		}
		conn, e := quic.Dial(ctx, pc, addr, tc, &quic.Config{HandshakeIdleTimeout: 10 * time.Second})
		if e != nil {
			return fail(e)
		}
		state = conn.ConnectionState().TLS
		conn.CloseWithError(0, "")
	} else {
		d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 12 * time.Second}, Config: tc}
		raw, e := d.DialContext(ctx, "tcp", address)
		if e != nil {
			return fail(e)
		}
		conn := raw.(*tls.Conn)
		state = conn.ConnectionState()
		conn.Close()
	}
	r.Accepted = state.ECHAccepted
	r.Verified = len(state.VerifiedChains) > 0
	r.Version = state.Version
	return r
}
func main() {
	var cases []Case
	if e := json.NewDecoder(os.Stdin).Decode(&cases); e != nil {
		fmt.Fprintln(os.Stderr, "invalid input")
		os.Exit(2)
	}
	out := make([]Result, len(cases))
	var wg sync.WaitGroup
	limit := make(chan struct{}, 3)
	for i, c := range cases {
		wg.Add(1)
		go func(i int, c Case) {
			defer wg.Done()
			limit <- struct{}{}
			defer func() { <-limit }()
			out[i] = check(c)
		}(i, c)
	}
	wg.Wait()
	json.NewEncoder(os.Stdout).Encode(out)
}
