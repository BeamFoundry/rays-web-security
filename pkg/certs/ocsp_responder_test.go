// This file is based on code from github.com/grimm-co/GOCSP-responder.
// Original Copyright (c) 2016 SMFS Inc. DBA GRIMM https://grimm-co.com
//
// Licensed under the MIT License.
package certs_test

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/gomega"
	"golang.org/x/crypto/ocsp"
)

const (
	StatusValid   = 'V'
	StatusRevoked = 'R'
	StatusExpired = 'E'
)

type OCSPConfig struct {
	IndexFile    string
	RespKeyFile  string
	RespCertFile string
	CaCertFile   string
	Strict       bool
}

type OCSPResponder struct {
	config             *OCSPConfig
	caCert             *x509.Certificate
	respCert           *x509.Certificate
	NextUpdateOverride *time.Time
	ThisUpdateOverride *time.Time
	indexModTime       time.Time
	indexEntries       []IndexEntry
}

type IndexEntry struct {
	Serial            *big.Int
	IssueTime         time.Time
	RevocationTime    time.Time
	DistinguishedName string
	Status            byte
}

func NewOCSPResponder() (*OCSPResponder, error) {
	config := &OCSPConfig{
		IndexFile:    "testdata/pki/intermediate/index.txt",
		RespKeyFile:  "testdata/pki/intermediate/ocsp/key.pem",
		RespCertFile: "testdata/pki/intermediate/ocsp/cert.pem",
		CaCertFile:   "testdata/pki/intermediate/cacert.pem",
		Strict:       true,
	}
	cacert, err := parseCertFile(config.CaCertFile)
	if err != nil {
		return nil, err
	}
	respcert, err := parseCertFile(config.RespCertFile)
	if err != nil {
		return nil, err
	}

	o := &OCSPResponder{
		config:       config,
		indexModTime: time.Time{},
		caCert:       cacert,
		respCert:     respcert,
	}

	return o, nil
}

func (o *OCSPResponder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if o.config.Strict && r.Header.Get("Content-Type") != "application/ocsp-request" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	resp, err := o.Verify(body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/ocsp-response")
	w.WriteHeader(http.StatusOK)
	_, writeErr := w.Write(resp)
	Expect(writeErr).NotTo(HaveOccurred())
}

func (o *OCSPResponder) Verify(rawreq []byte) ([]byte, error) {
	var status int
	var revokedAt time.Time

	req, err := ocsp.ParseRequest(rawreq)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	if verifyErr := o.verifyIssuer(req); verifyErr != nil {
		return nil, verifyErr
	}

	ent, err := o.getIndexEntry(req.SerialNumber)
	if err != nil {
		status = ocsp.Unknown
	} else {
		switch ent.Status {
		case StatusRevoked:
			status = ocsp.Revoked
			revokedAt = ent.RevocationTime
		case StatusValid:
			status = ocsp.Good
		default:
		}
	}

	keyi, err := parseKeyFile(o.config.RespKeyFile)
	if err != nil {
		return nil, err
	}
	key, ok := keyi.(crypto.Signer)
	if !ok {
		return nil, errors.New("tls: Could not make key a signer")
	}

	thisUpdate := time.Now().Add(-1 * time.Hour).UTC()
	if o.ThisUpdateOverride != nil {
		thisUpdate = *o.ThisUpdateOverride
	}

	nextUpdate := time.Now().Add(24 * time.Hour).UTC()
	if o.NextUpdateOverride != nil {
		nextUpdate = *o.NextUpdateOverride
	}

	template := ocsp.Response{
		Status:           status,
		SerialNumber:     req.SerialNumber,
		Certificate:      o.respCert,
		RevocationReason: ocsp.Unspecified,
		IssuerHash:       req.HashAlgorithm,
		RevokedAt:        revokedAt,
		ThisUpdate:       thisUpdate,
		NextUpdate:       nextUpdate,
	}

	resp, err := ocsp.CreateResponse(o.caCert, o.respCert, template, key)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return resp, nil
}

func (o *OCSPResponder) verifyIssuer(req *ocsp.Request) error {
	h := req.HashAlgorithm.New()
	if _, err := h.Write(o.caCert.RawSubject); err != nil {
		return fmt.Errorf("%w", err)
	}
	if !bytes.Equal(h.Sum(nil), req.IssuerNameHash) {
		return errors.New("tls: Issuer name does not match")
	}
	h.Reset()
	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(o.caCert.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		return fmt.Errorf("%w", err)
	}
	if _, err := h.Write(publicKeyInfo.PublicKey.RightAlign()); err != nil {
		return fmt.Errorf("%w", err)
	}
	if !bytes.Equal(h.Sum(nil), req.IssuerKeyHash) {
		return errors.New("tls: Issuer key hash does not match")
	}
	return nil
}

func (o *OCSPResponder) parseIndex() error {
	t := "060102150405Z"
	finfo, err := os.Stat(o.config.IndexFile)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	if !finfo.ModTime().After(o.indexModTime) {
		return nil
	}

	o.indexModTime = finfo.ModTime()
	o.indexEntries = o.indexEntries[:0]

	file, err := os.Open(o.config.IndexFile)
	if err != nil {
		return fmt.Errorf("%w", err)
	}
	defer func() {
		closeErr := file.Close()
		Expect(closeErr).NotTo(HaveOccurred())
	}()

	s := bufio.NewScanner(file)
	for s.Scan() {
		var ie IndexEntry
		ln := strings.Fields(s.Text())
		ie.Status = []byte(ln[0])[0]
		issueTime, parseErr := time.Parse(t, ln[1])
		Expect(parseErr).NotTo(HaveOccurred())
		ie.IssueTime = issueTime
		switch ie.Status {
		case StatusValid:
			ie.Serial, _ = new(big.Int).SetString(ln[2], 16)
			ie.DistinguishedName = ln[4]
			ie.RevocationTime = time.Time{}
		case StatusRevoked:
			ie.Serial, _ = new(big.Int).SetString(ln[3], 16)
			ie.DistinguishedName = ln[5]
			revTime, parseErr := time.Parse(t, ln[2])
			Expect(parseErr).NotTo(HaveOccurred())
			ie.RevocationTime = revTime
		default:
			continue
		}
		o.indexEntries = append(o.indexEntries, ie)
	}
	return nil
}

func (o *OCSPResponder) getIndexEntry(s *big.Int) (*IndexEntry, error) {
	if err := o.parseIndex(); err != nil {
		return nil, err
	}
	for _, entry := range o.indexEntries {
		if entry.Serial.Cmp(s) == 0 {
			return &entry, nil
		}
	}
	return nil, fmt.Errorf("tls: Serial 0x%x not found", s)
}

func parseCertFile(filename string) (*x509.Certificate, error) {
	ct, err := os.ReadFile(filepath.Clean(filename))
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	block, _ := pem.Decode(ct)
	if block == nil {
		return nil, errors.New("tls: invalid PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	return cert, nil
}

func parseKeyFile(filename string) (any, error) {
	kt, err := os.ReadFile(filepath.Clean(filename))
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	block, _ := pem.Decode(kt)
	if block == nil {
		return nil, errors.New("tls: invalid PEM key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	return key, nil
}

func startOCSPResponder(responder *OCSPResponder) (addr string, cleanup func()) {
	ts := httptest.NewServer(responder)
	return ts.Listener.Addr().String(), ts.Close
}
