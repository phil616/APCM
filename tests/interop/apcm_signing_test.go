// Added to a temporary checkout of the pinned upstream source by the interop script.
package signing

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestAPCMNativeWindowsCsr(t *testing.T) {
	directory := os.Getenv("APCM_CSR_FIXTURE_DIR")
	if directory == "" {
		t.Fatal("APCM_CSR_FIXTURE_DIR is required; native CSR coverage must not be skipped")
	}
	input := testCA(t, nil)
	now := time.Now().UTC()
	ca, err := loadAuthority(input.CertificatePEM, input.PrivateKeyPEM, input.ChainPEM, now)
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{Version: 1, AllowedDNSNames: []string{"apcm-csr-smoke.example.test"},
		AllowedIPRanges: []string{"10.20.0.0/16"}, AllowedEmailDomains: []string{"example.test"},
		AllowedURIPrefixes: []string{"spiffe://example.test/workloads/"},
		ExtendedKeyUsages:  []string{"server_auth", "client_auth"}, DefaultValiditySeconds: 3600, MaxValiditySeconds: 7200, MaxSANs: 4}
	if err := policy.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ECDSA-P256", "ECDSA-P384", "RSA-2048", "RSA-3072", "RSA-4096"} {
		t.Run(name, func(t *testing.T) {
			requestPEM, err := os.ReadFile(filepath.Join(directory, name+".csr"))
			if err != nil {
				t.Fatal(err)
			}
			csr, err := parseCSR(string(requestPEM)) // The actual production parser, including signature and extension checks.
			if err != nil {
				t.Fatalf("native Windows CSR rejected: %v", err)
			}
			if err := validateRequest(csr, policy); err != nil {
				t.Fatal(err)
			}
			if len(csr.Extensions) != 1 || csr.Extensions[0].Id.String() != "2.5.29.17" {
				t.Fatal("unexpected CSR extensions")
			}
			if !slices.Equal(csr.Subject.Organization, []string{"APCM 互操作测试"}) || csr.Subject.CommonName != "apcm-csr-smoke.example.test" || len(csr.DNSNames) != 1 || len(csr.IPAddresses) != 1 || len(csr.EmailAddresses) != 1 || len(csr.URIs) != 1 {
				t.Fatal("CSR identities changed")
			}
			body, err := os.ReadFile(filepath.Join(directory, name+".request.json"))
			if err != nil {
				t.Fatal(err)
			}
			var submitted IssueInput
			if err := json.Unmarshal(body, &submitted); err != nil {
				t.Fatal(err)
			}
			if submitted.CSRPEM != string(requestPEM) || submitted.ValiditySeconds != 3600 {
				t.Fatal("wire CSR differs from native fixture")
			}
			issued, err := ca.issue(csr, "00000000-0000-4000-8000-000000000001", "https://pki.example.test", submitted.ValiditySeconds, policy.ExtendedKeyUsages, now)
			if err != nil {
				t.Fatalf("production issuer rejected native CSR: %v", err)
			}
			block, _ := pem.Decode([]byte(issued.CertificatePEM))
			if block == nil {
				t.Fatal("issuer returned no certificate")
			}
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			requested, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			received, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(requested, received) {
				t.Fatal("issued certificate public key changed")
			}
			if !slices.Equal(leaf.DNSNames, csr.DNSNames) || !slices.Equal(leaf.EmailAddresses, csr.EmailAddresses) {
				t.Fatal("issued identities changed")
			}
			if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) || !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
				t.Fatal("server policy usages missing")
			}
			if err := ca.verify(leaf, now, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}); err != nil {
				t.Fatal(err)
			}
			// Confirm that the original Windows NEW wrapper really is rejected by the upstream wire protocol.
			legacy := strings.ReplaceAll(string(requestPEM), "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST")
			if _, err := parseCSR(legacy); err == nil {
				t.Fatal("legacy envelope unexpectedly accepted by server")
			}
		})
	}
}
