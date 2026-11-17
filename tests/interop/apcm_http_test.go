// Copied into console/httpapi so the tests exercise its actual strict JSON decoder.
package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/cfssl/console/signing"
)

func TestAPCMNativeIssueWireBody(t *testing.T) {
	directory := os.Getenv("APCM_CSR_FIXTURE_DIR")
	if directory == "" {
		t.Fatal("native CSR fixtures are required")
	}
	for _, name := range []string{"ECDSA-P256", "ECDSA-P384", "RSA-2048", "RSA-3072", "RSA-4096"} {
		t.Run(name, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(directory, name+".request.json"))
			if err != nil {
				t.Fatal(err)
			}
			csr, err := os.ReadFile(filepath.Join(directory, name+".csr"))
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodPost, "https://pki.example.test/signing/00000000-0000-4000-8000-000000000001/issue", bytes.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Idempotency-Key", "apcm-native-csr-fixture")
			recorder := httptest.NewRecorder()
			var input signing.IssueInput
			raw, ok := decodeSigningJSON(recorder, r, &input)
			if !ok {
				t.Fatalf("production HTTP decoder rejected request: %d %s", recorder.Code, recorder.Body.String())
			}
			if !bytes.Equal(raw, body) || input.CSRPEM != string(csr) || input.ValiditySeconds != 3600 {
				t.Fatal("HTTP decoder changed original request bytes or fields")
			}
		})
	}
}
