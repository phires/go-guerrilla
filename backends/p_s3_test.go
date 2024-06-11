package backends

import (
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	"github.com/phires/go-guerrilla/log"
	"github.com/phires/go-guerrilla/mail"
)

// TestS3 is a unit test function for testing the S3 backend.
//
// It creates a new envelope with a recipient address and writes some data to it.
// It then creates a logger and a new backend using the S3 configuration.
// It starts the backend and processes the envelope through it.
// It checks if the result of the processing is as expected.
// It checks if the log file exists and reads its contents.
// Finally, it removes the log file.
//
// Parameters:
// - t: a testing.T object for running the test and reporting errors.
//
// Return type: None.
func TestS3(t *testing.T) {

	// fake s3
	backend := s3mem.New()
	faker := gofakes3.New(backend)
	ts := httptest.NewServer(faker.Server())
	defer ts.Close()

	url, err := url.Parse(ts.URL)
	if err != nil {
		t.Error(err)
		return
	}
	host := url.Host

	e := mail.NewEnvelope("127.0.0.1", 1)
	e.RcptTo = append(e.RcptTo, mail.Address{User: "test", Host: "grr.la"})
	e.Data.WriteString("Subject: Test\n\nThis is a test nbnb nbnb hgghgh nnnbnb nbnbnb nbnbn.")

	l, _ := log.GetLogger("./test_s3.log", "debug")
	g, err := New(BackendConfig{
		"save_process":         "Hasher|S3",
		"s3_endpoint":          host,
		"s3_bucket_name":       "guerrillamail",
		"s3_region":            "",
		"s3_use_tls":           false,
		"s3_access_key_id":     "ACCESSKEY",
		"s3_secret_access_key": "SECRETKEY",
	}, l)
	if err != nil {
		t.Error(err)
		return
	}
	err = g.Start()
	if err != nil {
		t.Error(err)
		return
	}
	defer func() {
		err := g.Shutdown()
		if err != nil {
			t.Error(err)
		}
	}()
	if gateway, ok := g.(*BackendGateway); ok {
		r := gateway.Process(e)
		if !strings.Contains(r.String(), "250 2.0.0 OK") {
			t.Error("S3 processor didn't result with expected result, it said", r)
		}
	}
	// check the log
	if _, err := os.Stat("./test_s3.log"); err != nil {
		t.Error(err)
		return
	}
	if b, err := os.ReadFile("./test_s3.log"); err != nil {
		t.Error(err)
		return
	} else {
		if !strings.Contains(string(b), "successfully uploaded") {
			t.Error("Log did not contain 'successfully uploaded', the log was: ", string(b))
		}
	}

	if err := os.Remove("./test_s3.log"); err != nil {
		t.Error(err)
	}

}
