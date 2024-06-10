package backends

import (
	"os"
	"strings"
	"testing"

	"github.com/phires/go-guerrilla/log"
	"github.com/phires/go-guerrilla/mail"
)

func TestS3(t *testing.T) {

	e := mail.NewEnvelope("127.0.0.1", 1)
	e.RcptTo = append(e.RcptTo, mail.Address{User: "test", Host: "grr.la"})

	l, _ := log.GetLogger("./test_s3.log", "debug")
	g, err := New(BackendConfig{
		"save_process":         "Hasher|S3",
		"s3_endpoint":          "storage.googleapis.com",
		"s3_bucket_name":       "guerrillamail",
		"s3_region":            "",
		"s3_use_tls":           true,
		"s3_access_key_id":     "",
		"s3_secret_access_key": "",
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
		if strings.Index(r.String(), "250 2.0.0 OK") == -1 {
			t.Error("S3 processor didn't result with expected result, it said", r)
		}
	}
	// check the log
	if _, err := os.Stat("./test_s3.log"); err != nil {
		t.Error(err)
		return
	}
	if _, err := os.ReadFile("./test_s3.log"); err != nil {
		t.Error(err)
		return
	}

	if err := os.Remove("./test_s3.log"); err != nil {
		t.Error(err)
	}

}
