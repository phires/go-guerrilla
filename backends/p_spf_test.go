package backends

import (
	"os"
	"strings"
	"testing"

	"github.com/phires/go-guerrilla/log"
	"github.com/phires/go-guerrilla/mail"
)

func TestSpf(t *testing.T) {

	e := mail.NewEnvelope("168.119.142.36", 1) //DNS spf ip record
	e.MailFrom = mail.Address{User: "test", Host: "guerrillamail.com"}
	e.Data.WriteString("Subject: Test\n\nThis is a test nbnb nbnb hgghgh nnnbnb nbnbnb nbnbn.")

	l, _ := log.GetLogger("./test_spf.log", "debug")
	g, err := New(BackendConfig{
		"save_process": "SPF",
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
		r := gateway.Process(e, TaskSaveMail)
		if !strings.Contains(r.String(), "250 2.0.0 OK") {
			t.Error("spf processor didn't result with expected result, it said", r)
		}
	}
	// check the log
	if _, err := os.Stat("./test_spf.log"); err != nil {
		t.Error(err)
		return
	}
	if b, err := os.ReadFile("./test_spf.log"); err != nil {
		t.Error(err)
		return
	} else if !strings.Contains(string(b), "SPF pass") {
		t.Error("Log did not contain 'successfully uploaded', the log was: ", string(b))
		return
	}

	return

	if err := l.Close(); err != nil {
		t.Error(err)
		return
	}

	if err := os.Remove("./test_spf.log"); err != nil {
		t.Error(err)
		return
	}

}
