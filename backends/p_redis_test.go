package backends

import (
	"os"
	"strings"
	"testing"

	"github.com/phires/go-guerrilla/log"
	"github.com/phires/go-guerrilla/mail"
)

func TestRedisGeneric(t *testing.T) {

	e := mail.NewEnvelope("127.0.0.1", 1)
	e.RcptTo = append(e.RcptTo, mail.Address{User: "test", Host: "grr.la"})

	l, _ := log.GetLogger("./test_redis.log", "debug")
	g, err := New(BackendConfig{
		"save_process":         "Hasher|Redis",
		"redis_interface":      "127.0.0.1:6379",
		"redis_expire_seconds": 7200,
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
			t.Error("redis processor didn't result with expected result, it said", r)
		}
	}
	// check the log
	if _, err := os.Stat("./test_redis.log"); err != nil {
		t.Error(err)
		return
	}
	if b, err := os.ReadFile("./test_redis.log"); err != nil {
		t.Error(err)
		return
	} else {
		if !strings.Contains(string(b), "SETEX") {
			t.Error("Log did not contain SETEX, the log was: ", string(b))
		}
	}

	if err := l.Close(); err != nil {
		t.Error(err)
		return
	}

	if err := os.Remove("./test_redis.log"); err != nil {
		t.Error(err)
	}

}
