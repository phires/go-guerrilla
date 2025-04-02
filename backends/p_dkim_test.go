package backends

import (
	"os"
	"strings"
	"testing"

	"github.com/phires/go-guerrilla/log"
	"github.com/phires/go-guerrilla/mail"
)

const verifiedMailString = `DKIM-Signature: a=ed25519-sha256; bh=hfkNii+Z1I8AuAqwGcLOA6raVsIfm/K8PWWhoV6jopM=;
 c=simple/simple; d=example.com; h=From:To:Subject:Date:Message-ID;
 s=grrla; t=424242; v=1;
 b=7FJvQ6xDPl9je9besXRXtZMSvRFnyw0zwfplfa+9gPcQ54r6GH/tlJECkW5f0DaKbXUm91d9
 wCYumq0YEDxMBg==
From: Pkarc <pkarc@example.com>
To: phires <phires@example.com>
Subject: Is dkim ready?
Date: Mon, 4 Nov 2024 21:00:37 -0500 (PDT)
Message-ID: <20030712040037.46341.5F8J@example.com>

Hi.

DKIM is ready.

Pkarc.
`

func TestDKIM(t *testing.T) {

	e := mail.NewEnvelope("192.0.2.1", 1) //DNS spf ip record
	e.Data.WriteString(verifiedMailString)

	l, _ := log.GetLogger("./test_dkim.log", "debug")
	g, err := New(BackendConfig{
		"save_process":      "HeadersParser|DKIM",
		"primary_mail_host": "example.com",
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
		r := gateway.Process(e, TaskTest)
		if !strings.Contains(r.String(), "250 2.0.0 OK") {
			t.Error("DKIM processor didn't result with expected result, it said", r)
		}
	}
	// check the log
	if _, err := os.Stat("./test_dkim.log"); err != nil {
		t.Error(err)
		return
	}
	if b, err := os.ReadFile("./test_dkim.log"); err != nil {
		t.Error(err)
		return
	} else if !strings.Contains(string(b), "DKIM Valid signature") {
		t.Error("Log did not contain 'DKIM Valid signature', the log was: ", string(b))
		return
	}

	if err := l.Close(); err != nil {
		t.Error(err)
		return
	}

	if err := os.Remove("./test_dkim.log"); err != nil {
		t.Error(err)
		return
	}

}
