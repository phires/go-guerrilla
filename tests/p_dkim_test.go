package test

import (
	"os"
	"strings"
	"testing"

	"github.com/phires/go-guerrilla/backends"
	"github.com/phires/go-guerrilla/log"
	"github.com/phires/go-guerrilla/mail"
)

const verifiedMailString = `DKIM-Signature: a=ed25519-sha256; bh=hfkNii+Z1I8AuAqwGcLOA6raVsIfm/K8PWWhoV6jopM=;
 c=simple/simple; d=pkarc.dev; h=From:To:Subject:Date:Message-ID; s=grrla;
 t=424242; v=1;
 b=Pvrtqdonu3vmjeNmw61R+/bBJ5lhtpmZPvDWKdzZ/srfIujuD3xtqLwEUtmVRPdPzl2kvKvO
 Vk3wQKP0p45gDA==
From: Ivan Jaramillo <ivan@pkarc.dev>
To: Phillipe Resch <phil@2kd.de>
Subject: Is dkim ready?
Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)
Message-ID: <20030712040037.46341.5F8J@pkarc.dev>

Hi.

DKIM is ready.

Pkarc.
`

func TestDKIM(t *testing.T) {

	e := mail.NewEnvelope("192.0.2.1", 1) //DNS spf ip record
	e.Data.WriteString(verifiedMailString)

	l, _ := log.GetLogger("./test_dkim.log", "debug")
	g, err := backends.New(backends.BackendConfig{
		"save_process":      "HeadersParser|DKIM",
		"primary_mail_host": "pkarc.dev",
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
	if gateway, ok := g.(*backends.BackendGateway); ok {
		r := gateway.Process(e)
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
