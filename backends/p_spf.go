package backends

import (
	"net"

	"blitiri.com.ar/go/spf"
	"github.com/phires/go-guerrilla/mail"
)

func init() {
	processors["spf"] = func() Decorator {
		return SPF()
	}
}

func SPF() Decorator {
	return func(p Processor) Processor {
		return ProcessWith(func(e *mail.Envelope, task SelectTask) (Result, error) {
			if task == TaskSaveMail {

				res, err := spf.CheckHostWithSender(net.ParseIP(e.RemoteIP), e.MailFrom.Host, e.MailFrom.String())
				Log().Infoln("SPF debug", err)

				if res == spf.Fail {
					Log().Errorf("SPF result=%s", res)
					return NewResult("556 5.7.0 Unauthorized sender. Email blocked due to policy reasons."), SpfError
				}

				// next processor
				return p.Process(e, task)
			} else {
				// next processor
				return p.Process(e, task)
			}
		})
	}
}
