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
			switch task {
			case TaskSaveMail, TaskTest:
				res, err := spf.CheckHostWithSender(net.ParseIP(e.RemoteIP), e.MailFrom.Host, e.MailFrom.String())
				if err != nil {
					Log().WithError(err).Error("SPF error: ", err)
				}
				if res == spf.Fail {
					Log().Debugln("SPF fail result:", res)
					return NewResult("556 5.7.0 Unauthorized sender. Email blocked due to policy reasons."), SpfError
				}
				Log().Debugln("SPF pass result:", res)
			}
			// next processor
			return p.Process(e, task)
		})
	}
}
