package backends

import (
	"github.com/phires/go-guerrilla/mail"
)

// ----------------------------------------------------------------------------------
// Processor Name: headersparser
// ----------------------------------------------------------------------------------
// Description   : Parses the header using e.ParseHeaders()
// ----------------------------------------------------------------------------------
// Config Options: none
// --------------:-------------------------------------------------------------------
// Input         : envelope
// ----------------------------------------------------------------------------------
// Output        : Headers will be populated in e.Header
// ----------------------------------------------------------------------------------
func init() {
	processors["headersparser"] = func() Decorator {
		return HeadersParser()
	}
}

func HeadersParser() Decorator {
	return func(p Processor) Processor {
		return ProcessWith(func(e *mail.Envelope, task SelectTask) (Result, error) {
			switch task {
			case TaskSaveMail, TaskTest:
				if err := e.ParseHeaders(); err != nil {
					Log().WithError(err).Error("parse headers error")
				}
			}
			return p.Process(e, task)
		})
	}
}
