package backends

import (
	"github.com/phires/go-guerrilla/mail"
)

// ----------------------------------------------------------------------------------
// Processor Name: contentparser
// ----------------------------------------------------------------------------------
// Description   : Parses and decodes the content
// ----------------------------------------------------------------------------------
// Config Options: none
// --------------:-------------------------------------------------------------------
// Input         : envelope
// ----------------------------------------------------------------------------------
// Output        : Content will be populated in e.EnvelopeBody
// ----------------------------------------------------------------------------------
func init() {
	processors["contentparser"] = func() Decorator {
		return ContentParser()
	}
}

func ContentParser() Decorator {


	return func(p Processor) Processor {
		return ProcessWith(func(e *mail.Envelope, task SelectTask) (Result, error) {
			if task == TaskSaveMail {
				if err := e.ParseContent(); err != nil {
					Log().WithError(err).Error("parse content error")
				} else {
					Log().Info("Parsed Content is: ", e.EnvelopeBody)
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

