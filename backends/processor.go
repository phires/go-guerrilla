package backends

import (
	"github.com/phires/go-guerrilla/mail"
)

type SelectTask int

const (
	TaskSaveMail SelectTask = iota
	TaskValidateRcpt
	TaskSecurityChecks
	TaskTest
)

func (o SelectTask) String() string {
	switch o {
	case TaskSaveMail:
		return "save mail"
	case TaskValidateRcpt:
		return "validate recipient"
	case TaskSecurityChecks:
		return "check security"
	case TaskTest:
		return "test"
	}
	return "[unnamed task]"
}

var BackendResultOK = NewResult("200 OK")

// Our processor is defined as something that processes the envelope and returns a result and error
type Processor interface {
	Process(*mail.Envelope, SelectTask) (Result, error)
}

// Signature of Processor
type ProcessWith func(*mail.Envelope, SelectTask) (Result, error)

// Make ProcessWith will satisfy the Processor interface
func (f ProcessWith) Process(e *mail.Envelope, task SelectTask) (Result, error) {
	// delegate to the anonymous function
	return f(e, task)
}

// DefaultProcessor is a undecorated worker that does nothing
// Notice DefaultProcessor has no knowledge of the other decorators that have orthogonal concerns.
type DefaultProcessor struct{}

// do nothing except return the result
// (this is the last call in the decorator stack, if it got here, then all is good)
func (w DefaultProcessor) Process(e *mail.Envelope, task SelectTask) (Result, error) {
	return BackendResultOK, nil
}

// if no processors specified, skip operation
type NoopProcessor struct{ DefaultProcessor }
