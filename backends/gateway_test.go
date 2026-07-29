package backends

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phires/go-guerrilla/log"
	"github.com/phires/go-guerrilla/mail"
)

func TestStates(t *testing.T) {
	gw := BackendGateway{}
	str := gw.State.String()
	if strings.Index(str, "NewState") != 0 {
		t.Error("Backend should begin in NewState")
	}
}

func TestInitialize(t *testing.T) {
	c := BackendConfig{
		"save_process":       "HeadersParser|Debugger",
		"log_received_mails": true,
		"save_workers_size":  "1",
	}

	gateway := &BackendGateway{}
	err := gateway.Initialize(c)
	if err != nil {
		t.Error("Gateway did not init because:", err)
		t.Fail()
	}
	if gateway.processors == nil {
		t.Error("gateway.chains should not be nil")
	} else if len(gateway.processors) != 1 {
		t.Error("len(gateway.chains) should be 1, but got", len(gateway.processors))
	}

	if gateway.conveyor == nil {
		t.Error("gateway.conveyor should not be nil")
	} else if cap(gateway.conveyor) != gateway.workersSize() {
		t.Error("gateway.conveyor channel buffer cap does not match worker size, cap was", cap(gateway.conveyor))
	}

	if gateway.GetState() != BackendStateInitialized {
		t.Error("gateway state is not in initialized state, got ", gateway.GetState())
	}

}

func TestStartProcessStop(t *testing.T) {
	c := BackendConfig{
		"save_process":       "HeadersParser|Debugger",
		"log_received_mails": true,
		"save_workers_size":  2,
	}

	gateway := &BackendGateway{}
	err := gateway.Initialize(c)

	mainlog, _ := log.GetLogger(log.OutputOff.String(), "debug")
	Svc.SetMainlog(mainlog)

	if err != nil {
		t.Error("Gateway did not init because:", err)
		t.Fail()
	}
	err = gateway.Start()
	if err != nil {
		t.Error("Gateway did not start because:", err)
		t.Fail()
	}
	if gateway.GetState() != BackendStateRunning {
		t.Error("gateway state is not in running state, got ", gateway.GetState())
	}
	// can we place an envelope on the conveyor channel?

	e := &mail.Envelope{
		RemoteIP: "127.0.0.1",
		QueuedId: "abc12345",
		Helo:     "helo.example.com",
		MailFrom: mail.Address{User: "test", Host: "example.com"},
		TLS:      true,
	}
	e.PushRcpt(mail.Address{User: "test", Host: "example.com"})
	e.Data.WriteString("Subject:Test\n\nThis is a test.")
	notify := make(chan *notifyMsg)

	gateway.conveyor <- &workerMsg{e, notify, TaskSaveMail}

	// it should not produce any errors
	// headers (subject) should be parsed.

	select {
	case status := <-notify:

		if status.err != nil {
			t.Error("envelope processing failed with:", status.err)
		}
		if e.Header["Subject"][0] != "Test" {
			t.Error("envelope processing did not parse header")
		}

	case <-time.After(time.Second):
		t.Error("gateway did not respond after 1 second")
		t.Fail()
	}

	err = gateway.Shutdown()
	if err != nil {
		t.Error("Gateway did not shutdown")
	}
}

// testEnvelope builds a minimal envelope that the gateway will accept
func testEnvelope() *mail.Envelope {
	e := &mail.Envelope{
		RemoteIP: "127.0.0.1",
		QueuedId: "abc12345",
		Helo:     "helo.example.com",
		MailFrom: mail.Address{User: "test", Host: "example.com"},
	}
	e.PushRcpt(mail.Address{User: "test", Host: "example.com"})
	e.Data.WriteString("Subject:Test\n\nThis is a test.")
	return e
}

// TestGatewayEnqueueTimeout covers H5: the save timeout only ever guarded the
// select that waits for the *answer*, never the send onto the conveyor. The
// conveyor is buffered with workersSize (1 by default), so as soon as a worker
// gets stuck any number of connection goroutines pile up on that send with no
// timeout at all - each of them holding a client and a pool slot.
func TestGatewayEnqueueTimeout(t *testing.T) {
	// a processor that blocks until the test lets it go
	release := make(chan struct{})
	entered := make(chan struct{}, 8)
	Svc.AddProcessor("TestBlocker", func() Decorator {
		return func(p Processor) Processor {
			return ProcessWith(func(e *mail.Envelope, task SelectTask) (Result, error) {
				entered <- struct{}{}
				<-release
				return p.Process(e, task)
			})
		}
	})

	c := BackendConfig{
		"save_process":      "TestBlocker",
		"save_workers_size": 1,
		"gw_save_timeout":   "500ms",
	}
	mainlog, _ := log.GetLogger(log.OutputOff.String(), "info")
	Svc.SetMainlog(mainlog)

	gateway := &BackendGateway{}
	if err := gateway.Initialize(c); err != nil {
		t.Fatal("gateway did not init because:", err)
	}
	if err := gateway.Start(); err != nil {
		t.Fatal("gateway did not start because:", err)
	}
	defer func() {
		close(release) // let the stuck worker finish, so that Shutdown can return
		if err := gateway.Shutdown(); err != nil {
			t.Error("gateway did not shutdown because:", err)
		}
	}()

	// the only worker picks this one up and gets stuck in the processor
	if res := gateway.Process(testEnvelope(), TaskSaveMail); res.Code() < 400 {
		t.Error("expected the first message to time out, got:", res)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("the worker never reached the processor")
	}
	// this one fits in the conveyor's buffer, nobody will pick it up
	if res := gateway.Process(testEnvelope(), TaskSaveMail); res.Code() < 400 {
		t.Error("expected the second message to time out, got:", res)
	}

	// The buffer is full and the worker is stuck, so this send has nowhere to go.
	// It has to give up on the save timeout instead of blocking forever.
	done := make(chan Result, 1)
	go func() {
		done <- gateway.Process(testEnvelope(), TaskSaveMail)
	}()
	select {
	case res := <-done:
		if res.Code() < 400 {
			t.Error("expected a failure result for the third message, got:", res)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Process blocked on the conveyor: the send onto the channel has no timeout")
	}
}

// TestGatewayEnqueueAfterShutdown covers H5: a Process call that races with
// Shutdown must not park on a conveyor that no worker reads any more. It used to
// leak the message, a drain goroutine and a locked envelope with it.
func TestGatewayEnqueueAfterShutdown(t *testing.T) {
	c := BackendConfig{
		"save_process":       "HeadersParser|Debugger",
		"log_received_mails": true,
		"save_workers_size":  1,
		"gw_save_timeout":    "30s", // long, so a hang would not be masked by a timeout
	}
	mainlog, _ := log.GetLogger(log.OutputOff.String(), "info")
	Svc.SetMainlog(mainlog)

	gateway := &BackendGateway{}
	if err := gateway.Initialize(c); err != nil {
		t.Fatal("gateway did not init because:", err)
	}
	if err := gateway.Start(); err != nil {
		t.Fatal("gateway did not start because:", err)
	}
	if err := gateway.Shutdown(); err != nil {
		t.Fatal("gateway did not shutdown because:", err)
	}
	// no workers left, but pretend the state check was passed just before the
	// shutdown landed - that is exactly the race the review describes
	gateway.setState(BackendStateRunning)

	done := make(chan Result, 1)
	go func() {
		done <- gateway.Process(testEnvelope(), TaskSaveMail)
	}()
	select {
	case res := <-done:
		if res.Code() < 400 {
			t.Error("expected a failure result after shutdown, got:", res)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Process parked on a conveyor that no worker reads any more")
	}
}

// TestGatewayShutdownDrainsConveyor covers H5: a message that made it into the
// conveyor's buffer just as the workers stopped has nobody left to pick it up.
// Its caller used to sit there for the full save timeout and leak a drain
// goroutine and a locked envelope on the way out. Shutdown has to answer it.
//
// The gateway is deliberately not started: with no worker reading the conveyor,
// a queued message is in exactly the situation the race produces.
func TestGatewayShutdownDrainsConveyor(t *testing.T) {
	c := BackendConfig{
		"save_process":       "HeadersParser|Debugger",
		"log_received_mails": true,
		"save_workers_size":  1,
	}
	mainlog, _ := log.GetLogger(log.OutputOff.String(), "info")
	Svc.SetMainlog(mainlog)

	gateway := &BackendGateway{}
	if err := gateway.Initialize(c); err != nil {
		t.Fatal("gateway did not init because:", err)
	}

	msg := &workerMsg{e: testEnvelope(), notifyMe: make(chan *notifyMsg), task: TaskSaveMail}
	gateway.conveyor <- msg
	answered := make(chan *notifyMsg, 1)
	go func() {
		answered <- <-msg.notifyMe
	}()

	if err := gateway.Shutdown(); err != nil {
		t.Fatal("gateway did not shutdown because:", err)
	}
	select {
	case n := <-answered:
		if n.err == nil {
			t.Error("expected the queued message to be answered with an error, got", n)
		}
	case <-time.After(3 * time.Second):
		t.Error("the queued message was never answered, its caller is left waiting " +
			"out the whole save timeout")
	}
}

// TestGatewayStateRace covers H1: the gateway's state is written under gw.Mutex
// by Initialize/Start/Shutdown, but Process and ValidateRcpt used to read it
// without holding the lock. Only meaningful when run with -race.
func TestGatewayStateRace(t *testing.T) {
	c := BackendConfig{
		"save_process":       "HeadersParser|Debugger",
		"log_received_mails": true,
		"save_workers_size":  1,
	}
	mainlog, _ := log.GetLogger(log.OutputOff.String(), "info")
	Svc.SetMainlog(mainlog)

	gateway := &BackendGateway{}
	if err := gateway.Initialize(c); err != nil {
		t.Fatal("gateway did not init because:", err)
	}
	if err := gateway.Start(); err != nil {
		t.Fatal("gateway did not start because:", err)
	}

	begin := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e := &mail.Envelope{RemoteIP: "127.0.0.1", QueuedId: "abc12345"}
			e.PushRcpt(mail.Address{User: "test", Host: "example.com"})
			<-begin
			for k := 0; k < 100; k++ {
				// reads the state
				_ = gateway.ValidateRcpt(e)
			}
		}()
	}
	close(begin)
	// writes the state
	if err := gateway.Shutdown(); err != nil {
		t.Error("gateway did not shutdown because:", err)
	}
	wg.Wait()

	if gateway.GetState() != BackendStateShuttered {
		t.Error("gateway should be in shuttered state, got", gateway.GetState())
	}
	// the deprecated State field has to stay in sync with the atomic one
	if gateway.State != gateway.GetState() {
		t.Error("the deprecated State field should mirror GetState(), got",
			gateway.State, "want", gateway.GetState())
	}
}
