package backends

import (
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"runtime/debug"
	"strings"

	"github.com/phires/go-guerrilla/log"
	"github.com/phires/go-guerrilla/mail"
	"github.com/phires/go-guerrilla/response"
)

var ErrProcessorNotFound error

// A backend gateway is a proxy that implements the Backend interface.
// It is used to start multiple goroutine workers for saving mail, and then distribute email saving to the workers
// via a channel. Shutting down via Shutdown() will stop all workers.
// The rest of this program always talks to the backend via this gateway.
type BackendGateway struct {
	// channel for distributing envelopes to workers
	conveyor chan *workerMsg

	// waits for backend workers to start/stop
	wg           sync.WaitGroup
	workStoppers []chan bool
	processors   []Processor
	validators   []Processor

	// controls access to the gateway's configuration and worker set
	sync.Mutex

	// State mirrors the gateway's state for callers that read it directly.
	// It's only ever written while holding the mutex.
	//
	// Deprecated: reading this field is not goroutine safe, it may be torn or
	// stale when the gateway changes state concurrently. Use GetState() instead.
	State backendState

	// state is the authoritative copy of the gateway's state. Process and
	// ValidateRcpt read it on the hot path without taking the mutex, so it's
	// accessed atomically. Use GetState() / setState().
	state atomic.Int32

	// shutdownSignal stores a chan struct{} that gets closed when the gateway
	// shuts down, and is replaced by a fresh one on Initialize so that the gateway
	// can be reused. Closing it releases everything that waits to put a message on
	// the conveyor. Stored atomically because Process must not take the mutex:
	// Shutdown holds it across wg.Wait().
	shutdownSignal atomic.Value

	config   BackendConfig
	gwConfig *GatewayConfig
}

// shutdownChan returns the channel that is closed when the gateway shuts down.
// Returns nil for a gateway that was never initialized - receiving from a nil
// channel blocks forever, which is the safe default for a select case.
func (gw *BackendGateway) shutdownChan() <-chan struct{} {
	if sig, ok := gw.shutdownSignal.Load().(chan struct{}); ok {
		return sig
	}
	return nil
}

// signalShutdown releases everything that waits on the conveyor. The caller must
// hold the mutex, and must not call it twice for the same shutdown - the
// BackendStateShuttered check in Shutdown takes care of that.
func (gw *BackendGateway) signalShutdown() {
	if sig, ok := gw.shutdownSignal.Load().(chan struct{}); ok && sig != nil {
		close(sig)
	}
}

// isShuttingDown reports whether the shutdown signal has already been given.
// Used to give the shutdown priority over an otherwise ready conveyor: a select
// picks a random ready case, and a buffered conveyor stays writable even when
// there is no worker left to read from it.
func (gw *BackendGateway) isShuttingDown() bool {
	select {
	case <-gw.shutdownChan():
		return true
	default:
		return false
	}
}

// drainConveyor answers every message that is still queued. Called once the
// workers are gone, so that a caller whose message made it into the buffer just
// before the shutdown gets a result instead of waiting out its whole timeout and
// leaking a drain goroutine plus a locked envelope.
//
// Every queued message has exactly one waiter - either the caller itself or its
// drain goroutine - but the send is guarded by a short timeout anyway, so that a
// broken invariant cannot wedge Shutdown while it holds the mutex.
func (gw *BackendGateway) drainConveyor() {
	for {
		select {
		case msg := <-gw.conveyor:
			select {
			case msg.notifyMe <- &notifyMsg{err: StorageNotAvailable}:
			case <-time.After(time.Second):
				Log().Error("could not notify a queued message during shutdown")
			}
		default:
			return
		}
	}
}

// GetState returns the gateway's current state, goroutine safe
func (gw *BackendGateway) GetState() backendState {
	return backendState(gw.state.Load())
}

// setState stores the gateway's state, goroutine safe.
// The caller is expected to hold gw.Mutex, so that the deprecated State field
// keeps the same single-writer guarantee it always had.
func (gw *BackendGateway) setState(state backendState) {
	gw.state.Store(int32(state))
	gw.State = state
}

type GatewayConfig struct {
	// WorkersSize controls how many concurrent workers to start. Defaults to 1
	WorkersSize int `json:"save_workers_size,omitempty"`
	// SaveProcess controls which processors to chain in a stack for saving email tasks
	SaveProcess string `json:"save_process,omitempty"`
	// ValidateProcess is like ProcessorStack, but for recipient validation tasks
	ValidateProcess string `json:"validate_process,omitempty"`
	// TimeoutSave is duration before timeout when saving an email, eg "29s"
	TimeoutSave string `json:"gw_save_timeout,omitempty"`
	// TimeoutValidateRcpt duration before timeout when validating a recipient, eg "1s"
	TimeoutValidateRcpt string `json:"gw_val_rcpt_timeout,omitempty"`
}

// workerMsg is what get placed on the BackendGateway.saveMailChan channel
type workerMsg struct {
	// The email data
	e *mail.Envelope
	// notifyMe is used to notify the gateway of workers finishing their processing
	notifyMe chan *notifyMsg
	// select the task type
	task SelectTask
}

type backendState int

// possible values for state
const (
	BackendStateNew backendState = iota
	BackendStateRunning
	BackendStateShuttered
	BackendStateError
	BackendStateInitialized

	// default timeout for saving email, if 'gw_save_timeout' not present in config
	saveTimeout = time.Second * 30
	// default timeout for validating rcpt to, if 'gw_val_rcpt_timeout' not present in config
	validateRcptTimeout = time.Second * 5
	defaultProcessor    = "Debugger"
)

func (s backendState) String() string {
	switch s {
	case BackendStateNew:
		return "NewState"
	case BackendStateRunning:
		return "RunningState"
	case BackendStateShuttered:
		return "ShutteredState"
	case BackendStateError:
		return "ErrorSate"
	case BackendStateInitialized:
		return "InitializedState"
	}
	return strconv.Itoa(int(s))
}

// New makes a new default BackendGateway backend, and initializes it using
// backendConfig and stores the logger
func New(backendConfig BackendConfig, l log.Logger) (Backend, error) {
	Svc.SetMainlog(l)
	gateway := &BackendGateway{}
	err := gateway.Initialize(backendConfig)
	if err != nil {
		return nil, fmt.Errorf("error while initializing the backend: %s", err)
	}
	// keep the config known to be good.
	gateway.config = backendConfig

	b = Backend(gateway)
	return b, nil
}

var workerMsgPool = sync.Pool{
	// if not available, then create a new one
	New: func() interface{} {
		return &workerMsg{}
	},
}

// reset resets a workerMsg that has been borrowed from the pool
func (w *workerMsg) reset(e *mail.Envelope, task SelectTask) {
	if w.notifyMe == nil {
		w.notifyMe = make(chan *notifyMsg)
	}
	w.e = e
	w.task = task
}

// Process distributes an envelope to one of the backend workers with a TaskSaveMail task
func (gw *BackendGateway) Process(e *mail.Envelope, task SelectTask) Result {
	if gw.GetState() != BackendStateRunning || gw.isShuttingDown() {
		return NewResult(response.Canned.FailBackendNotRunning, response.SP, gw.GetState())
	}
	// borrow a workerMsg from the pool
	workerMsg := workerMsgPool.Get().(*workerMsg)
	workerMsg.reset(e, task)
	// One timer for the whole operation, so that a slow enqueue plus a slow save
	// cannot add up to twice the configured timeout.
	timer := time.NewTimer(gw.saveTimeout())
	defer timer.Stop()
	// place on the channel so that one of the save mail workers can pick it up.
	// The conveyor only buffers workersSize messages, so this send blocks as soon
	// as the workers fall behind - it needs the same timeout as the answer below.
	select {
	case gw.conveyor <- workerMsg:
	case <-timer.C:
		Log().Error("Backend has timed out while queueing email")
		// nobody took the message, so it's safe to recycle right away
		workerMsgPool.Put(workerMsg)
		return NewResult(response.Canned.FailBackendTimeout)
	case <-gw.shutdownChan():
		// the gateway shut down after we read the state above, don't park on a
		// conveyor that no worker reads any more
		workerMsgPool.Put(workerMsg)
		return NewResult(response.Canned.FailBackendNotRunning, response.SP, gw.GetState())
	}
	// wait for the save to complete
	// or timeout
	select {
	case status := <-workerMsg.notifyMe:
		// email saving transaction completed
		if status.result == BackendResultOK && status.queuedID != "" {
			return NewResult(response.Canned.SuccessMessageQueued, response.SP, status.queuedID)
		}

		// A custom result, there was probably an error, if so, log it
		if status.result != nil {
			if status.err != nil {
				Log().Error(status.err)
			}
			return status.result
		}

		// if there was no result, but there's an error, then make a new result from the error
		if status.err != nil {
			if _, err := strconv.Atoi(status.err.Error()[:3]); err != nil {
				return NewResult(response.Canned.FailBackendTransaction, response.SP, status.err)
			}
			return NewResult(status.err)
		}

		// both result & error are nil (should not happen)
		err := errors.New("no response from backend - processor did not return a result or an error")
		Log().Error(err)
		return NewResult(response.Canned.FailBackendTransaction, response.SP, err)

	case <-timer.C:
		Log().Error("Backend has timed out while saving email")
		e.Lock() // lock the envelope - it's still processing here, we don't want the server to recycle it
		go func() {
			// keep waiting for the backend to finish processing
			<-workerMsg.notifyMe
			e.Unlock()
			workerMsgPool.Put(workerMsg)
		}()
		return NewResult(response.Canned.FailBackendTimeout)
	}
}

// ValidateRcpt asks one of the workers to validate the recipient
// Only the last recipient appended to e.RcptTo will be validated.
func (gw *BackendGateway) ValidateRcpt(e *mail.Envelope) RcptError {
	if gw.GetState() != BackendStateRunning || gw.isShuttingDown() {
		return StorageNotAvailable
	}
	if _, ok := gw.validators[0].(NoopProcessor); ok {
		// no validator processors configured
		return nil
	}
	// place on the channel so that one of the save mail workers can pick it up
	workerMsg := workerMsgPool.Get().(*workerMsg)
	workerMsg.reset(e, TaskValidateRcpt)
	// one timer for the whole operation, see Process
	timer := time.NewTimer(gw.validateRcptTimeout())
	defer timer.Stop()
	select {
	case gw.conveyor <- workerMsg:
	case <-timer.C:
		Log().Error("Backend has timed out while queueing rcpt validation")
		// nobody took the message, so it's safe to recycle right away
		workerMsgPool.Put(workerMsg)
		return StorageTimeout
	case <-gw.shutdownChan():
		workerMsgPool.Put(workerMsg)
		return StorageNotAvailable
	}
	// wait for the validation to complete
	// or timeout
	select {
	case status := <-workerMsg.notifyMe:
		workerMsgPool.Put(workerMsg)
		if status.err != nil {
			return status.err
		}
		return nil

	case <-timer.C:
		e.Lock()
		go func() {
			<-workerMsg.notifyMe
			e.Unlock()
			workerMsgPool.Put(workerMsg)
			Log().Error("Backend has timed out while validating rcpt")
		}()
		return StorageTimeout
	}
}

// Shutdown shuts down the backend and leaves it in BackendStateShuttered state
func (gw *BackendGateway) Shutdown() error {
	gw.Lock()
	defer gw.Unlock()
	if gw.GetState() != BackendStateShuttered {
		// release anything that is waiting to put a message on the conveyor before
		// the workers go away, otherwise it would wait for a reader that never comes
		gw.signalShutdown()
		// send a signal to all workers
		gw.stopWorkers()
		// wait for workers to stop
		gw.wg.Wait()
		// nothing reads the conveyor from here on, so answer whatever is still
		// queued rather than leaving those callers to wait out their timeout
		gw.drainConveyor()
		// call shutdown on all processor shutdowners
		if err := Svc.shutdown(); err != nil {
			return err
		}
		gw.setState(BackendStateShuttered)
	}
	return nil
}

// Reinitialize initializes the gateway with the existing config after it was shutdown
func (gw *BackendGateway) Reinitialize() error {
	if gw.GetState() != BackendStateShuttered {
		return errors.New("backend must be in BackendStateshuttered state to Reinitialize")
	}
	// clear the Initializers and Shutdowners
	Svc.reset()

	err := gw.Initialize(gw.config)
	if err != nil {
		fmt.Println("reinitialize to ", gw.config, err)
		return fmt.Errorf("error while initializing the backend: %s", err)
	}

	return err
}

// newStack creates a new Processor by chaining multiple Processors in a call stack
// Decorators are functions of Decorator type, source files prefixed with p_*
// Each decorator does a specific task during the processing stage.
// This function uses the config value save_process or validate_process to figure out which Decorator to use
func (gw *BackendGateway) newStack(stackConfig string) (Processor, error) {
	var decorators []Decorator
	cfg := strings.ToLower(strings.TrimSpace(stackConfig))
	if len(cfg) == 0 {
		//cfg = strings.ToLower(defaultProcessor)
		return NoopProcessor{}, nil
	}
	items := strings.Split(cfg, "|")
	for i := range items {
		name := items[len(items)-1-i] // reverse order, since decorators are stacked
		if makeFunc, ok := processors[name]; ok {
			decorators = append(decorators, makeFunc())
		} else {
			ErrProcessorNotFound = fmt.Errorf("processor [%s] not found", name)
			return nil, ErrProcessorNotFound
		}
	}
	// build the call-stack of decorators
	p := Decorate(DefaultProcessor{}, decorators...)
	return p, nil
}

// loadConfig loads the config for the GatewayConfig
func (gw *BackendGateway) loadConfig(cfg BackendConfig) error {
	configType := BaseConfig(&GatewayConfig{})
	// Note: treat config values as immutable
	// if you need to change a config value, change in the file then
	// send a SIGHUP
	bcfg, err := Svc.ExtractConfig(cfg, configType)
	if err != nil {
		return err
	}
	gw.gwConfig = bcfg.(*GatewayConfig)
	return nil
}

// Initialize builds the workers and initializes each one
func (gw *BackendGateway) Initialize(cfg BackendConfig) error {
	gw.Lock()
	defer gw.Unlock()
	if gw.GetState() != BackendStateNew && gw.GetState() != BackendStateShuttered {
		return errors.New("can only Initialize in BackendStateNew or BackendStateShuttered state")
	}
	err := gw.loadConfig(cfg)
	if err != nil {
		gw.setState(BackendStateError)
		return err
	}
	workersSize := gw.workersSize()
	if workersSize < 1 {
		gw.setState(BackendStateError)
		return errors.New("must have at least 1 worker")
	}
	gw.processors = make([]Processor, 0)
	gw.validators = make([]Processor, 0)
	for i := 0; i < workersSize; i++ {
		p, err := gw.newStack(gw.gwConfig.SaveProcess)
		if err != nil {
			gw.setState(BackendStateError)
			return err
		}
		gw.processors = append(gw.processors, p)

		v, err := gw.newStack(gw.gwConfig.ValidateProcess)
		if err != nil {
			gw.setState(BackendStateError)
			return err
		}
		gw.validators = append(gw.validators, v)
	}
	// initialize processors
	if err := Svc.initialize(cfg); err != nil {
		gw.setState(BackendStateError)
		return err
	}
	if gw.conveyor == nil {
		gw.conveyor = make(chan *workerMsg, workersSize)
	}
	// a fresh shutdown signal, the old one may have been closed by Shutdown
	gw.shutdownSignal.Store(make(chan struct{}))
	// ready to start
	gw.setState(BackendStateInitialized)
	return nil
}

// Start starts the worker goroutines, assuming it has been initialized or shuttered before
func (gw *BackendGateway) Start() error {
	gw.Lock()
	defer gw.Unlock()
	if state := gw.GetState(); state == BackendStateInitialized || state == BackendStateShuttered {
		// we start our workers
		workersSize := gw.workersSize()
		// make our slice of channels for stopping
		gw.workStoppers = make([]chan bool, 0)
		// set the wait group
		gw.wg.Add(workersSize)

		for i := 0; i < workersSize; i++ {
			stop := make(chan bool)
			go func(workerId int, stop chan bool) {
				// blocks here until the worker exits
				for {
					state := gw.workDispatcher(
						gw.conveyor,
						gw.processors[workerId],
						gw.validators[workerId],
						workerId+1,
						stop)
					// keep running after panic
					if state != dispatcherStatePanic {
						break
					}
				}
				gw.wg.Done()
			}(i, stop)
			gw.workStoppers = append(gw.workStoppers, stop)
		}
		gw.setState(BackendStateRunning)
		return nil
	} else {
		return fmt.Errorf("cannot start backend because it's in %s state", gw.GetState())
	}
}

// workersSize gets the number of workers to use for saving email by reading the save_workers_size config value
// Returns 1 if no config value was set
func (gw *BackendGateway) workersSize() int {
	if gw.gwConfig.WorkersSize <= 0 {
		return 1
	}
	return gw.gwConfig.WorkersSize
}

// saveTimeout returns the maximum amount of seconds to wait before timing out a save processing task
func (gw *BackendGateway) saveTimeout() time.Duration {
	if gw.gwConfig.TimeoutSave == "" {
		return saveTimeout
	}
	t, err := time.ParseDuration(gw.gwConfig.TimeoutSave)
	if err != nil {
		return saveTimeout
	}
	return t
}

// validateRcptTimeout returns the maximum amount of seconds to wait before timing out a recipient validation  task
func (gw *BackendGateway) validateRcptTimeout() time.Duration {
	if gw.gwConfig.TimeoutValidateRcpt == "" {
		return validateRcptTimeout
	}
	t, err := time.ParseDuration(gw.gwConfig.TimeoutValidateRcpt)
	if err != nil {
		return validateRcptTimeout
	}
	return t
}

type dispatcherState int

const (
	dispatcherStateStopped dispatcherState = iota
	dispatcherStateIdle
	dispatcherStateWorking
	dispatcherStateNotify
	dispatcherStatePanic
)

func (gw *BackendGateway) workDispatcher(
	workIn chan *workerMsg,
	save Processor,
	validate Processor,
	workerId int,
	stop chan bool) (state dispatcherState) {

	var msg *workerMsg

	defer func() {

		// panic recovery mechanism: it may panic when processing
		// since processors may call arbitrary code, some may be 3rd party / unstable
		// we need to detect the panic, and notify the backend that it failed & unlock the envelope
		if r := recover(); r != nil {
			Log().Error("worker recovered from panic:", r, string(debug.Stack()))

			if state == dispatcherStateWorking {
				msg.notifyMe <- &notifyMsg{err: errors.New("storage failed")}
			}
			state = dispatcherStatePanic
			return
		}
		// state is dispatcherStateStopped if it reached here

	}()
	state = dispatcherStateIdle
	Log().Infof("processing worker started (#%d)", workerId)
	for {
		select {
		case <-stop:
			state = dispatcherStateStopped
			Log().Infof("stop signal for worker (#%d)", workerId)
			return
		case msg = <-workIn:
			state = dispatcherStateWorking // recovers from panic if in this state
			if msg.task == TaskSaveMail || msg.task == TaskTest {
				result, err := save.Process(msg.e, msg.task)
				state = dispatcherStateNotify
				msg.notifyMe <- &notifyMsg{err: err, result: result, queuedID: msg.e.QueuedId}
			} else {
				result, err := validate.Process(msg.e, msg.task)
				state = dispatcherStateNotify
				msg.notifyMe <- &notifyMsg{err: err, result: result}
			}
		}
		state = dispatcherStateIdle
	}
}

// stopWorkers sends a signal to all workers to stop
func (gw *BackendGateway) stopWorkers() {
	for i := range gw.workStoppers {
		gw.workStoppers[i] <- true
	}
}
