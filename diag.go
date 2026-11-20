package main

import (
	"encoding/json"
	"io"
	"net"
	"sync"
)

// nopWriteCloser adapts an io.Writer (e.g. os.Stderr, which the process must
// not close) to the io.WriteCloser the sink expects.
type nopWriteCloser struct{ w io.Writer }

func (n nopWriteCloser) Write(p []byte) (int, error) { return n.w.Write(p) }
func (n nopWriteCloser) Close() error                { return nil }

func newJSONEncoder(w io.Writer) *json.Encoder { return json.NewEncoder(w) }

func splitHostPort(hostport string) (string, string, error) {
	return net.SplitHostPort(hostport)
}

// DiagSink is the independent channel for failure diagnostics. It never
// shares a stream with the available-target output. Writes are serialized; if
// the downstream is closed (or any write fails) the sink latches into a
// broken state and silently drops further records — probing must continue and
// a whole batch must never be aborted because of diagnostics.
type DiagSink struct {
	mu       sync.Mutex
	w        io.WriteCloser
	enc      *json.Encoder
	broken   bool
	closable bool
}

// NewDiagSink wraps a writer. If closer is true the sink owns the writer and
// closes it at shutdown.
func NewDiagSink(w io.WriteCloser) *DiagSink {
	return &DiagSink{w: w, enc: json.NewEncoder(w), closable: true}
}

// Emit writes one diagnostic record. A failure latches the sink permanently;
// subsequent calls are cheap no-ops.
func (d *DiagSink) Emit(v *Verdict) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.broken {
		return
	}
	if err := d.enc.Encode(v); err != nil {
		d.broken = true
	}
}

// Close releases the underlying writer when the sink owns it. A close error
// is ignored: diagnostics are best-effort by contract.
func (d *DiagSink) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closable && d.w != nil {
		_ = d.w.Close()
		d.w = nil
	}
}

// verdictRegistry enforces "one target, one record" semantics under
// concurrency. The first worker to claim a target runs the probe; concurrent
// workers for the same target wait for and reuse its verdict, so the output
// stream can never contain two contradictory records for one target.
type verdictRegistry struct {
	mu      sync.Mutex
	waiters map[string]chan struct{}
	results map[string]*Verdict
}

func newVerdictRegistry() *verdictRegistry {
	return &verdictRegistry{
		waiters: make(map[string]chan struct{}),
		results: make(map[string]*Verdict),
	}
}

// claim returns the shared verdict for target once it exists, and whether the
// caller is the leader responsible for producing it.
func (r *verdictRegistry) claim(target string) (*Verdict, bool) {
	r.mu.Lock()
	if v, ok := r.results[target]; ok {
		r.mu.Unlock()
		return v, false
	}
	if ch, ok := r.waiters[target]; ok {
		r.mu.Unlock()
		<-ch
		r.mu.Lock()
		v := r.results[target]
		r.mu.Unlock()
		return v, false
	}
	ch := make(chan struct{})
	r.waiters[target] = ch
	r.mu.Unlock()
	return nil, true
}

// publish stores the leader's verdict and releases every waiter.
func (r *verdictRegistry) publish(target string, v *Verdict) {
	r.mu.Lock()
	r.results[target] = v
	ch := r.waiters[target]
	delete(r.waiters, target)
	r.mu.Unlock()
	close(ch)
}

// runProbe deduplicates the probing of a target. Exactly one Probe call is
// made per target no matter how many workers enqueue it. leader is true only
// for the worker that actually performs the probe and owns side effects
// (diagnostic emission, stdout output, HTTPS->HTTP fallback scheduling).
func (r *verdictRegistry) runProbe(p *Prober, target string) (v *Verdict, leader bool) {
	existing, isLeader := r.claim(target)
	if !isLeader {
		return existing, false
	}
	v = p.Probe(backgroundCtx(), target)
	r.publish(target, v)
	return v, true
}
