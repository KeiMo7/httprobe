package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// resultSink writes terminal results and guarantees that a failed write never
// causes already-completed results to be thrown away.
//
// For file output results are first written to a temporary file in the same
// directory and only renamed into place on Close. If the batch is cancelled,
// Close is still called and the completed portion is kept. If a write fails,
// the temp file is left in place and its path is reported rather than the
// partial batch being deleted.
type resultSink interface {
	// WriteResult appends one terminal result. Results are supplied in plan
	// order, so the on-disk order is stable between runs.
	WriteResult(probeResult) error
	// Close flushes and finalises the output. It returns the first write
	// error encountered. Completed results are preserved regardless.
	Close() error
	// Path is the final output destination ("-" for stdout).
	Path() string
}

func newResultSink(path string, jsonOut bool, stdout io.Writer) (resultSink, error) {
	if stdout == nil {
		stdout = os.Stdout
	}
	if path == "" || path == "-" {
		sw := &streamSink{
			w:       bufio.NewWriterSize(stdout, 64*1024),
			jsonOut: jsonOut,
			path:    "-",
			out:     stdout,
		}
		return sw, nil
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".httprobe-*.tmp")
	if err != nil {
		// Fall back to writing the destination directly so results are not
		// lost entirely.
		f, ferr := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if ferr != nil {
			return nil, fmt.Errorf("open output %s: %w", path, ferr)
		}
		return &streamSink{
			w:       bufio.NewWriterSize(f, 64*1024),
			jsonOut: jsonOut,
			path:    path,
			out:     f,
			closer:  f,
		}, nil
	}

	return &fileSink{
		streamSink: &streamSink{
			w:       bufio.NewWriterSize(tmp, 64*1024),
			jsonOut: jsonOut,
			path:    path,
			out:     tmp,
			closer:  tmp,
		},
		tmpPath:   tmp.Name(),
		finalPath: path,
	}, nil
}

// lineWriter is the minimal buffered-line interface streamSink needs. It is
// an interface so tests can inject a failing writer.
type lineWriter interface {
	WriteString(string) (int, error)
	Flush() error
}

type streamSink struct {
	w       lineWriter
	jsonOut bool
	path    string
	out     io.Writer
	closer  io.Closer
	err     error
	written int
}

func (s *streamSink) Path() string { return s.path }

func (s *streamSink) WriteResult(r probeResult) error {
	if s.err != nil {
		return s.err
	}
	var line string
	if s.jsonOut {
		line = formatJSON(r)
	} else {
		// Preserve the original stdout format: reachable URLs only.
		if r.Status != statusReachable {
			return nil
		}
		line = r.Target.URL
	}
	if _, err := s.w.WriteString(line + "\n"); err != nil {
		s.err = err
		return err
	}
	return nil
}

func (s *streamSink) Close() error {
	if err := s.w.Flush(); err != nil && s.err == nil {
		s.err = err
	}
	if s.closer != nil {
		if err := s.closer.Close(); err != nil && s.err == nil {
			s.err = err
		}
	}
	return s.err
}

type fileSink struct {
	*streamSink
	tmpPath   string
	finalPath string
	closed    bool
}

func (s *fileSink) Close() error {
	if s.closed {
		return s.err
	}
	s.closed = true
	writeErr := s.streamSink.Close()
	if writeErr != nil {
		// Keep the partial temp file: it contains the completed results.
		return fmt.Errorf("%w (partial results preserved at %s)", writeErr, s.tmpPath)
	}
	if err := os.Rename(s.tmpPath, s.finalPath); err != nil {
		return fmt.Errorf("finalise output %s: %w (partial results preserved at %s)", s.finalPath, err, s.tmpPath)
	}
	return nil
}

// formatJSON renders one result as a single stable JSON object. It includes
// the attempt count and the final error class but deliberately omits raw error
// text, which can contain the target address.
func formatJSON(r probeResult) string {
	obj := struct {
		URL       string     `json:"url"`
		Status    status     `json:"status"`
		Attempts  int        `json:"attempts"`
		LastError ErrorClass `json:"last_error"`
		Reachable bool       `json:"reachable"`
	}{
		URL:       r.Target.URL,
		Status:    r.Status,
		Attempts:  r.Attempts,
		LastError: r.LastError,
		Reachable: r.Status == statusReachable,
	}
	if obj.LastError == "" {
		obj.LastError = "none"
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return fmt.Sprintf(
			`{"url":%q,"status":%q,"attempts":%d,"reachable":false}`,
			r.Target.URL, r.Status, r.Attempts,
		)
	}
	return string(b)
}
