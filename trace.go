package main

import (
	"encoding/json"
	"io"
	"os"
)

// TraceTarget is one canonical probe target together with every original
// input line that normalized to it. A target may correspond to multiple lines
// (different case, trailing dots, scheme prefixes, etc.).
type TraceTarget struct {
	Target string     `json:"target"`
	Host   string     `json:"host"`
	Port   string     `json:"port,omitempty"`
	Source []RawEntry `json:"sources"`
}

// Trace is the full mapping between normalized targets and raw input lines.
// It is emitted as one JSON object per line (JSON Lines).
type Trace struct {
	Targets []TraceTarget  `json:"targets"`
	Invalid []InvalidEntry `json:"invalid,omitempty"`
	Skipped int            `json:"blank_lines_skipped"`
}

// Accumulator folds normalized input lines into unique targets keyed by the
// canonical target string. Dedup is based purely on normalization output,
// while every merged original spelling is retained.
type Accumulator struct {
	order   []string // target keys, in first-seen order
	targets map[string]*TraceTarget
	Invalid []InvalidEntry
	blank   int
}

// NewAccumulator constructs an empty Accumulator.
func NewAccumulator() *Accumulator {
	return &Accumulator{targets: map[string]*TraceTarget{}}
}

// Add feeds one NormalizeLine result into the accumulator.
func (a *Accumulator) Add(res Result) {
	switch {
	case res.Target != nil:
		t := res.Target
		if existing, ok := a.targets[t.Target]; ok {
			existing.Source = append(existing.Source, t.Entry)
			return
		}
		a.order = append(a.order, t.Target)
		a.targets[t.Target] = &TraceTarget{
			Target: t.Target,
			Host:   t.Host,
			Port:   t.Port,
			Source: []RawEntry{t.Entry},
		}
	case res.Invalid != nil:
		a.Invalid = append(a.Invalid, *res.Invalid)
	default:
		// Blank line.
		a.blank++
	}
}

// Targets returns the unique canonical targets in first-seen order.
func (a *Accumulator) Targets() []TraceTarget {
	out := make([]TraceTarget, 0, len(a.order))
	for _, key := range a.order {
		out = append(out, *a.targets[key])
	}
	return out
}

// WriteTrace emits the trace as JSON Lines. A failure here must never stop
// the batch: the caller logs the error and probing continues without a trace.
func (a *Accumulator) WriteTrace(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, key := range a.order {
		if err := enc.Encode(a.targets[key]); err != nil {
			return err
		}
	}
	for i := range a.Invalid {
		if err := enc.Encode(struct {
			Invalid InvalidEntry `json:"invalid"`
		}{Invalid: a.Invalid[i]}); err != nil {
			return err
		}
	}
	summary := struct {
		BlankLinesSkipped int `json:"blank_lines_skipped"`
		InvalidCount      int `json:"invalid_count"`
		TargetCount       int `json:"target_count"`
	}{a.blank, len(a.Invalid), len(a.order)}
	return enc.Encode(summary)
}

// openTrace opens the trace destination. The special name "-" means stderr
// (never stdout, which must keep carrying one probe result per line only).
// Any failure is returned to the caller so probing can proceed without it.
func openTrace(path string) (io.WriteCloser, error) {
	if path == "-" {
		return os.Stderr, nil
	}
	return os.Create(path)
}
