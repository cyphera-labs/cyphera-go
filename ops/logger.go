package ops

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

// NewNoopLogger returns a Logger that discards all events.
// Use this when audit logging is not needed (e.g. unit tests, batch processing).
func NewNoopLogger() Logger {
	return &noopLogger{}
}

// NewStdLogger returns a Logger that writes human-readable audit lines to w.
// Each line is formatted as:
//
//	[2006-01-02T15:04:05Z] encrypt ssn customer-primary/v3 ok
func NewStdLogger(w io.Writer) Logger {
	return &stdLogger{w: w}
}

// NewJSONLogger returns a Logger that writes one JSON object per line to w.
// The JSON structure mirrors the Event struct.
func NewJSONLogger(w io.Writer) Logger {
	return &jsonLogger{w: w}
}

// --- noop ---

type noopLogger struct{}

func (l *noopLogger) Log(_ context.Context, _ Event) error { return nil }

// --- std ---

type stdLogger struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *stdLogger) Log(_ context.Context, ev Event) error {
	status := "ok"
	if !ev.Success {
		status = "err: " + ev.Error
	}
	ts := ev.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	line := fmt.Sprintf("[%s] %s %s %s/v%d %s\n",
		ts.Format(time.RFC3339),
		ev.Operation,
		ev.Domain,
		ev.KeyRef,
		ev.KeyVersion,
		status,
	)
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err := io.WriteString(l.w, line)
	return err
}

// --- json ---

type jsonLogger struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *jsonLogger) Log(_ context.Context, ev Event) error {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = fmt.Fprintf(l.w, "%s\n", b)
	return err
}
