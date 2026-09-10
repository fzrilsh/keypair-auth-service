package main

import (
	"context"
	"io"
	"strings"
	"testing"
)

func TestRunDispatchesKnownCommand(t *testing.T) {
	called := false
	commands := map[string]commandRunner{
		"serve": func(context.Context, io.Reader, io.Writer) error {
			called = true
			return nil
		},
	}
	if err := run([]string{"serve"}, strings.NewReader(""), io.Discard, io.Discard, commands); err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	if !called {
		t.Fatal("expected serve command to run")
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	err := run([]string{"unknown"}, strings.NewReader(""), io.Discard, io.Discard, nil)
	if err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("expected unknown command error, got %v", err)
	}
}
