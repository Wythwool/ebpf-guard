package exporter

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"time"
)

type Stream struct {
	ch <-chan any
}

func NewStream(ch <-chan any) *Stream {
	return &Stream{ch: ch}
}

func (s *Stream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	bw := bufio.NewWriterSize(w, 64*1024)
	defer bw.Flush()

	ctx := r.Context()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	enc := json.NewEncoder(bw)
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-s.ch:
			if !ok {
				return
			}
			if err := enc.Encode(ev); err != nil {
				return
			}
			bw.Flush()
		case <-ticker.C:
			bw.Flush()
		}
	}
}
