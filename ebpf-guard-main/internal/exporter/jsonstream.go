package exporter

import (
	"net/http"
	"sync"
)

type Stream struct {
	mu      sync.Mutex
	clients map[chan []byte]struct{}
}

func NewStream() *Stream {
	return &Stream{clients: make(map[chan []byte]struct{})}
}

func (s *Stream) Publish(data []byte) {
	if data == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.clients {
		select {
		case ch <- append([]byte(nil), data):
		default:
		}
	}
}

func (s *Stream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "stream unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	ch := make(chan []byte, 128)
	s.addClient(ch)
	defer s.removeClient(ch)

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case payload := <-ch:
			if _, err := w.Write(payload); err != nil {
				return
			}
			if _, err := w.Write([]byte("\n")); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *Stream) addClient(ch chan []byte) {
	s.mu.Lock()
	s.clients[ch] = struct{}{}
	s.mu.Unlock()
}

func (s *Stream) removeClient(ch chan []byte) {
	s.mu.Lock()
	delete(s.clients, ch)
	close(ch)
	s.mu.Unlock()
}
