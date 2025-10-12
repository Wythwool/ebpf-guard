package exporter

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
)

type Metrics struct {
	EventsTotal        *prometheus.CounterVec
	RuleMatchesTotal   *prometheus.CounterVec
	RingbufDropped     *prometheus.CounterVec
	SensorsAttached    *prometheus.GaugeVec
}

func NewMetrics() *Metrics {
	m := &Metrics{
		EventsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ebpf_guard_events_total",
			Help: "Events by type",
		}, []string{"type"}),
		RuleMatchesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ebpf_guard_rule_matches_total",
			Help: "Rule matches",
		}, []string{"name","action"}),
		RingbufDropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ebpf_guard_ringbuf_dropped_total",
			Help: "Dropped ringbuffer records by sensor",
		}, []string{"sensor"}),
		SensorsAttached: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_guard_sensor_attached",
			Help: "Sensor attached (1) or not (0)",
		}, []string{"sensor"}),
	}
	prometheus.MustRegister(m.EventsTotal, m.RuleMatchesTotal, m.RingbufDropped, m.SensorsAttached)
	return m
}

func Handler() http.Handler {
	return promhttp.Handler()
}
