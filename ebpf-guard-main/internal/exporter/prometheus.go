package exporter

import "github.com/prometheus/client_golang/prometheus"

type Metrics struct {
	events         *prometheus.CounterVec
	ruleMatches    *prometheus.CounterVec
	ringbufDropped *prometheus.CounterVec
	attachErrors   *prometheus.CounterVec
	sensors        *prometheus.GaugeVec
}

func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		events: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "ebpf_guard",
			Name:      "events_total",
			Help:      "Total events per type.",
		}, []string{"type"}),
		ruleMatches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "ebpf_guard",
			Name:      "rule_matches_total",
			Help:      "Rule matches by name and action.",
		}, []string{"name", "action"}),
		ringbufDropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "ebpf_guard",
			Name:      "ringbuf_dropped_total",
			Help:      "Dropped samples per sensor.",
		}, []string{"sensor"}),
		attachErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "ebpf_guard",
			Name:      "attach_errors_total",
			Help:      "Errors while attaching sensors.",
		}, []string{"sensor"}),
		sensors: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "ebpf_guard",
			Name:      "sensors_attached",
			Help:      "Attachment state of sensors.",
		}, []string{"sensor"}),
	}

	reg.MustRegister(m.events, m.ruleMatches, m.ringbufDropped, m.attachErrors, m.sensors)
	return m
}

func (m *Metrics) IncEvent(t string) {
	m.events.WithLabelValues(t).Inc()
}

func (m *Metrics) IncRuleMatch(name, action string) {
	m.ruleMatches.WithLabelValues(name, action).Inc()
}

func (m *Metrics) AddRingbufDropped(sensor string, count uint64) {
	m.ringbufDropped.WithLabelValues(sensor).Add(float64(count))
}

func (m *Metrics) IncAttachError(sensor string) {
	m.attachErrors.WithLabelValues(sensor).Inc()
}

func (m *Metrics) SetSensorAttached(sensor string, state int) {
	m.sensors.WithLabelValues(sensor).Set(float64(state))
}
