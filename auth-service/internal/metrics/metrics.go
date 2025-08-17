package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	RequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "http_requests_total", Help: "Total HTTP requests"},
		[]string{"route", "method", "status"},
	)
	ReqDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Request duration seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"route", "method"},
	)
	InFlight = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "http_in_flight_requests", Help: "In-flight HTTP requests"},
	)
)

func MustRegister() {
	prometheus.MustRegister(RequestsTotal, ReqDuration, InFlight)
}
