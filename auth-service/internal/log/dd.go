package log

import (
	"context"
	"fmt"

	"go.uber.org/zap"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

// WithDD returns a logger enriched with Datadog correlation fields if a span is present in ctx.
// Adds: dd.trace_id, dd.span_id. (As strings — так ожидает Datadog).
func WithDD(ctx context.Context, base *zap.Logger, extra ...zap.Field) *zap.Logger {
	l := base
	if sp, ok := tracer.SpanFromContext(ctx); ok && sp != nil {
		if sc, ok := sp.Context().(ddtrace.SpanContext); ok {
			tid := fmt.Sprintf("%d", sc.TraceID())
			sid := fmt.Sprintf("%d", sc.SpanID())
			extra = append(extra, zap.String("dd.trace_id", tid), zap.String("dd.span_id", sid))
		}
	}
	return l.With(extra...)
}
