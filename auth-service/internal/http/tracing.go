package http

import (
	"context"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

func WithSpan(ctx context.Context, name string, fn func(ctx context.Context)) {
	span, ctx2 := tracer.StartSpanFromContext(ctx, name)
	defer span.Finish()
	fn(ctx2)
}

func TagError(err error) tracer.StartSpanOption {
	if err == nil {
		return nil
	}
	return tracer.Tag("error", err.Error())
}
