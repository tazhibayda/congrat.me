package log

import "go.uber.org/zap"

var L *zap.Logger

func Init(prod bool) (func() error, error) {
	var err error
	if prod {
		L, err = zap.NewProduction()
	} else {
		L, err = zap.NewDevelopment()
	}
	
	if err != nil {
		return nil, err
	}
	return L.Sync, nil
}
