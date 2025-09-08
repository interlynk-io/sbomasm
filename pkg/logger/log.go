// Copyright 2025 Interlynk.io
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package logger

import (
	"context"

	"go.uber.org/zap"
)

var logger *zap.SugaredLogger

type logKey struct{}

func InitProdLogger() {
	l, _ := zap.NewProduction()
	// l, _ := zap.NewDevelopment()
	defer l.Sync()
	if logger != nil {
		panic("logger already initialized")
	}
	logger = l.Sugar()
}

func InitDebugLogger() {
	l, _ := zap.NewDevelopment()
	defer l.Sync()
	if logger != nil {
		panic("logger already initialized")
	}
	logger = l.Sugar()
}

func WithLogger(ctx context.Context) context.Context {
	return context.WithValue(ctx, logKey{}, logger)
}

func WithLoggerAndCancel(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithCancel(context.WithValue(ctx, logKey{}, logger))
}

func FromContext(ctx context.Context) *zap.SugaredLogger {
	if logger, ok := ctx.Value(logKey{}).(*zap.SugaredLogger); ok {
		return logger
	}

	return zap.NewNop().Sugar()
}

type ZapRetryLogger struct {
	Debug  bool
	Logger *zap.SugaredLogger
}

// implement Logger: https://pkg.go.dev/github.com/hashicorp/go-retryablehttp#Logger
func (z *ZapRetryLogger) Printf(format string, args ...interface{}) {
	if z.Debug {
		z.Logger.Debugf(format, args...)
	}
}
