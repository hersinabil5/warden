package session

import (
	"context"
	"fmt"
	"log/slog"
)

// RedisLogger adapts slog to go-redis's package-level logger, which
// otherwise prints plain text to stderr. Install it once, from main, with
// redis.SetLogger (docs/DECISIONS.md D3).
type RedisLogger struct{ Logger *slog.Logger }

func (l RedisLogger) Printf(_ context.Context, format string, v ...any) {
	l.Logger.Warn("redis client", "detail", fmt.Sprintf(format, v...))
}
