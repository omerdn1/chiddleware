package logger

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type LoggerOptions struct {
	// LogLevel defines the minimum level of severity that app should log.
	//
	// Must be one of: ["trace", "debug", "info", "warn", "error", "critical"]
	LogLevel string

	// JSON enables structured logging output in json. Make sure to enable this
	// in production mode so log aggregators can receive data in parsable format.
	//
	// In local development mode, its appropriate to set this value to false to
	// receive pretty output and stacktraces to stdout.
	JSON bool

	// Concise mode includes fewer log details during the request flow. For example
	// exluding details like request content length, user-agent and other details.
	// This is useful if during development your console is too noisy.
	Concise bool

	// Tags are additional fields included at the root level of all logs.
	// These can be useful for example the commit hash of a build, or an environment
	// name like prod/stg/dev
	Tags map[string]string

	// SkipHeaders are additional headers which are redacted from the logs
	SkipHeaders []string
}

type RequestMiddlewareOptions struct {
	// ResponseBody enables the inclusion of a portion of the response body in the log entry
	ResponseBody bool
}

type requestLogger struct {
	// Logger refers to the zerolog logging object
	Logger zerolog.Logger
}

var DefaultLoggerOptions = LoggerOptions{
	LogLevel:    "info",
	JSON:        false,
	Concise:     false,
	Tags:        nil,
	SkipHeaders: nil,
}

var DefaultRequestMiddlewareOptions = RequestMiddlewareOptions{
	ResponseBody: false,
}

// configure configures the logger using the given options.
func configure(opts LoggerOptions) {
	if opts.LogLevel == "" {
		opts.LogLevel = "info"
	}

	// Pre-downcase all SkipHeaders
	for i, header := range opts.SkipHeaders {
		opts.SkipHeaders[i] = strings.ToLower(header)
	}

	// Set the zerolog global level
	logLevel, err := zerolog.ParseLevel(strings.ToLower(opts.LogLevel))
	if err != nil {
		fmt.Printf("logger: error converting level string into zerolevel value. %v\n", err)
		os.Exit(1)
	}
	zerolog.SetGlobalLevel(logLevel)

	zerolog.LevelFieldName = "level"
	zerolog.TimestampFieldName = "timestamp"
	zerolog.TimeFieldFormat = time.RFC3339Nano

	if !opts.JSON {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})
	}
}

// New initiates a new logger instance using the given serviceName and options.
func New(serviceName string, opts ...LoggerOptions) zerolog.Logger {
	if len(opts) > 0 {
		configure(opts[0])
	} else {
		configure(DefaultLoggerOptions)
	}
	logger := log.With().Str("service", strings.ToLower(serviceName))
	if !DefaultLoggerOptions.Concise && len(DefaultLoggerOptions.Tags) > 0 {
		logger = logger.Fields(map[string]interface{}{
			"tags": DefaultLoggerOptions.Tags,
		})
	}
	return logger.Logger()
}

// RequestMiddleware is an http middleware to log http requests and responses.
func RequestMiddleware(logger zerolog.Logger, opts ...RequestMiddlewareOptions) func(next http.Handler) http.Handler {
	if len(opts) > 0 {
		return requestLoggerHandler(&requestLogger{logger}, opts[0])
	} else {
		return requestLoggerHandler(&requestLogger{logger}, DefaultRequestMiddlewareOptions)
	}
}

// RequestLogger returns a logger handler using a custom LogFormatter.
func requestLoggerHandler(f middleware.LogFormatter, opts RequestMiddlewareOptions) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			entry := f.NewLogEntry(r)
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			var buf io.ReadWriter
			if opts.ResponseBody {
				buf = newLimitBuffer(512)
				ww.Tee(buf)
			}

			t1 := time.Now()
			defer func() {
				var respBody []byte
				bytesWritten := ww.BytesWritten()
				status := ww.Status()

				// Include a portion of the response body (e.g: an error response) in the log entry
				if opts.ResponseBody && bytesWritten > 0 && status >= 400 {
					respBody, _ = ioutil.ReadAll(buf)
				}
				entry.Write(status, bytesWritten, ww.Header(), time.Since(t1), respBody)
			}()

			next.ServeHTTP(ww, middleware.WithLogEntry(r, entry))
		}
		return http.HandlerFunc(fn)
	}
}

func (l *requestLogger) NewLogEntry(r *http.Request) middleware.LogEntry {
	entry := &RequestLoggerEntry{}
	entry.Logger = l.Logger.With().Fields(requestLogFields(r, true)).Logger()
	if !DefaultLoggerOptions.Concise {
		msg := fmt.Sprintf("Request: %s %s", r.Method, r.URL.Path)
		entry.Logger.Info().Fields(requestLogFields(r, DefaultLoggerOptions.Concise)).Msgf(msg)
	}
	return entry
}

func requestLogFields(r *http.Request, concise bool) map[string]interface{} {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	requestURL := fmt.Sprintf("%s://%s%s", scheme, r.Host, r.RequestURI)

	requestFields := map[string]interface{}{
		"requestURL":    requestURL,
		"requestMethod": r.Method,
		"requestPath":   r.URL.Path,
		"userAgent":     r.UserAgent(),
		"remoteAddress": r.RemoteAddr,
		"proto":         r.Proto,
	}
	if reqID := middleware.GetReqID(r.Context()); reqID != "" {
		requestFields["requestID"] = reqID
	}

	if concise {
		return map[string]interface{}{
			"httpRequest": requestFields,
		}
	}

	requestFields["scheme"] = scheme

	if len(r.Header) > 0 {
		requestFields["header"] = headerLogField(r.Header)
	}

	return map[string]interface{}{
		"httpRequest": requestFields,
	}
}

type RequestLoggerEntry struct {
	Logger zerolog.Logger
	msg    string
}

func (l *RequestLoggerEntry) Write(status, bytes int, header http.Header, elapsed time.Duration, extra interface{}) {
	msg := fmt.Sprintf("Response: %d %s", status, statusLabel(status))
	if l.msg != "" {
		msg = fmt.Sprintf("%s - %s", msg, l.msg)
	}

	responseLog := map[string]interface{}{
		"status":  status,
		"bytes":   bytes,
		"elapsed": float64(elapsed.Nanoseconds()) / 1000000.0, // in milliseconds
	}

	if !DefaultLoggerOptions.Concise {
		// Include response header, as well for error status codes (>400) we include
		// the response body so we may inspect the log message sent back to the client.
		if status >= 400 {
			body, _ := extra.([]byte)
			responseLog["body"] = string(body)
		}
		if len(header) > 0 {
			responseLog["header"] = headerLogField(header)
		}
	}

	l.Logger.WithLevel(statusLevel(status)).Fields(map[string]interface{}{
		"httpResponse": responseLog,
	}).Msgf(msg)
}

func (l *RequestLoggerEntry) Panic(v interface{}, stack []byte) {
	stacktrace := "#"
	if DefaultLoggerOptions.JSON {
		stacktrace = string(stack)
	}

	l.Logger = l.Logger.With().
		Str("stacktrace", stacktrace).
		Str("panic", fmt.Sprintf("%+v", v)).
		Logger()

	l.msg = fmt.Sprintf("%+v", v)

	if !DefaultLoggerOptions.JSON {
		middleware.PrintPrettyStack(v)
	}
}

func headerLogField(header http.Header) map[string]string {
	headerField := map[string]string{}
	for k, v := range header {
		k = strings.ToLower(k)
		switch {
		case len(v) == 0:
			continue
		case len(v) == 1:
			headerField[k] = v[0]
		default:
			headerField[k] = fmt.Sprintf("[%s]", strings.Join(v, "], ["))
		}
		if k == "authorization" || k == "cookie" || k == "set-cookie" {
			// Redact sensitive headers
			headerField[k] = "***"
		}

		// Redact user defined sensitive headers
		for _, skip := range DefaultLoggerOptions.SkipHeaders {
			if k == skip {
				headerField[k] = "***"
				break
			}
		}
	}
	return headerField
}

func statusLevel(status int) zerolog.Level {
	switch {
	case status <= 0:
		return zerolog.WarnLevel
	case status < 400: // for codes in 100s, 200s, 300s
		return zerolog.InfoLevel
	case status >= 400 && status < 500:
		return zerolog.WarnLevel
	case status >= 500:
		return zerolog.ErrorLevel
	default:
		return zerolog.InfoLevel
	}
}

func statusLabel(status int) string {
	switch {
	case status >= 100 && status < 300:
		return "OK"
	case status >= 300 && status < 400:
		return "Redirect"
	case status >= 400 && status < 500:
		return "Client Error"
	case status >= 500:
		return "Server Error"
	default:
		return "Unknown"
	}
}

// Helper methods used by the application to get the request-scoped
// logger entry and set additional fields between handlers.
//
// This is a useful pattern to use to set state on the entry as it
// passes through the handler chain, which at any point can be logged
// with a call to .Print(), .Info(), etc.

func LogEntry(ctx context.Context) zerolog.Logger {
	entry := ctx.Value(middleware.LogEntryCtxKey).(*RequestLoggerEntry)
	return entry.Logger
}

func LogEntrySetField(ctx context.Context, key, value string) {
	if entry, ok := ctx.Value(middleware.LogEntryCtxKey).(*RequestLoggerEntry); ok {
		entry.Logger = entry.Logger.With().Str(key, value).Logger()
	}
}

func LogEntrySetFields(ctx context.Context, fields map[string]interface{}) {
	if entry, ok := ctx.Value(middleware.LogEntryCtxKey).(*RequestLoggerEntry); ok {
		entry.Logger = entry.Logger.With().Fields(fields).Logger()
	}
}

// Helper methods for manual logging by the application.

// Log logs at the specified level for the specified sender
func Log(ctx context.Context, level zerolog.Level, format string, v ...interface{}) {
	entry := ctx.Value(middleware.LogEntryCtxKey).(*RequestLoggerEntry)
	var ev *zerolog.Event

	switch level {
	case zerolog.DebugLevel:
		ev = entry.Logger.Debug()
	case zerolog.InfoLevel:
		ev = entry.Logger.Info()
	case zerolog.WarnLevel:
		ev = entry.Logger.Warn()
	default:
		ev = entry.Logger.Error()
	}

	ev.Msg(fmt.Sprintf(format, v...))
}

// Debug logs at debug level for the specified sender
func Debug(ctx context.Context, format string, v ...interface{}) {
	Log(ctx, zerolog.DebugLevel, format, v...)
}

// Info logs at info level for the specified sender
func Info(ctx context.Context, format string, v ...interface{}) {
	Log(ctx, zerolog.InfoLevel, format, v...)
}

// Warn logs at warn level for the specified sender
func Warn(ctx context.Context, format string, v ...interface{}) {
	Log(ctx, zerolog.WarnLevel, format, v...)
}

// Error logs at error level for the specified sender
func Error(ctx context.Context, format string, v ...interface{}) {
	Log(ctx, zerolog.ErrorLevel, format, v...)
}
