package logger

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/rs/zerolog"
)

type RequestMiddlewareOptions struct {
	// ResponseBody enables the inclusion of a portion of the response body in the log entry
	ResponseBody bool

	// SkipHeaders are additional headers which are redacted from the logs
	SkipHeaders []string
}

type requestLogger struct {
	// Logger refers to the zerolog logging object
	Logger zerolog.Logger
}

var DefaultRequestMiddlewareOptions = RequestMiddlewareOptions{
	ResponseBody: false,
	SkipHeaders:  nil,
}

// RequestMiddleware is an http middleware to log http requests and responses.
func RequestMiddleware(logger zerolog.Logger, opts ...RequestMiddlewareOptions) func(next http.Handler) http.Handler {
	if len(opts) > 0 {
		return requestLoggerHandler(&requestLogger{logger}, opts[0])
	}
	return requestLoggerHandler(&requestLogger{logger}, DefaultRequestMiddlewareOptions)
}

// LogFormatter initiates the beginning of a new LogEntry per request.
// See DefaultLogFormatter for an example implementation.
type LogFormatter interface {
	NewLogEntry(r *http.Request) LogEntry
}

// LogEntry records the final log when a request completes.
// See defaultLogEntry for an example implementation.
type LogEntry interface {
	Write(status, bytes int, header http.Header, elapsed time.Duration, extra interface{})
	Panic(v interface{}, stack []byte)
}

// RequestLogger returns a logger handler using a custom LogFormatter.
func requestLoggerHandler(f LogFormatter, opts RequestMiddlewareOptions) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			entry := f.NewLogEntry(r)
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			next.ServeHTTP(ww, r)

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
		}
		return http.HandlerFunc(fn)
	}
}

func (l *requestLogger) NewLogEntry(r *http.Request) LogEntry {
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
