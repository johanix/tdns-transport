/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Router middleware that is not tied to a role: logging and metrics.
 *
 * Authorization, signature verification and decryption are not middleware
 * (cleanup plan, step 1): they happen in ChunkNotifyHandler.RouteViaRouter,
 * before the router is entered, so that a message is refused before any
 * cryptography and decrypted with the claimed sender's key only. A router
 * is a verb table plus what is here, the stats middleware, the response
 * wrapper and the callback wrapper.
 */

package transport

// newLoggingMiddleware creates middleware for request/response logging.
func newLoggingMiddleware(verbose bool) MiddlewareFunc {
	return func(ctx *MessageContext, next MessageHandlerFunc) error {
		if verbose {
			lgTransport().Debug("processing message", "source", ctx.RemoteAddr, "peer", ctx.PeerID, "distrib", ctx.DistributionID)
		}

		err := next(ctx)

		if verbose {
			if err != nil {
				lgTransport().Debug("message processing failed", "err", err)
			} else {
				lgTransport().Debug("message processed successfully")
			}
		}

		return err
	}
}

// newMetricsMiddleware creates middleware that counts handled messages
// through the given collector.
func newMetricsMiddleware(collector interface {
	RecordMetric(name string, value float64)
}) MiddlewareFunc {
	return func(ctx *MessageContext, next MessageHandlerFunc) error {
		err := next(ctx)

		if collector != nil {
			if err != nil {
				collector.RecordMetric("message.errors", 1)
			} else {
				collector.RecordMetric("message.success", 1)
			}
		}

		return err
	}
}
