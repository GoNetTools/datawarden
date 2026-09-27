module example.com/ruleexamples

go 1.22

require (
	github.com/honeycombio/beeline-go v0.0.0
	github.com/honeycombio/libhoney-go v0.0.0
	github.com/newrelic/go-agent/v3 v3.0.0
	go.opentelemetry.io/otel v0.0.0
	gopkg.in/DataDog/dd-trace-go.v1 v1.0.0
	github.com/gin-gonic/gin v0.0.0
	github.com/go-chi/chi/v5 v5.0.0
	github.com/labstack/echo/v4 v4.0.0
	github.com/aws/aws-sdk-go-v2/service/sns v0.0.0
	github.com/getsentry/sentry-go v0.0.0
	github.com/redis/go-redis/v9 v9.0.0
	github.com/rs/zerolog v0.0.0
	github.com/segmentio/analytics-go/v3 v3.0.0
	github.com/sirupsen/logrus v0.0.0
	github.com/twilio/twilio-go v0.0.0
	go.uber.org/zap v0.0.0
	golang.org/x/crypto v0.0.0
	gorm.io/gorm v0.0.0
)

replace (
	github.com/honeycombio/beeline-go => ../../gostubs/beeline
	github.com/honeycombio/libhoney-go => ../../gostubs/libhoney
	github.com/newrelic/go-agent/v3 => ../../gostubs/newrelic
	go.opentelemetry.io/otel => ../../gostubs/otel
	gopkg.in/DataDog/dd-trace-go.v1 => ../../gostubs/ddtrace
	github.com/gin-gonic/gin => ../../gostubs/gin
	github.com/go-chi/chi/v5 => ../../gostubs/chi
	github.com/labstack/echo/v4 => ../../gostubs/echo
	github.com/aws/aws-sdk-go-v2/service/sns => ../../gostubs/sns
	github.com/getsentry/sentry-go => ../../gostubs/sentry-go
	github.com/redis/go-redis/v9 => ../../gostubs/go-redis
	github.com/rs/zerolog => ../../gostubs/zerolog
	github.com/segmentio/analytics-go/v3 => ../../gostubs/analytics-go
	github.com/sirupsen/logrus => ../../gostubs/logrus
	github.com/twilio/twilio-go => ../../gostubs/twilio-go
	go.uber.org/zap => ../../gostubs/zap
	golang.org/x/crypto => ../../gostubs/xcrypto
	gorm.io/gorm => ../../gostubs/gorm
)
