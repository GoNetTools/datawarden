module example.com/ruleexamples

go 1.22

require (
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
