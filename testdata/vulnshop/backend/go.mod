module example.com/vulnshop

go 1.22

require github.com/getsentry/sentry-go v0.0.0

replace github.com/getsentry/sentry-go => ./stubs/sentry-go
