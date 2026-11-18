FROM golang:1.22-alpine AS build-env
RUN apk add --no-cache --upgrade ca-certificates
WORKDIR /go/src/app

COPY . /go/src/app

RUN go build -o httprobe .


FROM alpine:3.19

RUN apk add shadow bash && \
    useradd --create-home --shell /sbin/nologin httprobe && \
    mkdir /httprobe && \
    chown httprobe:httprobe /httprobe

COPY --from=build-env /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build-env /go/src/app/httprobe /httprobe/httprobe


USER httprobe
WORKDIR /httprobe

ENTRYPOINT ["/httprobe/httprobe"]
