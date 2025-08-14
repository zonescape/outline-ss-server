FROM --platform=$BUILDPLATFORM golang:1.24.6-alpine3.22 AS builder

ARG TARGETOS
ARG TARGETARCH

COPY outline-ss-server /go/src/outline-ss-server

WORKDIR /go/src/outline-ss-server

ENV \
    CGO_ENABLED=0 \
    GOWORK=off

RUN \
    version="$(go list -m -f '{{ .Version }}' github.com/Jigsaw-Code/outline-ss-server)" && \
    echo "version=$version" && \
	GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags "-X main.version=${version} -s -w" -o outline-ss-server ./vendor/github.com/Jigsaw-Code/outline-ss-server/cmd/outline-ss-server

COPY keygen /go/src/keygen

WORKDIR /go/src/keygen

RUN \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags "-s -w" -o keygen


# final image
FROM alpine:3.22.1

RUN apk add --no-cache --update tzdata

RUN adduser -s /bin/sh -D -u 1001 app

COPY --from=builder /go/src/outline-ss-server/outline-ss-server /srv
RUN ln -s /srv/outline-ss-server /usr/bin/outline-ss-server

COPY --from=builder /go/src/keygen/keygen /srv
RUN ln -s /srv/keygen /usr/bin/keygen

USER app

WORKDIR /srv
