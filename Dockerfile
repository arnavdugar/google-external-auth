FROM golang:1.21.6-alpine3.19 as build-stage
RUN apk --update add ca-certificates
WORKDIR /app
COPY src/ ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o main main.go

FROM scratch as production-stage
COPY --from=build-stage /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build-stage /app/main /app/main
CMD [ "/app/main" ]
