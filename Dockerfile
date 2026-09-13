FROM golang:1.27.1 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY network ./network
RUN CGO_ENABLED=0 go build -trimpath -o /unifi-go ./cmd/unifi-go
RUN mkdir -m 700 /runtime

FROM scratch
COPY --from=build /unifi-go /unifi-go
COPY --from=build /runtime /runtime
ENTRYPOINT ["/unifi-go"]
