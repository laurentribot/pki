FROM golang:1.10 as builder

ADD https://github.com/golang/dep/releases/download/v0.5.0/dep-linux-amd64 /usr/bin/dep
RUN chmod +x /usr/bin/dep

WORKDIR /go/src/pki
COPY Gopkg.toml Gopkg.lock ./
RUN dep ensure --vendor-only

COPY . ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o pki cmd/pki.go

FROM scratch
COPY --from=builder /go/src/pki/pki /bin/pki
EXPOSE 8080
VOLUME /etc/pki
ENTRYPOINT ["/bin/pki"]
