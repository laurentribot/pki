FROM golang:1.10 as build
WORKDIR /go/src/pki
ADD . /go/src/pki
RUN go get -d -v ./...
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o pki cmd/pki.go

FROM scratch
WORKDIR /root/
COPY --from=build /go/src/pki/pki .
expose 80
CMD ["./pki"]
