FROM alpine:3.21
RUN apk add --no-cache tcpreplay
USER 65532:65532
ENTRYPOINT ["tcpreplay"]
