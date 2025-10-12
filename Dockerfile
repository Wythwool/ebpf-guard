FROM golang:1.22 as build
WORKDIR /src
COPY . .
RUN make all

FROM debian:stable-slim
RUN apt-get update && apt-get install -y bpftool ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/bin/ebpf-guard /usr/local/bin/ebpf-guard
COPY --from=build /src/configs/rules.sample.yaml /etc/ebpf-guard/rules.yaml
EXPOSE 9108
ENTRYPOINT ["/usr/local/bin/ebpf-guard","-prom","-json","-rules","/etc/ebpf-guard/rules.yaml"]
