FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential pkg-config libz-dev wget tar libssl-dev musl-dev libc-dev git
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y clang

COPY . /repo
WORKDIR /repo
RUN ./configure
RUN make
RUN clang++ /repo/mayhem/fuzz_get_domain_name.cpp -fsanitize=fuzzer,address -L /repo/src/libmerc/ -l:libmerc.a -lcrypto -lz -o /fuzz

FROM ubuntu:22.04 as package
COPY --from=builder /repo/src/mercury /
COPY --from=builder /fuzz /fuzz_get_domain_name
