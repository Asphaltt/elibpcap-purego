# elibpcap

`elibpcap` is a Go library to inject pcap-filter expressions to bpf prog.

> This is a [purego](github.com/ebitengine/purego) version to call libpcap's C
> functions. It is not a wrapper of libpcap.
>
> Then, with `purego`, it is possible to build without CGO.

## Usage

For example, here is the stub function in bpf code:

```c
static __noinline bool
filter_pcap_ebpf_l2(void *_skb, void *__skb, void *___skb, void *data, void* data_end)
{
    return data != data_end && _skb == __skb && __skb == ___skb;
}
```

Then, use `elibpcap` to inject the pcap-filter expression:

```go
    specTc, err := loadTcDump()
    if err != nil {
        log.Fatalf("Failed to load bpf spec: %v", err)
    }

    progSpec := specTc.Programs["on_ingress"]
    progSpec.Instructions, err = elibpcap.Inject(flags.PcapFilterExpr,
        progSpec.Instructions, elibpcap.Options{
            AtBpf2Bpf:  "filter_pcap_ebpf_l2",
            DirectRead: true,
            L2Skb:      true,
        })
```

P.S. Import "github.com/jschwinger233/elibpcap" and `go mod edit -replace=github.com/jschwinger233/elibpcap@latest=github.com/Asphaltt/elibpcap-purego@latest && go mod tidy` to use this library.
