package elibpcap

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/cilium/ebpf/asm"
	"github.com/cloudflare/cbpfc"
	"github.com/ebitengine/purego"
	"golang.org/x/net/bpf"
)

const (
	MaxBpfInstructions       = 4096
	bpfInstructionBufferSize = 8 * MaxBpfInstructions
	MAXIMUM_SNAPLEN          = 262144
)

const (
	DLT_EN10MB = 1
	DLT_RAW    = 12

	PCAP_ERROR = -1

	PCAP_NETMASK_UNKNOWN = 0xffffffff
)

type StackOffset int

const (
	BpfReadKernelOffset StackOffset = -8*(iota+1) - 80
	R1Offset
	R2Offset
	R3Offset
	R4Offset
	R5Offset
	AvailableOffset
)

type pcap_t uintptr

type pcapBpfInsnStruct bpf.RawInstruction

type pcapBpfProgramStruct struct {
	BfLen   uint32
	_       uint32
	BfInsns *pcapBpfInsnStruct
}

type pcapType uintptr

var (
	pcap_open_dead func(int, int) pcapType
	pcap_close     func(pcapType)
	pcap_geterr    func(pcapType) string
	pcap_compile   func(pcapType, *pcapBpfProgramStruct, string, int, uint32) int
	pcap_freecode  func(*pcapBpfProgramStruct)
)

func findLibpcapSo() string {
	libpcapSo, _ := filepath.Glob("/usr/lib/x86_64-linux-gnu/libpcap.so*")
	if len(libpcapSo) != 0 {
		return libpcapSo[0]
	}

	return ""
}

func RegisterLibpcap(libpcapSo string) error {
	if libpcapSo == "" {
		libpcapSo = findLibpcapSo()
	}
	if libpcapSo == "" {
		return fmt.Errorf("libpcap.so not found")
	}
	if _, err := os.Stat(libpcapSo); err != nil && os.IsNotExist(err) {
		return fmt.Errorf("libpcap.so not exists: %s", libpcapSo)
	}

	libpcap, err := purego.Dlopen(libpcapSo, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return err
	}

	purego.RegisterLibFunc(&pcap_open_dead, libpcap, "pcap_open_dead")
	purego.RegisterLibFunc(&pcap_close, libpcap, "pcap_close")
	purego.RegisterLibFunc(&pcap_geterr, libpcap, "pcap_geterr")
	purego.RegisterLibFunc(&pcap_compile, libpcap, "pcap_compile")
	purego.RegisterLibFunc(&pcap_freecode, libpcap, "pcap_freecode")

	return nil
}

func CompileEbpf(expr string, opts Options) (insts asm.Instructions, err error) {
	if expr == "__reject_all__" {
		return asm.Instructions{
			asm.Mov.Reg(asm.R4, asm.R5), // r4 = r5 (data = data_end)
		}, nil
	}
	cbpfInsts, err := CompileCbpf(expr, opts.L2Skb)
	if err != nil {
		return
	}

	ebpfInsts, err := cbpfc.ToEBPF(cbpfInsts, cbpfc.EBPFOpts{
		PacketStart: asm.R4,
		PacketEnd:   asm.R5,
		Result:      opts.result(),
		ResultLabel: opts.resultLabel(),
		Working:     [4]asm.Register{asm.R0, asm.R1, asm.R2, asm.R3},
		LabelPrefix: opts.labelPrefix(),
		StackOffset: -int(AvailableOffset),
	})
	if err != nil {
		return
	}

	return adjustEbpf(ebpfInsts, opts)
}

func CompileCbpf(expr string, l2 bool) (insts []bpf.Instruction, err error) {
	if len(expr) == 0 {
		return
	}

	if pcap_open_dead == nil {
		if err := RegisterLibpcap(""); err != nil {
			return nil, err
		}
	}

	pcapType := DLT_RAW
	if l2 {
		pcapType = DLT_EN10MB
	}
	pcap := pcap_open_dead(pcapType, MAXIMUM_SNAPLEN)
	if pcap == 0 {
		return nil, fmt.Errorf("failed to pcap_open_dead: %+v\n", PCAP_ERROR)
	}
	defer pcap_close(pcap)

	var bpfProg pcapBpfProgramStruct
	if pcap_compile(pcap, &bpfProg, expr, 1, PCAP_NETMASK_UNKNOWN) < 0 {
		return nil, fmt.Errorf("failed to pcap_compile '%s': %+v", expr, pcap_geterr(pcap))
	}
	defer pcap_freecode(&bpfProg)

	for _, v := range (*[bpfInstructionBufferSize]pcapBpfInsnStruct)(unsafe.Pointer(bpfProg.BfInsns))[0:bpfProg.BfLen:bpfProg.BfLen] {
		insts = append(insts, bpf.RawInstruction(v).Disassemble())
	}
	return
}

func adjustEbpf(insts asm.Instructions, opts Options) (newInsts asm.Instructions, err error) {
	if !opts.DirectRead {
		replaceIdx := []int{}
		replaceInsts := map[int]asm.Instructions{}
		for idx, inst := range insts {
			if inst.OpCode.Class().IsLoad() {
				replaceIdx = append(replaceIdx, idx)
				replaceInsts[idx] = append(replaceInsts[idx],

					asm.StoreMem(asm.RFP, int16(R1Offset), asm.R1, asm.DWord),
					asm.StoreMem(asm.RFP, int16(R2Offset), asm.R2, asm.DWord),
					asm.StoreMem(asm.RFP, int16(R3Offset), asm.R3, asm.DWord),

					asm.Mov.Reg(asm.R1, asm.RFP),
					asm.Add.Imm(asm.R1, int32(BpfReadKernelOffset)),
					asm.Mov.Imm(asm.R2, int32(inst.OpCode.Size().Sizeof())),
					asm.Mov.Reg(asm.R3, inst.Src),
					asm.Add.Imm(asm.R3, int32(inst.Offset)),
					asm.FnProbeReadKernel.Call(),

					asm.LoadMem(inst.Dst, asm.RFP, int16(BpfReadKernelOffset), inst.OpCode.Size()),

					asm.LoadMem(asm.R4, asm.RFP, int16(R4Offset), asm.DWord),
					asm.LoadMem(asm.R5, asm.RFP, int16(R5Offset), asm.DWord),
				)

				restoreInsts := asm.Instructions{
					asm.LoadMem(asm.R1, asm.RFP, int16(R1Offset), asm.DWord),
					asm.LoadMem(asm.R2, asm.RFP, int16(R2Offset), asm.DWord),
					asm.LoadMem(asm.R3, asm.RFP, int16(R3Offset), asm.DWord),
				}

				switch inst.Dst {
				case asm.R1, asm.R2, asm.R3:
					restoreInsts = append(restoreInsts[:inst.Dst-1], restoreInsts[inst.Dst:]...)
				}

				replaceInsts[idx] = append(replaceInsts[idx], restoreInsts...)
				replaceInsts[idx][0].Metadata = inst.Metadata
			}
		}

		for i := len(replaceIdx) - 1; i >= 0; i-- {
			idx := replaceIdx[i]
			insts = append(insts[:idx], append(replaceInsts[idx], insts[idx+1:]...)...)
		}

		insts = append([]asm.Instruction{
			asm.StoreMem(asm.RFP, int16(R4Offset), asm.R4, asm.DWord),
			asm.StoreMem(asm.RFP, int16(R5Offset), asm.R5, asm.DWord),
		}, insts...)
	}

	return append(insts,
		asm.Mov.Imm(asm.R1, 0).WithSymbol(opts.resultLabel()),
		asm.Mov.Imm(asm.R2, 0),
		asm.Mov.Imm(asm.R3, 0),
		asm.Mov.Reg(asm.R4, opts.result()),
		asm.Mov.Imm(asm.R5, 0),
	), nil
}
