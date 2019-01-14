import sys

from bcc import BPF

Device = "enp0s25"
Function = 'xdp_filter'


def load(file, func=Function, dev=Device):
    # load BPF program
    print('Loading bpf program')
    bpf = BPF(src_file=file)

    fn = bpf.load_func(func, BPF.XDP)

    bpf.attach_xdp(dev, fn, 0)

    print("Following traceprint, hit CTRL+C to stop and remove")
    try:
        bpf.trace_print()
    except KeyboardInterrupt:
        print("\nRemoving filter from device")
        bpf.remove_xdp(dev, 0)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: sudo python xdp-tracer.py [file name]")
        exit(1)

    file_name = sys.argv[1]
    load(file_name)
