import sys

from bcc import BPF

if len(sys.argv) != 2:
    print("Usage: sudo python xdp-tracer.py [file name]")
    exit(1)

file_name = sys.argv[1]
function_name = 'xdp_filter'

device = "enp0s25"

# load BPF program
print('Loading bpf program')
bpf = BPF(src_file=file_name)

fn = bpf.load_func(function_name, BPF.XDP)

bpf.attach_xdp(device, fn, 0)

print("Following traceprint, hit CTRL+C to stop and remove")
try:
    bpf.trace_print()
except KeyboardInterrupt:
    print("\nRemoving filter from device")
    bpf.remove_xdp(device, 0)
