import sys

from bcc import BPF

Device = "enp0s25"
Function = 'xdp_filter'


def analyze(file, func=Function, dev=Device):
    result = {'TP': 0, 'TN': 0, 'FP': 0, 'FN': 0, 'UP': 0, 'UN': 0}
    keywords = dict([('$%s$' % k, k) for k in result.keys()])

    # load BPF program
    print('Loading bpf program')
    bpf = BPF(src_file=file)

    fn = bpf.load_func(func, BPF.XDP)

    bpf.attach_xdp(dev, fn, 0)

    print("Following traceprint, hit CTRL+C to stop and remove")
    try:
        while True:
            line = str(bpf.trace_readline(nonblocking=False))
            for k in keywords:
                if k in line:
                    result[keywords[k]] += 1
                    continue
    except KeyboardInterrupt:
        print("\nInterrupted")
    finally:
        print("Removing filter from device")
        bpf.remove_xdp(dev, 0)

    return result


def print_analysis(analysis: dict, simple=False):
    if not simple:
        print('--- ANALYSIS RESULTS ---\n')
        all_packets = sum(analysis.values())
        print('Packets captured:', all_packets)
        classified_packets = sum([v for k, v in analysis.items() if not k.startswith('U')])
        print('of which classified:', classified_packets)

        tpr = analysis['TP'] / (analysis['TP'] + analysis['FN'])
        tnr = analysis['TN'] / (analysis['TN'] + analysis['FP'])
        ppv = analysis['TP'] / (analysis['TP'] + analysis['FP'])
        npv = analysis['TN'] / (analysis['TN'] + analysis['FN'])
        accuracy = (analysis['TP'] + analysis['TN']) / classified_packets

        table_line = '%-20s | %-20s | %-20s | %-20s'

        print()
        print(table_line % ('', 'Actually positive', 'Actually negative', 'Predictive value'))
        print(table_line % ('-' * 20, '-' * 20, '-' * 20, '-' * 20))
        print(table_line % ('Class. positive', analysis['TP'], analysis['FP'], ppv))
        print(table_line % ('Class. negative', analysis['FN'], analysis['TN'], npv))
        print(table_line % ('True rate', tpr, tnr, ''))
        print()

        print('Accuracy: ', accuracy)
        print('\n--- END OF ANALYSIS ---')

    else:
        table_line = '%-10d | %-10d | %-10d'
        print(table_line % (analysis['TP'], analysis['FP'], analysis['UP']))
        print(table_line % (analysis['FN'], analysis['TN'], analysis['UN']))


def load(file, func=Function, dev=Device):
    data = None
    # load BPF program
    print('Loading bpf program')
    bpf = BPF(src_file=file)

    fn = bpf.load_func(func, BPF.XDP)

    bpf.attach_xdp(dev, fn, 0)

    print("Following traceprint, hit CTRL+C to stop and remove")
    try:
        bpf.trace_print()
    except KeyboardInterrupt:
        print("\nInterrupted")
    finally:
        print("Removing filter from device")
        bpf.remove_xdp(dev, 0)

    return data


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: sudo python xdp-tracer.py [file name]")
        exit(1)

    file_name = sys.argv[1]
    a = analyze(file_name)
    print_analysis(a)
