working = 'if (tcp != NULL && ip != NULL && htons(tcp->source) == 443) bpf_trace_printk("%u\n",htons(tcp->source));'
not_working = 'if (tcp != NULL && ip != NULL && htons(tcp->source) == 433) bpf_trace_printk("%u\n",htons(tcp->source));'

if __name__ == '__main__':
    for (i, c) in enumerate(working):
        if c != not_working[i]:
            print('Error at %s, after"%s"' % (i, working[:i]))
