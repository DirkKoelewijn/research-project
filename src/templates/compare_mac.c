static int compare_mac(unsigned char mac[], unsigned char c0, unsigned char c1, unsigned char c2, unsigned char c3, unsigned char c4, unsigned char c5){
    unsigned char other[6] = {c0, c1, c2, c3, c4, c5};
    int i, r;
    for(i=0;i<6;i++){
        r = mac[i] - other[i];
        if (r != 0) return r;
    }
    return 0;
}