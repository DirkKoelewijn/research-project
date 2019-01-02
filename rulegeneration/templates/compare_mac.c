static int compare_mac(unsigned char mac[], unsigned char mac1[]){
    int i, r;
    for(i=0;i<6;i++){
        r = mac[i] - mac1[i];
        if (r != 0) return r;
    }
    return 0;
}