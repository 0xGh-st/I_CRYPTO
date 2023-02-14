void hexdump(const char *title, void *mem, unsigned int len){
    unsigned int i = 0;
    unsigned int j = 0;

    fprintf(stdout, "-[%s](%d)\n", title, len);

    for (i = 0; i<len + ((len % 16) ? (16 - len % 16) : 0); i++){
        // print offset
        if (i % 16 == 0)
            printf("0x%08X: ", i);
        // print hex data
        if (i<len)
            printf("%02X ", 0xFF & ((char*)mem)[i]);
        else
            printf("   ");
        // print ascii dump
        if (i % 16 == (16 - 1)){
            for (j = i - (16 - 1); j <= i; j++){
                if (j >= len)
                    putchar(' ');
                else if ((((char*)mem)[j] >= 32) && (((char*)mem)[j] <= 126))
                    putchar(0xFF & ((char*)mem)[j]);
                else
                    putchar('.');
            }
            putchar('\n');
        }
    }  // for
    puts("");
}
