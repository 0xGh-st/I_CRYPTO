package org.example;
public class JNI_I_SYM {
    public JNI_I_SYM(){};
    static{
        System.loadLibrary("JNI_I_SYM");
    }
    public native void hexdump(String title, byte[] mem);
    public native int edge_crypto_init();
    public native int edge_crypto_final();
    public native int getCipherID();
    public native long I_CIPHER_PARAMETERS_new();
    public native void I_CIPHER_PARAMETERS_free(long p_param);
    public native void init_key(byte[] key);
    public native byte[] i_enc(int p_cipherId, byte[] p_key, long p_param, byte[] p_input);
    public native byte[] i_dec(int p_cipherId, byte[] p_key, long p_param, byte[] p_input);

    public native long i_ctx_new();
    public native void i_ctx_reset(long p_context);
    public native void i_ctx_free(long p_context);
    public native void i_enc_init(long p_context, int p_cipher_id, byte[] p_key, long p_param);
    public native byte[] i_enc_update(long p_context, byte[] p_input);
    public native byte[] i_enc_final(long p_context);
    public native void i_dec_init(long p_context, int p_cipher_id, byte[] p_key, long p_param);
    public native byte[] i_dec_update(long p_context, byte[] p_input);
    public  native int i_dec_final(long p_context);
}

