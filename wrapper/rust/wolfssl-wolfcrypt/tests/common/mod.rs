pub fn setup()
{
    #[cfg(fips)]
    {
        use wolfssl_wolfcrypt::sys;
        unsafe {
            sys::wolfCrypt_SetPrivateKeyReadEnable_fips(1, sys::wc_KeyType_WC_KEYTYPE_ALL);
        }
    }
}
