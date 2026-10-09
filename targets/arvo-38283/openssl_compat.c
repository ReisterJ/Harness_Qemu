/* OpenSSL 3 removed FIPS_mode(); this target image is not FIPS-enabled. */
int FIPS_mode(void) { return 0; }
