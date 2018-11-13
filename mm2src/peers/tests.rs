
pub fn test_dht() {
    extern "C" {fn dht_init();}
    unsafe {dht_init()}
}
