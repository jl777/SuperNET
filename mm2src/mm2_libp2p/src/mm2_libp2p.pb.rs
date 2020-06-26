#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MakerOrderKeepAlive {
    #[prost(bytes, tag="1")]
    pub uuid: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MakerOrder {
    #[prost(bytes, tag="1")]
    pub uuid: std::vec::Vec<u8>,
    #[prost(string, tag="2")]
    pub base_ticker: std::string::String,
    #[prost(string, tag="3")]
    pub rel_ticker: std::string::String,
    #[prost(uint32, repeated, tag="4")]
    pub price_numer: ::std::vec::Vec<u32>,
    #[prost(uint32, repeated, tag="5")]
    pub price_denom: ::std::vec::Vec<u32>,
    #[prost(uint32, repeated, tag="6")]
    pub max_volume_numer: ::std::vec::Vec<u32>,
    #[prost(uint32, repeated, tag="7")]
    pub max_volume_denom: ::std::vec::Vec<u32>,
    #[prost(uint32, repeated, tag="8")]
    pub min_volume_numer: ::std::vec::Vec<u32>,
    #[prost(uint32, repeated, tag="9")]
    pub min_volume_denom: ::std::vec::Vec<u32>,
    #[prost(uint32, tag="10")]
    pub base_confs: u32,
    #[prost(uint32, tag="11")]
    pub rel_confs: u32,
    #[prost(bool, tag="12")]
    pub base_nota: bool,
    #[prost(bool, tag="13")]
    pub rel_nota: bool,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignedMessage {
    #[prost(bytes, tag="1")]
    pub pubkey: std::vec::Vec<u8>,
    #[prost(bytes, tag="2")]
    pub signature: std::vec::Vec<u8>,
    #[prost(bytes, tag="3")]
    pub payload: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ForTest {
    #[prost(bytes, tag="1")]
    pub payload: std::vec::Vec<u8>,
}
