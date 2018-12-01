#include <algorithm>
#include <cassert>
#include <cstdint>
#include <functional>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <string.h>  // strdup
#include "libtorrent/alert_types.hpp"
#include "libtorrent/bencode.hpp"
#include "libtorrent/entry.hpp"
#include "libtorrent/kademlia/ed25519.hpp"
#include "libtorrent/kademlia/item.hpp"
#include "libtorrent/session.hpp"

/// A common context shared between the functions and tracked on the Rust side.
struct dugout_struct_t {
    char const* err;
    /// cf. https://www.libtorrent.org/reference-Settings.html
    lt::settings_pack* sett;
    lt::session* session;
};
typedef struct dugout_struct_t dugout_t;

extern "C" char const* delete_dugout (dugout_t* dugout) try {
    if (dugout->session) {delete dugout->session; dugout->session = nullptr;}
    if (dugout->sett) {delete dugout->sett; dugout->sett = nullptr;}
    if (dugout->err) {free ((void*) dugout->err); dugout->err = nullptr;}
    return nullptr;
} catch (std::exception const& ex) {
    return strdup (ex.what());
}

extern "C" dugout_t dht_init (char const* listen_interfaces) {
    dugout_t dugout = {};

    try {
        lt::settings_pack* sett = dugout.sett = new lt::settings_pack;
        sett->set_bool (lt::settings_pack::enable_dht, false);
        sett->set_int (lt::settings_pack::alert_mask, 0x7fffffff);
        sett->set_str (lt::settings_pack::listen_interfaces, listen_interfaces);

        sett->set_str (lt::settings_pack::dht_bootstrap_nodes,
            // https://stackoverflow.com/a/32797766/257568
            "router.utorrent.com:6881"
            ",router.bittorrent.com:6881"
            ",dht.transmissionbt.com:6881"
            ",router.bitcomet.com:6881"
            ",dht.aelitis.com:6881");

        lt::session* session = dugout.session = new lt::session (*sett);

        lt::dht::dht_settings dsett;
        dsett.item_lifetime = 600;
        dsett.upload_rate_limit = 64000;
        session->set_dht_settings (dsett);
    } catch (std::exception const& ex) {
        dugout.err = strdup (ex.what());
    }
    return dugout;
}

extern "C" void enable_dht (dugout_t* dugout) try {
    if (!dugout->sett || !dugout->session) throw std::runtime_error ("Not initialized");
	dugout->sett->set_bool (lt::settings_pack::enable_dht, true);
	dugout->session->apply_settings (*dugout->sett);
} catch (std::exception const& ex) {
    dugout->err = strdup (ex.what());
}

extern "C" void dht_alerts (dugout_t* dugout, void (*cb) (void*, lt::alert*), void* cbctx) try {
    std::vector<lt::alert*> alerts;
    dugout->session->pop_alerts (&alerts);
    for (lt::alert* a : alerts) cb (cbctx, a);
} catch (std::exception const& ex) {
    dugout->err = strdup (ex.what());
}

extern "C" char const* alert_message (lt::alert const* alert) {
    std::ostringstream ss;
    ss << alert->type() << " (" << alert->what() << ") " << alert->message();
    return strdup (ss.str().c_str());
}

extern "C" bool is_dht_bootstrap_alert (lt::alert const* alert) {
    return alert->type() == lt::dht_bootstrap_alert::alert_type;
}

template <class A>
char const* endpoint_format (A const* alert) {
    std::ostringstream ss;
    ss << alert->address.to_string() << ':' << alert->port;
    if (alert->socket_type == lt::socket_type_t::tcp || alert->socket_type == lt::socket_type_t::tcp_ssl) ss << "@tcp";
    else if (alert->socket_type == lt::socket_type_t::udp) ss << "@udp";
    return strdup (ss.str().c_str());
}

extern "C" char const* as_listen_succeeded_alert (lt::alert const* alert) {
    if (alert->type() == lt::listen_succeeded_alert::alert_type)
        return endpoint_format (static_cast<lt::listen_succeeded_alert const*> (alert));
    return nullptr;
}

extern "C" char const* as_listen_failed_alert (lt::alert const* alert) {
    if (alert->type() == lt::listen_failed_alert::alert_type)
        return endpoint_format (static_cast<lt::listen_failed_alert const*> (alert));
    return nullptr;
}

extern "C" int32_t as_dht_mutable_item_alert (
    lt::alert const* alert,
    uint8_t* pkbuf, int32_t pkbuflen,
    int8_t* saltbuf, int32_t saltbuflen,
    uint8_t* buf, int32_t buflen,
    int64_t* seq, bool* auth
) {
    if (alert->type() != lt::dht_mutable_item_alert::alert_type) return 0;
    auto mia = static_cast<lt::dht_mutable_item_alert const*> (alert);

    *seq = mia->seq;
    *auth = mia->authoritative;

    // NB: This is not the `seed` but rather the public key generated from it with `ed25519_create_keypair`.
    assert (pkbuflen == 32);
    assert (pkbuflen == mia->key.size());
    std::copy (mia->key.begin(), mia->key.end(), pkbuf);

    if (mia->salt.size() + 1 > saltbuflen) return -1;
    std::copy (mia->salt.begin(), mia->salt.end(), saltbuf);
    saltbuf[mia->salt.size()] = 0;

    std::vector<char> v;
    lt::bencode (std::back_inserter (v), mia->item);
    if (v.size() > buflen) return -2;
    std::copy (v.begin(), v.end(), buf);
    return (int32_t) v.size();
}

extern "C" void dht_put (dugout_t* dugout,
                         uint8_t const* key, int32_t keylen,
                         uint8_t const* salt_c, int32_t saltlen,
                         void (*callback) (void*, uint64_t, uint8_t*, int32_t, uint8_t**, int32_t*, int64_t*), void* arg, uint64_t arg2) {
    assert (key != nullptr);
    assert (keylen == 32);
    assert (salt_c != nullptr);
    assert (callback != nullptr);

    std::array<char, 32> seed;
    std::copy (key, key + keylen, seed.begin());

	lt::dht::public_key pk;
    lt::dht::secret_key sk;
    std::tie (pk, sk) = lt::dht::ed25519_create_keypair (seed);

    std::string salt ((char const*) salt_c, saltlen);

    dugout->session->dht_put_item (
        pk.bytes,
        [salt, pk, sk, callback, arg, arg2] (lt::entry& en, std::array<char, 64>& sig, std::int64_t& seq, std::string const&) {
            std::vector<char> have;
            lt::bencode (std::back_inserter (have), en);

            uint8_t* benload; int32_t benlen;
            callback (arg, arg2, (uint8_t*) have.data(), (int32_t) have.size(), &benload, &benlen, &seq);

            // NB: It might be important to use a new `lt::entry` instance here, `en = lt::bdecode` appends.
            //     (TODO: Should double-check it, I suspect the duplication/appending might happen on some DHT nodes instead).
            lt::entry new_entry = lt::bdecode (benload, benload + benlen);
            lt::span<char> benspan ((char*) benload, (std::size_t) benlen);
            en = new_entry;

            lt::dht::signature sign;
            sign = lt::dht::sign_mutable_item (benspan, salt, lt::dht::sequence_number (seq), pk, sk);
            sig = sign.bytes;
        },
        salt);
}

// TODO: Return the public key from the `dht_get` instead.
extern "C" void dht_seed_to_public_key (
    uint8_t const* key, int32_t keylen,
    uint8_t* pkbuf, int32_t pkbuflen
) {
    assert (keylen == 32);
    assert (pkbuflen == 32);

    std::array<char, 32> seed;
    std::copy (key, key + keylen, seed.begin());

	lt::dht::public_key pk;
    lt::dht::secret_key sk;
    std::tie (pk, sk) = lt::dht::ed25519_create_keypair (seed);

    assert (pk.bytes.size() == 32);
    std::copy (pk.bytes.begin(), pk.bytes.end(), pkbuf);
}

extern "C" void dht_get (dugout_t* dugout,
                         uint8_t const* key, int32_t keylen,
                         uint8_t const* salt_c, int32_t saltlen) {
    assert (keylen == 32);
    assert (salt_c != nullptr);

    std::array<char, 32> seed;
    std::copy (key, key + keylen, seed.begin());

	lt::dht::public_key pk;
    lt::dht::secret_key sk;
    std::tie (pk, sk) = lt::dht::ed25519_create_keypair (seed);

    std::string salt ((char const*) salt_c, saltlen);

    dugout->session->dht_get_item (pk.bytes, salt);
}
