#include <chrono>
#include <cstdint>
#include <functional>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <thread>
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
    return strdup (alert->message().c_str());
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

/*
    for (;;) {

        std::this_thread::sleep_for (std::chrono::milliseconds (100));
    }

    std::array<char, 32> seed;
    std::random_device rd;
    std::default_random_engine rng (rd());
    std::uniform_int_distribution<std::default_random_engine::result_type> dist
        ((std::default_random_engine::result_type) CHAR_MIN, (std::default_random_engine::result_type) CHAR_MAX);
    for (char& ch : seed) ch = (char) dist (rng);
	lt::dht::public_key pk;
    lt::dht::secret_key sk;
    std::tie (pk, sk) = lt::dht::ed25519_create_keypair (seed);

    for (int i = 0; i < 55; ++i) {
        dugout->session->post_dht_stats();

        if (i < 9) {
            std::stringstream salt; salt << i;
            std::string salt_copy = salt.str();
            dugout->session->dht_put_item (
                pk.bytes,
                [salt_copy, pk, sk] (lt::entry& en, std::array<char, 64>& sig, std::int64_t& seq, std::string const&) {
                    en = "foobar";
                    std::vector<char> buf;
                    lt::bencode (std::back_inserter (buf), "foobar");
                    lt::dht::signature sign;
                    ++seq;
                    sign = lt::dht::sign_mutable_item (buf, salt_copy, lt::dht::sequence_number (seq), pk, sk);
                    sig = sign.bytes;
                },
                salt.str());
        }

        std::this_thread::sleep_for (std::chrono::seconds (1));

        if ((i > 9 && i < 19) || (i > 19 && i < 29)) {
            std::stringstream salt; salt << (i > 19 ? i - 20 : i - 10);
            dugout->session->dht_get_item (pk.bytes, salt.str());
        }

        // https://www.libtorrent.org/reference-Alerts.html
        std::vector<lt::alert*> alerts;
        dugout->session->pop_alerts (&alerts);
        for (lt::alert* a : alerts) {
            if (a->type() == lt::dht_stats_alert::alert_type) {
                auto* dsa = static_cast<lt::dht_stats_alert*> (a);
                std::cout << "dht_init:" << __LINE__ << "] dht_stats_alert: " << dsa->message() << std::endl;
            } else if (a->type() == lt::dht_put_alert::alert_type) {
                auto* dpa = static_cast<lt::dht_put_alert*> (a);
                std::cout << "dht_init:" << __LINE__ << "] dht_put_alert: " << dpa->message() << std::endl;
            } else if (a->type() == lt::dht_mutable_item_alert::alert_type) {
                auto* dmi = static_cast<lt::dht_mutable_item_alert*> (a);
                std::cout << "dht_init:" << __LINE__ << "] dht_mutable_item_alert: " << dmi->message() << "; val: " << dmi->item.to_string() << std::endl;
            }
        }
    }
    */
