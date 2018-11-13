#include <chrono>
#include <iostream>
#include <thread>
#include <vector>
#include "libtorrent/alert_types.hpp"
#include "libtorrent/entry.hpp"
#include "libtorrent/session.hpp"

extern "C" void dht_init() try {
    lt::settings_pack sett;
    sett.set_bool (lt::settings_pack::enable_dht, true);

    sett.set_str (lt::settings_pack::dht_bootstrap_nodes,
        // https://stackoverflow.com/a/32797766/257568
        "router.utorrent.com:6881"
        ",router.bittorrent.com:6881"
        ",dht.transmissionbt.com:6881"
        ",router.bitcomet.com:6881"
        ",dht.aelitis.com:6881");

    lt::session s (sett);
    lt::dht::dht_settings dsett;
    dsett.item_lifetime = 600;
    dsett.upload_rate_limit = 64000;
    s.set_dht_settings (dsett);
    for (;;) {
        bool is_dht_running = s.is_dht_running();
        std::cout << "dht_init:" << __LINE__ << "] is_dht_running: " << is_dht_running << std::endl;
        if (s.is_dht_running()) break;
        std::this_thread::sleep_for (std::chrono::milliseconds (100));
    }
    for (int i = 0; i < 19; ++i) {
        s.post_dht_stats();
        std::this_thread::sleep_for (std::chrono::seconds (1));

        // https://www.libtorrent.org/reference-Alerts.html
        std::vector<lt::alert*> alerts;
        s.pop_alerts (&alerts);
        for (lt::alert* a : alerts) {
            if (a->type() == lt::dht_stats_alert::alert_type) {
                auto* d = static_cast<lt::dht_stats_alert*> (a);
                std::cout << "dht_init:" << __LINE__ << "] dht_stats_alert: " << d->message() << std::endl;
            }
        }
    }
} catch (std::exception const& ex) {
    std::cerr << "dht_init] ex: " << ex.what() << std::endl;
}
