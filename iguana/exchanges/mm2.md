# Market Maker 2

This document will help us track the information related to the MarketMaker Rust rewrite.

## Rewrite goals

Rewrites and ports
[are costly](http://nibblestew.blogspot.com/2017/04/why-dont-you-just-rewrite-it-in-x.html).
We tend to think that porting is simple, and on some level this intuition is true
because we can skip some high-level design decisions and focus on translating the existing logic,
but it still takes a lot of time
and though we don't need to make some of the new design decisions,
we might spend no less effort to reverse-engineer and understand the old ones.

So why the rewrite then?

Carol, in her talk about rewrites, offers some possible reasons:

"*If* you have some code in C or another language, and need to change it, or it’s slow, or it crashes a
lot, or no one understands it anymore, THEN maybe a rewrite in Rust would be a good fit.
I would also posit that more people are *able* to write production Rust than production C, so if your
team *is* willing to learn Rust, it might actually expand the number of
maintainers." - https://github.com/carols10cents/rust-out-your-c-talk, https://www.youtube.com/watch?v=SKGVItFlK3w.

And we have some of these:

* We *need to change* the MarketMaker: A more approachable and reliable API. Ability to embed the MarketMaker in the GUI applications. Ways to more easily deploy it at home by running it from small computers like on a spare mobile phone or on a Raspberry Pi 3.

* The MarketMaker *crashes a lot*, to quote hyperDEX: "The biggest issue with the MM right now, is bobs crash or does not have the orders in users orderbook, or when users try to do a order it doesnt work or goes unmatched or other random stuff". And we want it to be stable and reliable instead.
