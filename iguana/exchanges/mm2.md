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

## Purely functional core

One of our goals is to make the MarketMaker 2 more
[stable and reliable](https://softwareengineering.stackexchange.com/questions/158054/stability-vs-reliability).
We want it to crash less often.
If there was a failure, we want to simplify and preferably automate recovery.
And we want to reduce the time between a failure and a fix.

We'll make a big step towards these goals if the core of the MarketMaker is purely functional.
That is, if we can untangle the *state* of the MarketMaker from the code operating on that state.

The benefits we want to reap from this are:
* Transparency. Some bugs are hard to fix because we don't have enough information about them. We might be lucky to have been running the program in a debugger or finding the necessary bits it verbose logs, but more often than not this is not the case: we know that a failure has happened, but have no idea where and on what input. Separating the state from the code allows the state to be easily shared with a developer, which means much faster roundtrips between discovering a failure and fixing it.
* Replayability. Having a separate state allows us to easily replay any operation. If a failure occured in the middle of a transaction, it should be possible to try a new version of the code without manually repeating all the steps that were necessary to initiate the transaction. And the updated code will run exactly on the failing transaction, not on some other transaction initiated at a later time, which means that users will benefit from less friction and developers will have a better chance to fix the hard-to-reproduce bugs.
* Testability. Stateless code is much easier to test and according to Kent Beck is often a natural result of a Test-Driven development process.
* Portability. Separating the state from the code allows us to more easily use the stateless parts from the sandboxed environments, such as when running under the Web Assembly (WASM). We only need to port the state-managing layer, fully reusing the stateless code.
* Hot reloading. When the code is separated from state, it's trivial to reload it, both with the shared libraries in CPU-native environments (dlopen) and with WASM in GUI environments. This might positively affect the development cycle, reducing the round-trip time from a failure to a fix.

Implementation might consist of two layers.
A layer that is ported to the host environment (native, JS, Java, Objective-C, cross-compiled Raspberry Pi 3, etc) and implements the TCP/IP communication, state management, hot reloading all, things that won't fit into the WASM sandbox.
And a layer that implements the core logic in a stateless manner and which is compiled into a native shared library or WASM.

Parts of the state might be marked as sensitive.
This will give the users an option to share only the information that can be freely shared,
without a risk of loosing money that is.
Even without the sensitive information a state snapshot might provide the developer with enough data to quickly triage and/or fix the failure, therefore improving the roundtrip time before a failure and a fix.
Plus users will more easily share their problems when it's quick, automatic and doesn't pose a monetary risk.

The feasibility of this approach is yet to be evaluated, but we can move gradually towards it
by separating the code into the stateful and stateless layers while working on the basic Rust port.