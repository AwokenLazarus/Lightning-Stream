# References

What Lightning Stream takes from other people, with a reference a reader can follow. The
whitepaper (<https://lazarus-xbt.xyz/stream/>) carries the same list under the same numbers.
Each entry was opened and read against what these texts say of it on 2026-10-12; where only an
archived copy or only part of a source was read, the entry says so. Libraries the code links,
and code and data copied into this tree, are in [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).

## What is whose

| What | Whose | Ref |
|---|---|---|
| One-way payment channels (the frozen on-chain channel) | Jeremy Spilman, 2013; the `CHECKLOCKTIMEVERIFY` form is one of BIP 65's examples | 1, 2 |
| Lightning, its channels and its routing | Joseph Poon and Tadge Dryja; the BOLTs | 3, 4 |
| Hold invoices, which a stream ticket is made of | Joost Jager, in lnd, 2019 | 5 |
| A payment the payer releases in a second step | Hiroki Gondo, "stuckless payments", 2019 (with point locks; tickets get a similar effect from hold invoices) | 6 |
| Paying a seller with no invoice (keysend, AMP), and streaming sats by the minute | Lightning developers; Podcasting 2.0 | 7, 8, 9 |
| Channel jamming and the defences proposed against it: unconditional fees, hold fees, endorsement | Shikhelman and Tikhomirov; Jager; Kirk-Cohen | 10 to 13 |
| Point locks | Poelstra's scriptless scripts; Malavolta and others | 14, 15, 16 |
| Adaptor signatures and payment hubs that cannot take the money (the retired hub) | Poelstra; Aumayr and others; Fournier; TumbleBit; A2L | 16 to 20 |
| HTTP 402, and the shape of a paid request | RFC 2068; x402 (created by Coinbase, kept by the x402 Foundation), whose `batch-settlement` name the frozen channel is carried under; L402 | 21, 22, 23 |
| Network names | CAIP-2 and the `bip122` namespace | 24 |
| A wallet that an app may spend from within limits | Nostr Wallet Connect | 25 |
| The agent's tool protocol | Model Context Protocol (Anthropic; now the Agentic AI Foundation) | 26 |
| Paying per request with ecash; one operator for many users | Cashu, Routstr; Ark | 27, 28, 29 |
| Serving a stranger one piece before it has paid | BitTorrent's optimistic unchoke (Bram Cohen) | 30 |
| Selling a key through a hash lock; Merkle proofs | Gregory Maxwell; Ralph Merkle | 31, 32 |
| Paying small amounts by lottery | David Wheeler, 1996, and Ronald Rivest, 1997; then Micali and Rivest, Pass and shelat, Chiesa and others, Mitani and Otsuka, Orchid, Livepeer; on Bitcoin, Caldwell, Dryja, Kurbatov | 33 to 43 |
| **A win that enforces itself over Lightning** | **Paul Gerhart, Jay Taylor and Sri Aravinda Krishnan Thyagarajan, May 2026. The aim is theirs first, and so is the proof that ties a hash lock to a key. Our construction differs (one locked ticket and oblivious transfer, where theirs is a paid exchange per roll built on adaptor signatures and an oblivious pseudorandom function) and, unlike theirs, has no formal treatment and no review.** | 44 |
| How pools even out a miner's income | Meni Rosenfeld | 45 |
| The parts of the sealed draw: oblivious transfer, its extension, multiplication from transfers, the proof and its curves | Chou and Orlandi; Ishai, Kilian, Nissim, Petrank; Keller, Orsini, Scholl; Roy; Gilboa; Doerner, Kondi, Lee, shelat; Groth; Electric Coin Company and Zcash; arkworks | 46 to 59 |
| XBT's consensus rules: BLAKE2b proof of work, the unified signature hash, the reduced-data rules | Bitcoin Knots: Luke Dashjr; Kyle Santiago; BIP 110 | 60 |
| Lightning on XBT, and the lab every ticket number was measured in | Lightning Fork and `lightning-fork-lab` by Paul Lamb, on lnd by Lightning Labs; the Core Lightning fork by PrivKey (not tested by us) | 61, 62, 63 |
| The Electrum server the light backend talks to; signing; pay with work | electrs (Roman Zeyde); libsecp256k1; OCEAN's DATUM and TIDES | 64, 65, 66 |

What is ours: the binding of these to one another (a hold invoice on a hash the buyer chose,
released inside an HTTP request, under an owner's signed policy), the policy wallet, the wire in
[`TICKETS.md`](TICKETS.md), the XBT binding of x402, and the way the sealed draw's parts are put
together. The last of these is unreviewed. An external review of the earlier design found
serious issues (see the README); the reviewer is not named in this tree.

## Payment channels and Lightning

1. <a id="ref-1"></a>J. Spilman. "Anti DoS for tx replacement". bitcoin-development mailing list, 20 April 2013. [archived copy](https://web.archive.org/web/20201030125710/https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2013-April/002433.html).
2. <a id="ref-2"></a>P. Todd. "BIP 65: OP_CHECKLOCKTIMEVERIFY". 2014. Its section "Payment Channels" describes "Jeremy Spilman style payment channels". [bip-0065](https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki).
3. <a id="ref-3"></a>J. Poon, T. Dryja. "The Bitcoin Lightning Network: Scalable Off-Chain Instant Payments". Draft 0.5.9.2, 14 January 2016. [lightning.network](https://lightning.network/lightning-network-paper.pdf).
4. <a id="ref-4"></a>Lightning Network developers. "BOLT: Basis of Lightning Technology". BOLT 2 (the peer protocol, and the limit of 483 pending payments in a channel), BOLT 11 (invoices), BOLT 12 (offers; R. Russell, merged 2024). [lightning/bolts](https://github.com/lightning/bolts).
5. <a id="ref-5"></a>J. Jager. "htlcswitch: hodl invoice". lnd pull request 2022, merged March 2019; released in lnd v0.6-beta, April 2019. The calls are AddHoldInvoice, SettleInvoice and CancelInvoice of lnd's invoices service. [pull request](https://github.com/lightningnetwork/lnd/pull/2022), [Optech: hold invoices](https://bitcoinops.org/en/topics/hold-invoices/).
6. <a id="ref-6"></a>H. Gondo. "Proposal for Stuckless Payment". lightning-dev mailing list, 25 June 2019. [archived copy](https://web.archive.org/web/20201107230308/https://lists.linuxfoundation.org/pipermail/lightning-dev/2019-June/002029.html).
7. <a id="ref-7"></a>O. Osuntokun, with C. Fromknecht. "AMP: Atomic Multi-Path Payments over Lightning". lightning-dev mailing list, 6 February 2018. [archived copy](https://web.archive.org/web/20201109042159/https://lists.linuxfoundation.org/pipermail/lightning-dev/2018-February/000993.html).
8. <a id="ref-8"></a>V. Wallace. "bLIP 3: Keysend". 2021. [blip-0003](https://github.com/lightning/blips/blob/master/blip-0003.md).
9. <a id="ref-9"></a>Satoshis Stream. "bLIP 10: Podcasting 2.0 Streaming payments, Boosts and Boostagrams". 2022. [blip-0010](https://github.com/lightning/blips/blob/master/blip-0010.md).
10. <a id="ref-10"></a>Bitcoin Optech. "Channel jamming attacks". Topic page. [bitcoinops.org](https://bitcoinops.org/en/topics/channel-jamming-attacks/).
11. <a id="ref-11"></a>C. Shikhelman, S. Tikhomirov. "Unjamming Lightning: A Systematic Approach". Cryptology ePrint Archive 2022/1454, 2022. [ePrint 2022/1454](https://eprint.iacr.org/2022/1454).
12. <a id="ref-12"></a>J. Jager. "Hold fee rates as DoS protection (channel spamming and jamming)". lightning-dev mailing list, 11 February 2021. [archived copy](https://web.archive.org/web/20231114193113/https://lists.linuxfoundation.org/pipermail/lightning-dev/2021-February/002958.html).
13. <a id="ref-13"></a>C. Kirk-Cohen. "bLIP 4: Experimental Endorsement Signaling". 2024. [blip-0004](https://github.com/lightning/blips/blob/master/blip-0004.md), [Optech: HTLC endorsement](https://bitcoinops.org/en/topics/htlc-endorsement/).
14. <a id="ref-14"></a>Bitcoin Optech. "Point Time Locked Contracts (PTLCs)". Topic page. See also "Multi-Hop Locks from Scriptless Scripts", Blockstream Research. [bitcoinops.org](https://bitcoinops.org/en/topics/ptlc/), [multi-hop locks](https://github.com/BlockstreamResearch/scriptless-scripts/blob/master/md/multi-hop-locks.md).
15. <a id="ref-15"></a>G. Malavolta, P. Moreno-Sanchez, C. Schneidewind, A. Kate, M. Maffei. "Anonymous Multi-Hop Locks for Blockchain Scalability and Interoperability". NDSS 2019. [ePrint 2018/472](https://eprint.iacr.org/2018/472).
16. <a id="ref-16"></a>A. Poelstra. "Scriptless Scripts". Slides, MIT Bitcoin Expo, 4 March 2017. [slides](https://download.wpsoftware.net/bitcoin/wizardry/mw-slides/2017-03-mit-bitcoin-expo/slides.pdf).
17. <a id="ref-17"></a>L. Aumayr, O. Ersoy, A. Erwig, S. Faust, K. Hostakova, M. Maffei, P. Moreno-Sanchez, S. Riahi. "Generalized Channels from Limited Blockchain Scripts and Adaptor Signatures". Asiacrypt 2021. [ePrint 2020/476](https://eprint.iacr.org/2020/476).
18. <a id="ref-18"></a>Blockstream Research. libsecp256k1-zkp, module ecdsa_adaptor, which follows L. Fournier, "One-Time Verifiably Encrypted Signatures A.K.A. Adaptor Signatures". [secp256k1-zkp](https://github.com/BlockstreamResearch/secp256k1-zkp). *We read the module's header, which names Fournier's paper; we did not read the paper itself.*
19. <a id="ref-19"></a>E. Heilman, L. AlShenibr, F. Baldimtsi, A. Scafuro, S. Goldberg. "TumbleBit: An Untrusted Bitcoin-Compatible Anonymous Payment Hub". NDSS 2017. [ePrint 2016/575](https://eprint.iacr.org/2016/575).
20. <a id="ref-20"></a>E. Tairi, P. Moreno-Sanchez, M. Maffei. "A2L: Anonymous Atomic Locks for Scalability in Payment Channel Hubs". IEEE Symposium on Security and Privacy 2021. [ePrint 2019/589](https://eprint.iacr.org/2019/589).

## HTTP, agents and other payment systems

21. <a id="ref-21"></a>R. Fielding and others. "Hypertext Transfer Protocol: HTTP/1.1". RFC 2068, January 1997, section 10.4.3: "402 Payment Required. This code is reserved for future use." It is still reserved in RFC 9110 (2022), section 15.5.3. [RFC 2068](https://www.rfc-editor.org/rfc/rfc2068.txt), [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.txt).
22. <a id="ref-22"></a>x402 Foundation. "x402", protocol version 2, with its schemes exact (and exact on Lightning, 2026), upto and batch-settlement. Created by Coinbase; since April 2026 kept by the x402 Foundation under the Linux Foundation. Apache-2.0. [x402-foundation/x402](https://github.com/x402-foundation/x402), [announcement](https://www.linuxfoundation.org/press/linux-foundation-is-launching-the-x402-foundation-and-welcoming-the-contribution-of-the-x402-protocol).
23. <a id="ref-23"></a>Lightning Labs. "L402 Protocol Specification". [lightninglabs/L402](https://github.com/lightninglabs/L402/blob/master/protocol-specification.md).
24. <a id="ref-24"></a>S. Warta, ligi, P. Gomes, A. Herzog. "CAIP-2: Blockchain ID Specification". 2019. With the bip122 namespace (Warta, ligi, Gomes), which follows M. Pontello, "BIP 122: URI scheme for Blockchain references / exploration". [CAIP-2](https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-2.md), [bip122 namespace](https://github.com/ChainAgnostic/namespaces/tree/main/bip122).
25. <a id="ref-25"></a>Nostr contributors. "NIP-47: Nostr Wallet Connect". 2023. [NIP-47](https://github.com/nostr-protocol/nips/blob/master/47.md).
26. <a id="ref-26"></a>Anthropic. "Introducing the Model Context Protocol". 25 November 2024. Since December 2025 the protocol is kept by the Agentic AI Foundation, under the Linux Foundation. [announcement](https://www.anthropic.com/news/model-context-protocol), [modelcontextprotocol.io](https://modelcontextprotocol.io).
27. <a id="ref-27"></a>Cashu contributors (calle and others). "Cashu NUTs", the Cashu protocol specifications; "NUT-24: HTTP 402 Payment Required". [cashubtc/nuts](https://github.com/cashubtc/nuts), [NUT-24](https://github.com/cashubtc/nuts/blob/main/24.md).
28. <a id="ref-28"></a>Routstr. "routstr-core". [Routstr/routstr-core](https://github.com/Routstr/routstr-core).
29. <a id="ref-29"></a>Burak. "Ark: An Alternative Privacy-preserving Second Layer Solution". bitcoin-dev mailing list, 22 May 2023. For expiry and refresh as built: Second, "VTXO lifetime". [archived copy](https://web.archive.org/web/20250128005325/https://gnusha.org/pi/bitcoindev/1300890009.1516890.1684742043892%40eu1.myprofessionalmail.com/), [second.tech](https://second.tech/docs/learn/lifetime).
30. <a id="ref-30"></a>B. Cohen. "Incentives Build Robustness in BitTorrent". 22 May 2003. Section 3.3, "Optimistic Unchoking". [bittorrent.org](https://www.bittorrent.org/bittorrentecon.pdf).
31. <a id="ref-31"></a>G. Maxwell. "Zero Knowledge Contingent Payment". Bitcoin Wiki, page created 28 November 2011. [Bitcoin Wiki](https://en.bitcoin.it/wiki/Zero_Knowledge_Contingent_Payment). *The page names no author in its text; the author and date are from its history.*
32. <a id="ref-32"></a>R. C. Merkle. "A Digital Signature Based on a Conventional Encryption Function". Crypto '87, Springer, 1988. [doi:10.1007/3-540-48184-2_32](https://doi.org/10.1007/3-540-48184-2_32).

## Paying by lottery

33. <a id="ref-33"></a>D. Wheeler. "Transactions Using Bets". Security Protocols, LNCS 1189, Springer, 1996. [doi:10.1007/3-540-62494-5_7](https://doi.org/10.1007/3-540-62494-5_7). *We read its record and what Rivest and later authors say of it, not the paper itself.*
34. <a id="ref-34"></a>R. L. Rivest. "Electronic Lottery Tickets as Micropayments". Financial Cryptography 1997. [author's copy](https://people.csail.mit.edu/rivest/pubs/Riv97b.pdf).
35. <a id="ref-35"></a>S. Micali, R. L. Rivest. "Micropayments Revisited". CT-RSA 2002. [author's copy](https://people.csail.mit.edu/rivest/pubs/MR02a.pdf).
36. <a id="ref-36"></a>R. Pass, a. shelat. "Micropayments for Decentralized Currencies". ACM CCS 2015. [ePrint 2016/332](https://eprint.iacr.org/2016/332).
37. <a id="ref-37"></a>A. Chiesa, M. Green, J. Liu, P. Miao, I. Miers, P. Mishra. "Decentralized Anonymous Micropayments". Eurocrypt 2017. [ePrint 2016/1033](https://eprint.iacr.org/2016/1033).
38. <a id="ref-38"></a>T. Mitani, A. Otsuka. "Anonymous probabilistic payment in payment hub". Cryptology ePrint Archive 2020/748, 2020 (a preprint). [ePrint 2020/748](https://eprint.iacr.org/2020/748).
39. <a id="ref-39"></a>J. S. Cannell, J. Sheek, J. Freeman, G. Hazel, J. Rodriguez-Mueller, E. Hou, B. J. Fox, S. Waterhouse. "Orchid: A Decentralized Network Routing Market". Version 2.0, 2019. [whitepaper](https://www.orchid.com/whitepaper/english.pdf).
40. <a id="ref-40"></a>D. Petkanics, Y. Fu. "Livepeer Streamflow Paper". 2018. The contract is TicketBroker in the Livepeer protocol. [Streamflow](https://github.com/livepeer/wiki/blob/master/STREAMFLOW.md), [contract](https://github.com/livepeer/protocol/blob/confluence/contracts/pm/mixins/MixinTicketBrokerCore.sol).
41. <a id="ref-41"></a>M. Caldwell (casascius). "Sustainable nanopayment idea: Probabilistic Payments". Bitcoin Forum, 4 February 2012. [bitcointalk.org](https://bitcointalk.org/index.php?topic=62558.0).
42. <a id="ref-42"></a>T. Dryja. "LN as a Directed Graph: Single-Funded Channel Topology". Slides, 11 April 2016. [slides](https://docs.google.com/presentation/d/1G4xchDGcO37DJ2lPC_XYyZIUkJc2khnLrCaZXgvDN0U/).
43. <a id="ref-43"></a>O. Kurbatov. "Emulating OP_RAND in Bitcoin". arXiv:2501.16451, January 2025, and the Delving Bitcoin thread "Emulating OP_RAND". [arXiv:2501.16451](https://arxiv.org/abs/2501.16451), [thread](https://delvingbitcoin.org/t/emulating-op-rand/1409), [Optech: probabilistic payments](https://bitcoinops.org/en/topics/probabilistic-payments/).
44. <a id="ref-44"></a>P. Gerhart, J. Taylor, S. A. K. Thyagarajan. "Probabilistic Atomic Swaps for Bitcoin and Friends". arXiv:2605.04975, 6 May 2026. [arXiv:2605.04975](https://arxiv.org/abs/2605.04975).
45. <a id="ref-45"></a>M. Rosenfeld. "Analysis of Bitcoin Pooled Mining Reward Systems". arXiv:1112.4980, 2011. [arXiv:1112.4980](https://arxiv.org/abs/1112.4980).

## Building blocks of the sealed draw

46. <a id="ref-46"></a>T. Chou, C. Orlandi. "The Simplest Protocol for Oblivious Transfer". Latincrypt 2015. [ePrint 2015/267](https://eprint.iacr.org/2015/267).
47. <a id="ref-47"></a>Z. A. Genç, V. Iovino, A. Rial. "'The Simplest Protocol for Oblivious Transfer' Revisited". Information Processing Letters, 2020. It finds a flaw in the security proof of the protocol above. [ePrint 2017/370](https://eprint.iacr.org/2017/370).
48. <a id="ref-48"></a>Y. Ishai, J. Kilian, K. Nissim, E. Petrank. "Extending Oblivious Transfers Efficiently". Crypto 2003. [doi:10.1007/978-3-540-45146-4_9](https://doi.org/10.1007/978-3-540-45146-4_9).
49. <a id="ref-49"></a>M. Keller, E. Orsini, P. Scholl. "Actively Secure OT Extension with Optimal Overhead". Crypto 2015, revised 2022. The authors' 2022 note says the original proof does not hold and gives a repair that uses Roy's technique. [ePrint 2015/546](https://eprint.iacr.org/2015/546).
50. <a id="ref-50"></a>L. Roy. "SoftSpokenOT: Quieter OT Extension From Small-Field Silent VOLE in the Minicrypt Model". Crypto 2022. [ePrint 2022/192](https://eprint.iacr.org/2022/192).
51. <a id="ref-51"></a>N. Gilboa. "Two Party RSA Key Generation". Crypto '99. [doi:10.1007/3-540-48405-1_8](https://doi.org/10.1007/3-540-48405-1_8).
52. <a id="ref-52"></a>J. Doerner, Y. Kondi, E. Lee, a. shelat. "Secure Two-party Threshold ECDSA from ECDSA Assumptions". IEEE Symposium on Security and Privacy 2018. [ePrint 2018/499](https://eprint.iacr.org/2018/499).
53. <a id="ref-53"></a>J. Doerner, Y. Kondi, E. Lee, a. shelat. "Threshold ECDSA in Three Rounds". IEEE Symposium on Security and Privacy 2024. [ePrint 2023/765](https://eprint.iacr.org/2023/765).
54. <a id="ref-54"></a>J. Groth. "On the Size of Pairing-based Non-interactive Arguments". Eurocrypt 2016. [ePrint 2016/260](https://eprint.iacr.org/2016/260).
55. <a id="ref-55"></a>Electric Coin Company. "BLS12-381: New zk-SNARK Elliptic Curve Construction". 11 March 2017. [blog post](https://electriccoin.co/blog/new-snark-curve/).
56. <a id="ref-56"></a>D.-E. Hopwood, S. Bowe, T. Hornby, N. Wilcox. "Zcash Protocol Specification". Section 5.4.9.3, "Jubjub". [zips.z.cash](https://zips.z.cash/protocol/protocol.pdf). *Read from an archived copy of 21 September 2026; the address given did not answer us.*
57. <a id="ref-57"></a>arkworks contributors. ark-groth16, ark-bls12-381 and ark-ed-on-bls12-381, Rust libraries. MIT or Apache-2.0. [arkworks-rs](https://github.com/arkworks-rs).
58. <a id="ref-58"></a>M. Campanelli, R. Gennaro, S. Goldfeder, L. Nizzardo. "Zero-Knowledge Contingent Payments Revisited: Attacks and Payments for Services". ACM CCS 2017. [ePrint 2017/566](https://eprint.iacr.org/2017/566).
59. <a id="ref-59"></a>G. Fuchsbauer. "Subversion-zero-knowledge SNARKs". PKC 2018. [ePrint 2017/587](https://eprint.iacr.org/2017/587).

## Software this work runs on

60. <a id="ref-60"></a>Bitcoin Knots, maintained by Luke Dashjr. Release 29.4.1 (September 2026) carries the BLAKE2b proof of work (L. Dashjr) and the unified opt-in signature hash (K. Santiago; specified in the tree's doc/unified-sighash.md), activated at block 961,640 together with the reduced-data rules of BIP 110 (D. Ohm). MIT. [bitcoinknots/bitcoin](https://github.com/bitcoinknots/bitcoin), [unified-sighash.md](https://github.com/bitcoinknots/bitcoin/blob/29.x-knots/doc/unified-sighash.md).
61. <a id="ref-61"></a>Lightning Fork, by Paul Lamb: lnd for the BLAKE2b chain. Measured here at tag v0.21.3-beta-blake2b.17 (commit cebc10fe), in the regtest lab of the same author, lightning-fork-lab, at commit a5cadc5. Lightning Fork is MIT; the lab carries no licence file. [paulscode/lightning-fork](https://github.com/paulscode/lightning-fork), [paulscode/lightning-fork-lab](https://github.com/paulscode/lightning-fork-lab).
62. <a id="ref-62"></a>lnd, the Lightning Network Daemon, by Lightning Labs and the Lightning Network developers. MIT. [lightningnetwork/lnd](https://github.com/lightningnetwork/lnd).
63. <a id="ref-63"></a>The Core Lightning fork for the BLAKE2b chain, by PrivKey, built on Core Lightning (R. Russell, Blockstream, and contributors). Not tested by us. [privkeyio/lightning](https://github.com/privkeyio/lightning), [ElementsProject/lightning](https://github.com/ElementsProject/lightning).
64. <a id="ref-64"></a>electrs, by Roman Zeyde. MIT. [romanz/electrs](https://github.com/romanz/electrs).
65. <a id="ref-65"></a>libsecp256k1, by Pieter Wuille and the Bitcoin Core developers. MIT. [bitcoin-core/secp256k1](https://github.com/bitcoin-core/secp256k1).
66. <a id="ref-66"></a>OCEAN. DATUM Gateway (Bitcoin Ocean, LLC, Jason Hughes and contributors; MIT), and J. Hughes, "TIDES: Transparent Index of Distinct Extended Shares", 2024. [OCEAN-xyz/datum_gateway](https://github.com/OCEAN-xyz/datum_gateway), [TIDES](https://ocean.xyz/docs/tides).

