# btc-tx

All tx's are made on the testnet

tx's i made using this script:
1. [`f8adcf93489b1ec772f2a289b77addd01acd33c1185c2ce407d48533837d4ca9`](https://blockstream.info/testnet/tx/f8adcf93489b1ec772f2a289b77addd01acd33c1185c2ce407d48533837d4ca9?expand)
2. [`bc5c87ee33cd45814b006b2ee23ee5f67016dacff765cf3474ab23e2cc101103`](https://blockstream.info/testnet/tx/bc5c87ee33cd45814b006b2ee23ee5f67016dacff765cf3474ab23e2cc101103)


raw tx data of [`bc5c87ee33cd45814b006b2ee23ee5f67016dacff765cf3474ab23e2cc101103`](https://blockstream.info/testnet/tx/bc5c87ee33cd45814b006b2ee23ee5f67016dacff765cf3474ab23e2cc101103)
```
raw tx data: 01000000015b2fca7e6092211b4b5388794502ea7e0eec3b469e4687c5b7012fda6a64892b000000008a473044022031b8804457e6a9e1104b16e9ca056c3425aa0eebb908af6a4007d923cc3af0260220124c882aed83d09fc7215756beed86805971f2c2fc6010d33de5f64b315dc5cf0141048fa8bba39d339d979ad6a3e82b19595e7032f81ff5fe35cd3dfb9c5743f7625952cb9c86f771cdf7469c7887eeba959f0bc5b1b3d1464f3b1e5ab6898e77ea8cffffffff02e8030000000000001976a914e2172262eae7880950012cb28a5e98c1f85d44ae88acd07e0100000000001976a914d8061caf13fe356638ad1ef8501646b8e8a9a5d088ac00000000
txid: bc5c87ee33cd45814b006b2ee23ee5f67016dacff765cf3474ab23e2cc101103
```

The broadcast script is not working(`send` method in [tx.py](tx.py)). i can't figure out why it's not working, everything seem's fine though.


hexdump of the broadcast data corresponding to tx [`bc5c87ee33cd45814b006b2ee23ee5f67016dacff765cf3474ab23e2cc101103`](https://blockstream.info/testnet/tx/bc5c87ee33cd45814b006b2ee23ee5f67016dacff765cf3474ab23e2cc101103)
```
00000000: 0B 11 09 07 74 78 00 00  00 00 00 00 00 00 00 00  ....tx..........
00000010: 01 01 00 00 B4 F4 66 8B  01 00 00 00 01 5B 2F CA  ......f......[/.
00000020: 7E 60 92 21 1B 4B 53 88  79 45 02 EA 7E 0E EC 3B  ~`.!.KS.yE..~..;
00000030: 46 9E 46 87 C5 B7 01 2F  DA 6A 64 89 2B 00 00 00  F.F..../.jd.+...
00000040: 00 8A 47 30 44 02 20 31  B8 80 44 57 E6 A9 E1 10  ..G0D. 1..DW....
00000050: 4B 16 E9 CA 05 6C 34 25  AA 0E EB B9 08 AF 6A 40  K....l4%......j@
00000060: 07 D9 23 CC 3A F0 26 02  20 12 4C 88 2A ED 83 D0  ..#.:.&. .L.*...
00000070: 9F C7 21 57 56 BE ED 86  80 59 71 F2 C2 FC 60 10  ..!WV....Yq...`.
00000080: D3 3D E5 F6 4B 31 5D C5  CF 01 41 04 8F A8 BB A3  .=..K1]...A.....
00000090: 9D 33 9D 97 9A D6 A3 E8  2B 19 59 5E 70 32 F8 1F  .3......+.Y^p2..
000000A0: F5 FE 35 CD 3D FB 9C 57  43 F7 62 59 52 CB 9C 86  ..5.=..WC.bYR...
000000B0: F7 71 CD F7 46 9C 78 87  EE BA 95 9F 0B C5 B1 B3  .q..F.x.........
000000C0: D1 46 4F 3B 1E 5A B6 89  8E 77 EA 8C FF FF FF FF  .FO;.Z...w......
000000D0: 02 E8 03 00 00 00 00 00  00 19 76 A9 14 E2 17 22  ..........v...."
000000E0: 62 EA E7 88 09 50 01 2C  B2 8A 5E 98 C1 F8 5D 44  b....P.,..^...]D
000000F0: AE 88 AC D0 7E 01 00 00  00 00 00 19 76 A9 14 D8  ....~.......v...
00000100: 06 1C AF 13 FE 35 66 38  AD 1E F8 50 16 46 B8 E8  .....5f8...P.F..
00000110: A9 A5 D0 88 AC 00 00 00  00                       .........
```

but then this didn't work, so i don't know maybe i didn't connect with the correct peers?

used this website to broadcast the raw tx: [bitaps](https://tbtc.bitaps.com/broadcast) & [blockstream](https://blockstream.info/testnet/tx/push)
