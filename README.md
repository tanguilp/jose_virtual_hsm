# JOSEVirtualHSM

Virtual JOSE HSM for signing JWSes and decrypting JWEs

## Installation

```elixir
def deps do
  [
    {:jose_virtual_hsm, "~> 0.2.0"}
  ]
end
```

## Description

It is a virtual HSM in the sense that keys private keys for signing and decrypting are not
available to other processes, and are particularly protected against leaking:
- there are stored in a private ETS
- processes dealing with these keys are marked as sensitive
- keys loaded from the disk or the environment can be deleted after loading (ideal for
container deployment)

Other features include:
- keys can be generated automatically given a specification, so that there **no secret to
handle** during deployment
- it is automatically clusterized: any node can sign a JWS or decrypt a JWE with any key
in the cluster. Nodes don't share keys (they can't) but can work with each other in a
transparent fashion
- key ID is automatically generated using
[RFC7638 - JSON Web Key (JWK) Thumbprint](https://tools.ietf.org/html/rfc7638)
  - however, note that due to a limitation in the underlying `JOSE` library, JWSes do not
  include the kid in their header

## Launching `JOSEVirtualHSM`

`JOSEVirtualHSM` is a `GenServer` that must be launched in a supervised manner at application
startup. In your `app/application.ex` file, add:


```elixir
children = [
  JOSEVirtualHSM
]
```

or

```elixir
children = [
  {JOSEVirtualHSM, opts...}
]
```

where `opts` is a `Keyword` to the list of children.

## Options

- `:delete_on_load`: when loading a private key from a file or the environment, this
options, when set to `true`, deletes the key after loading. Defaults to `true`
- `:keys`: the list of keys to load. See `t:key_load_specs/0` for the different methods
to load keys

## Environment options

The key specification can also be retrieved from the environment options:

`config/config.exs`:

```elixir
config :jose_virtual_hsm, :keys, [
  {:auto_gen, {:ec, "P-256"}, %{"use" => "sig"}},
  {:auto_gen, {:rsa, 2048}, %{"use" => "sig"}},
  {:auto_gen, {:okp, :Ed25519}, %{"use" => "sig"}},
  {:auto_gen, {:ec, "P-256"}, %{"use" => "enc"}},
  {:auto_gen, {:rsa, 2048}, %{"use" => "enc"}},
  {:auto_gen, {:okp, :X25519}, %{"use" => "enc"}}
]
```

This key specification is used i nthe following examples.

## Example

### Retrieving public keys

```elixir
iex> JOSEVirtualHSM.public_keys()
[
  %{
    "crv" => "X25519",
    "kid" => "NqYw6_wlorTvDqae3HaI79i_k_Q61l0jESQNvgT0Ku4",
    "kty" => "OKP",
    "use" => "enc",
    "x" => "lY2nopV03NTsSqCVgfyr_VNjTBkUhGHcHjIHJNrlaKQ"
  },
  %{
    "crv" => "Ed25519",
    "kid" => "Hq3_i8UWJ1FqokUqTQRDLw4GvvBQCKiMjSoQ4Ng6CY0",
    "kty" => "OKP",
    "use" => "sig",
    "x" => "XxHceRoVym7hsb5W-T2RqTzgoz_DEmCZKHBjy6MWsZA"
  },
  %{
    "e" => "AQAB",
    "kid" => "5A5Z3JxpYNO4pqbfC4wSFUk2cpkcAxwZsH0yev3zXpk",
    "kty" => "RSA",
    "n" => "7Rwb2l4ORycxCPAMK2B_p1FqKqrBpmcjklqazucAiJtNPtY2n-yEziD05-urwutIN2-wfaKIGg51-8KIQN5x_PTXUxje2oK3GOHHWaSWGpd1kJVEe-owSKGQxoga5rQDTk4j3MMA0brbgoJM2v32lKiv5CgV6E-wgCXb8QlrvIpwhnIN9CPEHuxo9Izpw8WqIj4d8Uu7LohxUM0eFfBkdbmgt5xL4Xm5MV6eDRhYq9agRLGNbBIHK2T5Xyq6-YB5URtWCeizA8hongk6nZAzy19wvz88pj4CsBy73UuP0jdT-wlGGvTpGx9AEFLv1p_RXzVgfZMGn2z3Q8Mhf0mxVQ",
    "use" => "sig"
  },
  %{
    "e" => "AQAB",
    "kid" => "szhiyrpeKBtQOr6cSEj3TbJ87vqvvGuk3Is6cPBYNm0",
    "kty" => "RSA",
    "n" => "5GX4GERxJ2rV-w5T2G00D3-HLEriXjriL-w7TkCB9H8zhiljHH0SxmbxBMT5HksJMWQyiDZEKp6ilrZCjsvOAJCpvh0SrPnIRzu95Wt1VlGOlp0C2BnL0wuPnkrUHbGZAzE-ux4ISpw9LqTi6KlL1dWQei6-_ihs0E37iTpFJy2EbEVXG6ydsH0FnoJv0_dgf3P4Yy8kIoNx5f4czLSWhK-psoPVKxxAN3mlY7iRGQHxOdgEyrsANj8uSQehzO87T5IVmMDtoBBx6PUn9awDW5emoU_mfXy3hlR3S67pjbjfNA5A3QZBs39-hCU92EtA7CS0IQ_rvvAfvlLV3T-tjQ",
    "use" => "enc"
  },
  %{
    "crv" => "P-256",
    "kid" => "ltu_BZFFssJhqlTdKvf3VWu7z9dFKhwFxXSx8Q-bpw4",
    "kty" => "EC",
    "use" => "enc",
    "x" => "jopq4PgS4w9721MwJppxw7niV-1zqgtBd-JeVWPuBcU",
    "y" => "Eo1xbm0g5AsB8GSiXKHRynXH2OwRcMO9i-6PTi-k-GE"
  },
  %{
    "crv" => "P-256",
    "kid" => "SiuAFPXstUhUzhmc__1mybX1ZJcJ6F2llEeb-LaAjIo",
    "kty" => "EC",
    "use" => "sig",
    "x" => "2PXy4aIbWUHzkRksSITO1ws9Y1AI14fBAtsvr1UDwXQ",
    "y" => "hPtgSkKH6DXzh18Ym_jh9bzcJir5mKp_skj9oKI5ydA"
  }
]
```

These public keys can obviously be shared with third parties. They can be used:
- to verify signature of a JWS signed by `JOSEVirtualHSM`
- to encrypt a JWE to be sent to the server using `JOSEVirtualHSM`

`JOSEVirtualHSM` doesn't support JWS verification and JWE encryption. For that, use
`JOSE` or `JOSEUtils` instead.

### Signing:

```elixir
iex> JOSEVirtualHSM.sign(%{"hello" => "world"})
{:ok,
 {"eyJhbGciOiJSUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIn0.nFP2GBJdsKzgUMR7g55pMmtNckXB9F9C83jhfAW0qOake7AmpZb3eLZhGi3OrTB7CRI2x9MHtA1qQMdOY0u8R_VovYfv5fGLVRJLe8uICGIq1NojO_66lMMoxmtMxIhVcX1FZfWR9Z_Ez4KGVm4eJvTuO33ds115Ik8Vh3aGFBorW74rYqjYZPgEHyjO4RqbzexBodq-z5rGOqAvFgz9C6X_xkMwiI6mNI4XIQ-5jzLPKMP5t94QwJGZ4EEc9QyFbNqmh2OlUaY0NTthP6MAzler7K5oz2S_6mQvt6K4Fmk1C-HIR3nad_s_z-PLvj6tEJnmIiEcFHTxfRcceUQ_QA",
  %{
    "e" => "AQAB",
    "kid" => "5A5Z3JxpYNO4pqbfC4wSFUk2cpkcAxwZsH0yev3zXpk",
    "kty" => "RSA",
    "n" => "7Rwb2l4ORycxCPAMK2B_p1FqKqrBpmcjklqazucAiJtNPtY2n-yEziD05-urwutIN2-wfaKIGg51-8KIQN5x_PTXUxje2oK3GOHHWaSWGpd1kJVEe-owSKGQxoga5rQDTk4j3MMA0brbgoJM2v32lKiv5CgV6E-wgCXb8QlrvIpwhnIN9CPEHuxo9Izpw8WqIj4d8Uu7LohxUM0eFfBkdbmgt5xL4Xm5MV6eDRhYq9agRLGNbBIHK2T5Xyq6-YB5URtWCeizA8hongk6nZAzy19wvz88pj4CsBy73UuP0jdT-wlGGvTpGx9AEFLv1p_RXzVgfZMGn2z3Q8Mhf0mxVQ",
    "use" => "sig"
  }}}
iex> JOSEVirtualHSM.sign(%{"hello" => "world"})
{:ok,
 {"eyJhbGciOiJFZERTQSJ9.eyJoZWxsbyI6IndvcmxkIn0.WVRgyl4Pen0nieJF7cmGXQnkOocP4B6i78VgkKxcu_-gADSIM5Cg_mL2T-cU1ZY1ib91bQnHALdNoXqVSi66DQ",
  %{
    "crv" => "Ed25519",
    "kid" => "Hq3_i8UWJ1FqokUqTQRDLw4GvvBQCKiMjSoQ4Ng6CY0",
    "kty" => "OKP",
    "use" => "sig",
    "x" => "XxHceRoVym7hsb5W-T2RqTzgoz_DEmCZKHBjy6MWsZA"
  }}}
iex> JOSEVirtualHSM.sign(%{"hello" => "world"})
{:ok,
 {"eyJhbGciOiJFZERTQSJ9.eyJoZWxsbyI6IndvcmxkIn0.WVRgyl4Pen0nieJF7cmGXQnkOocP4B6i78VgkKxcu_-gADSIM5Cg_mL2T-cU1ZY1ib91bQnHALdNoXqVSi66DQ",
  %{
    "crv" => "Ed25519",
    "kid" => "Hq3_i8UWJ1FqokUqTQRDLw4GvvBQCKiMjSoQ4Ng6CY0",
    "kty" => "OKP",
    "use" => "sig",
    "x" => "XxHceRoVym7hsb5W-T2RqTzgoz_DEmCZKHBjy6MWsZA"
  }}}
iex> JOSEVirtualHSM.sign(%{"hello" => "world"})
{:ok,
 {"eyJhbGciOiJFUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIn0.1viHUsVOseF1eJ0nZAOXbo0RfHGP5H1U8lfV9qLijf4EnDbaPI7NkRdFQIHvbYVTYakm0dHdF2YPlNfKOrGMbg",
  %{
    "crv" => "P-256",
    "kid" => "SiuAFPXstUhUzhmc__1mybX1ZJcJ6F2llEeb-LaAjIo",
    "kty" => "EC",
    "use" => "sig",
    "x" => "2PXy4aIbWUHzkRksSITO1ws9Y1AI14fBAtsvr1UDwXQ",
    "y" => "hPtgSkKH6DXzh18Ym_jh9bzcJir5mKp_skj9oKI5ydA"
  }}}
```

Notice how keys where chosen randomly from all the available keys. `JOSEVirtualHSM` always
prefers keys on local node, when available. It's possible to specify how to sign using
`t:JOSEUtils.JWK.key_selector/0`:

```elixir
iex> JOSEVirtualHSM.sign(%{"hello" => "world"}, alg: ["ES256", "ES384", "ES512"])
{:ok,
 {"eyJhbGciOiJFUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIn0.ooZ8pRuhp20K8s7k0xkNGCb47nE8sW_JrjHtsb_w5PEFFGR1F7wysJGfg2tTU7kT0QzQQEeWUg0FJgkqsowbTw",
  %{
    "crv" => "P-256",
    "kid" => "SiuAFPXstUhUzhmc__1mybX1ZJcJ6F2llEeb-LaAjIo",
    "kty" => "EC",
    "use" => "sig",
    "x" => "2PXy4aIbWUHzkRksSITO1ws9Y1AI14fBAtsvr1UDwXQ",
    "y" => "hPtgSkKH6DXzh18Ym_jh9bzcJir5mKp_skj9oKI5ydA"
  }}}
iex> JOSEVirtualHSM.sign(%{"hello" => "world"}, kty: "OKP")
{:ok,
 {"eyJhbGciOiJFZERTQSJ9.eyJoZWxsbyI6IndvcmxkIn0.WVRgyl4Pen0nieJF7cmGXQnkOocP4B6i78VgkKxcu_-gADSIM5Cg_mL2T-cU1ZY1ib91bQnHALdNoXqVSi66DQ",
  %{
    "crv" => "Ed25519",
    "kid" => "Hq3_i8UWJ1FqokUqTQRDLw4GvvBQCKiMjSoQ4Ng6CY0",
    "kty" => "OKP",
    "use" => "sig",
    "x" => "XxHceRoVym7hsb5W-T2RqTzgoz_DEmCZKHBjy6MWsZA"
  }}}
```

### Decryption

With RSA:

```elixir
iex> jwk_pub = JOSEVirtualHSM.public_keys() |> Enum.find(&(&1["kty"] == "RSA" and &1["use"] == "enc"))
%{
  "e" => "AQAB",
  "kid" => "szhiyrpeKBtQOr6cSEj3TbJ87vqvvGuk3Is6cPBYNm0",
  "kty" => "RSA",
  "n" => "5GX4GERxJ2rV-w5T2G00D3-HLEriXjriL-w7TkCB9H8zhiljHH0SxmbxBMT5HksJMWQyiDZEKp6ilrZCjsvOAJCpvh0SrPnIRzu95Wt1VlGOlp0C2BnL0wuPnkrUHbGZAzE-ux4ISpw9LqTi6KlL1dWQei6-_ihs0E37iTpFJy2EbEVXG6ydsH0FnoJv0_dgf3P4Yy8kIoNx5f4czLSWhK-psoPVKxxAN3mlY7iRGQHxOdgEyrsANj8uSQehzO87T5IVmMDtoBBx6PUn9awDW5emoU_mfXy3hlR3S67pjbjfNA5A3QZBs39-hCU92EtA7CS0IQ_rvvAfvlLV3T-tjQ",
  "use" => "enc"
}
iex> jwe = JOSEUtils.JWE.encrypt!(%{"very" => "secret"}, jwk_pub, "RSA-OAEP", "A128GCM")
"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ.0odG-8i5DL-SB1h4_DeGbavEZhACbVKqvnz2MCoSUyCW84U7ejqn2HqLh8Te03_yIlR9jC8raJ4OI75fbsK9bKrSf_RubJIYjVto0GaBIJzREujjS2fVACe5UUPQ9lVkYplXiT-wqm3wvtX9GkaBz4FL-fmftgtdW9zdYC9U2D_AfFG5hhO4BnAUaI7x1wDdnVMCPjbg5B21x6IPGSma0H6YgCyBf26BRIuNNRbaly89CAam3oqzTn3t0UrDb-Hrx8jEC4a9RxmL44RIdFVAjijcWLjorSd8qq8qGrDa7gpcFEGAYrX7U5XDawjyJnWzWD1g-LDn6H0IbAn5LEorEA.rTMjuaYevaacZbzt.6t7IpuvqFe2nt94httLzpjk.Cc5UcgwZBhkuUFsDeKpQBA"
iex> JOSEVirtualHSM.decrypt(jwe)
{:ok,
 {"{\\"very\\":\\"secret\\"}",
  %{
    "e" => "AQAB",
    "kid" => "szhiyrpeKBtQOr6cSEj3TbJ87vqvvGuk3Is6cPBYNm0",
    "kty" => "RSA",
    "n" => "5GX4GERxJ2rV-w5T2G00D3-HLEriXjriL-w7TkCB9H8zhiljHH0SxmbxBMT5HksJMWQyiDZEKp6ilrZCjsvOAJCpvh0SrPnIRzu95Wt1VlGOlp0C2BnL0wuPnkrUHbGZAzE-ux4ISpw9LqTi6KlL1dWQei6-_ihs0E37iTpFJy2EbEVXG6ydsH0FnoJv0_dgf3P4Yy8kIoNx5f4czLSWhK-psoPVKxxAN3mlY7iRGQHxOdgEyrsANj8uSQehzO87T5IVmMDtoBBx6PUn9awDW5emoU_mfXy3hlR3S67pjbjfNA5A3QZBs39-hCU92EtA7CS0IQ_rvvAfvlLV3T-tjQ",
    "use" => "enc"
  }}}
```

With ECDH-ES:

```elixir
iex> jwk_pub = JOSEVirtualHSM.public_keys() |> Enum.find(&(&1["kty"] == "EC" and &1["use"] == "enc"))
%{
  "crv" => "P-256",
  "kid" => "ltu_BZFFssJhqlTdKvf3VWu7z9dFKhwFxXSx8Q-bpw4",
  "kty" => "EC",
  "use" => "enc",
  "x" => "jopq4PgS4w9721MwJppxw7niV-1zqgtBd-JeVWPuBcU",
  "y" => "Eo1xbm0g5AsB8GSiXKHRynXH2OwRcMO9i-6PTi-k-GE"
}
iex> my_jwk_priv = JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_map() |> elem(1)
%{
  "crv" => "P-256",
  "d" => "TsfNgJq_UEWdf0rqp2W5OQJQMbtANMMWwguNO4VrZkM",
  "kty" => "EC",
  "x" => "UIZ5br7q2li5NzcZePOiK4Wi3jV4xATVT4Yie8xMRT8",
  "y" => "eiLF2EUWFbPX2MTchz_h-VbiEjnJ9koB-6kVqWF3kBo"
}
iex> jwe = JOSEUtils.JWE.encrypt!(%{"very" => "secret"}, {jwk_pub, my_jwk_priv}, "ECDH-ES", "A128GCM")
"eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOEdDTSIsImVwayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IlVJWjVicjdxMmxpNU56Y1plUE9pSzRXaTNqVjR4QVRWVDRZaWU4eE1SVDgiLCJ5IjoiZWlMRjJFVVdGYlBYMk1UY2h6X2gtVmJpRWpuSjlrb0ItNmtWcVdGM2tCbyJ9fQ..16AhXI2qu9cw7A6e.dG_TaBdpAJHgR962LxThdWo.uBtZ3N55sztIRgCFwzC5hw"
iex> JOSEVirtualHSM.decrypt(jwe)
{:ok,
 {"{\\"very\\":\\"secret\\"}",
  %{
    "crv" => "P-256",
    "kid" => "ltu_BZFFssJhqlTdKvf3VWu7z9dFKhwFxXSx8Q-bpw4",
    "kty" => "EC",
    "use" => "enc",
    "x" => "jopq4PgS4w9721MwJppxw7niV-1zqgtBd-JeVWPuBcU",
    "y" => "Eo1xbm0g5AsB8GSiXKHRynXH2OwRcMO9i-6PTi-k-GE"
  }}}
```

## Clustering

The `JOSEVirtualHSM` of the current node listens to other `JOSEVirtualHSM` on joining and
leaving of other nodes, and registers their public keys and deletes them when needed.

This is based on BEAM distribution. Other distribution methods (such as using Redis as an
intermediary) are **not** supported.

## Architecture

Each node runs its own instance of `JOSEVirtualHSM`, which is a `GenServer`. This
`GenServer` has the following roles:
- on startup, it loads the keys from the key specification
- it stores local private keys in a private ETS
- it listens for joining and leaving nodes to gain knowledge of available keys

When an operation is requested for a local key, the local instance of `JOSEVirtualHSM`
launches a worker process and sends it the required private keys to perform the signing or
decryption operation. This process is in charge of:
- performing the signing or decryption operation
- answer to the original process

The `JOSEVirtualHSM` instance keeps track of the launched process and responds with an error
to the calling process if the worker process died in an abnormal manner.

The number of worker processes is **not** limited. No queueing or pooling method is
implemented.  As a consequence, a server could become unresponsive and overwhelmed should too
many signing or decryption requests arrive at the same time. Any PR implementing it is
welcome :)
