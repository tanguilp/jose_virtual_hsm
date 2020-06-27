defmodule JOSEVirtualHSM do
  @moduledoc """
  Virtual JOSE HSM for signing JWSes and decrypting JWEs

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


      children = [
        JOSEVirtualHSM
      ]

  or

      children = [
        {JOSEVirtualHSM, opts...}
      ]

  where `opts` is a `Keyword` to the list of children.

  ## Options

  - `:delete_on_load`: when loading a private key from a file or the environment, this
  options, when set to `true`, deletes the key after loading. Defaults to `true`
  - `:keys`: the list of keys to load. See `t:key_load_specs/0` for the different methods
  to load keys

  ## Environment options

  The key specification can also be retrieved from the environment options:

  `config/config.exs`

      config :jose_virtual_hsm, :keys, [
        {:auto_gen, {:ec, "P-256"}, %{"use" => "sig"}},
        {:auto_gen, {:rsa, 2048}, %{"use" => "sig"}},
        {:auto_gen, {:okp, :Ed25519}, %{"use" => "sig"}},
        {:auto_gen, {:ec, "P-256"}, %{"use" => "enc"}},
        {:auto_gen, {:rsa, 2048}, %{"use" => "enc"}},
        {:auto_gen, {:okp, :X25519}, %{"use" => "enc"}}
      ]

  This key specification is used in the following examples.

  ## Example

  ### Retrieving public keys

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

  These public keys can obviously be shared with third parties. They can be used:
  - to verify signature of a JWS signed by `JOSEVirtualHSM`
  - to encrypt a JWE to be sent to the server using `JOSEVirtualHSM`

  `JOSEVirtualHSM` doesn't support JWS verification and JWE encryption. For that, use
  `JOSE` or `JOSEUtils` instead.

  ### Signing:

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

  Notice how keys where chosen randomly from all the available keys. `JOSEVirtualHSM` always
  prefers keys on local node, when available. It's possible to specify how to sign using
  `t:JOSEUtils.JWK.key_selector/0`:

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

  ### Decryption

  With RSA:

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

  With ECDH-ES:

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
  """

  # records stored in this table are of the form:
  # {kid, jwk_pub, [nodes]}
  @pub_keys_tab Module.concat(__MODULE__, PublicKeys)

  use GenServer

  alias JOSEVirtualHSM.{
    DecryptionError,
    NoSuitableKeyFoundError,
    Worker,
    WorkerError
  }

  require Logger

  @type key_fields :: %{optional(String.t()) => any()}

  @type key_load_specs :: [key_load_spec()]

  @type key_load_spec ::
          {:auto_gen, {:ec, curve :: String.t()}}
          | {:auto_gen, {:ec, curve :: String.t()}, key_fields()}
          | {:auto_gen, {:okp, :Ed25519 | :Ed448 | :X25519 | :X448}}
          | {:auto_gen, {:okp, :Ed25519 | :Ed448 | :X25519 | :X448}, key_fields()}
          | {:auto_gen, {:rsa, modulus_size :: non_neg_integer()}}
          | {:auto_gen, {:rsa, modulus_size :: non_neg_integer()}, key_fields()}
          | {:pem_file, Path.t()}
          | {:pem_file, Path.t(), key_fields()}
          | {:der_file, Path.t()}
          | {:der_file, Path.t(), key_fields()}
          | {:pem_env, var_name :: String.t()}
          | {:pem_env, var_name :: String.t(), key_fields()}
          | {:der_env, var_name :: String.t()}
          | {:der_env, var_name :: String.t(), key_fields()}
          | {:map_env, var_name :: String.t()}

  @doc """
  Starts a supervised JOSE virtual HSM

  ## Options

  - `:delete_on_load`: deletes the file or environment option of a key after loading it.
  Boolean, defaults to `true`
  - `:keys`: the list of keys to load. See `t:key_load_specs/0` for the different methods
  to load keys
  """
  def start_link(opts) do
    opts =
      opts
      |> Enum.into(%{})
      |> Map.put_new(:delete_on_load, true)

    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Return the registered public keys

  ## Options
  - `:local_only`: when set to `true`, only returns the local keys, not those registered from other
  nodes. Defaults to `false`
  """
  @spec public_keys(Keyword.t()) :: [JOSEUtils.JWK.t()]
  def public_keys(opts \\ []) do
    filter_fun =
      if opts[:local_only] == true do
        fn {_kid, _jwk_pub, nodes} -> node() in nodes end
      else
        fn _ -> true end
      end

    @pub_keys_tab
    |> :ets.tab2list()
    |> Enum.filter(filter_fun)
    |> Enum.map(fn {_kid, jwk_pub, _nodes} -> jwk_pub end)
  end

  @doc """
  Signs a message with one of the available signing keys

  If the payload is a string, it is signed as is. Otherwise, it is encoded to a string using
  `Jason.encode/1`. Example:

      JOSEVirtualHSM.sign(%{"Hello" => "Tomo"})

  The second parameter can be used to further specify which type of key to use:

      JOSEVirtualHSM.sign(%{"Hello" => "Tomo"}, kty: "RSA")
      JOSEVirtualHSM.sign(%{"Hello" => "Tomo"}, crv: "P-256")
      JOSEVirtualHSM.sign(%{"Hello" => "Tomo"}, alg: ["EdDSA", "RS512"])

  and can be used to use a specific key as well:

      JOSEVirtualHSM.sign(%{"Hello" => "Tomo"}, kid: ""wVX9XFHbv9ihewikZ2h-4FuwMZJIONu3n_0AdPFxy2Q"")

  When more than one key is available for signing, one is chosen randomly. Don't be
  surprised if signing returns JWSes signed with different algorithms!
  """
  @spec sign(
          payload :: String.t() | any(),
          JOSEUtils.JWK.key_selector(),
          timeout :: non_neg_integer()
        ) :: {:ok, {signed_payload :: String.t(), JOSEUtils.JWK.t()}} | {:error, Exception.t()}
  def sign(payload, key_selector \\ [], timeout \\ 30_000)

  def sign(<<_::binary>> = payload, key_selector, timeout) do
    key_selector =
      key_selector
      |> Keyword.put(:use, "sig")
      |> Keyword.put(:key_ops, "sign")

    @pub_keys_tab
    |> :ets.tab2list()
    |> Enum.filter(&JOSEUtils.JWK.match_key_selector?(elem(&1, 1), key_selector))
    |> Enum.split_with(fn {_, _, nodes} -> node() in nodes end)
    |> case do
      {[], []} ->
        {:error, %NoSuitableKeyFoundError{}}

      {[_ | _] = local_keys, _remote_keys} ->
        {kid, _jwk, _nodes} = Enum.random(local_keys)

        GenServer.call(JOSEVirtualHSM, {:sign, kid, key_selector[:alg], payload}, timeout)

      {[], remote_keys} ->
        {kid, _jwk, target_nodes} = Enum.random(remote_keys)

        GenServer.call(
          {JOSEVirtualHSM, Enum.random(target_nodes)},
          {:sign, kid, key_selector[:alg], payload},
          timeout
        )
    end
  rescue
    e ->
      {:error, e}
  end

  def sign(payload, key_selector, timeout) do
    with {:ok, payload} <- Jason.encode(payload) do
      sign(payload, key_selector, timeout)
    end
  end

  @doc """
  Decrypts a JWE encrypted with a public key of `JOSEVirtualHSM`

  As the encryption key can be located on any node running `JOSEVirtualHSM` in the cluster,
  this function:
  - retains only the keys that could have been used for encryption
  - tries decrypting the JWE sequentially on each possible node (it does not try to decrypt in
  parallel for performance reason: this would overload the `JOSEVirtualHSM` instances)

  For instance:

      JOSEVirtualHSM.decrypt(jwe)

  This function determines automatically the algorithms in use from the JWE header. The second
  parameter may be used to further select specific keys:

      JOSEVirtualHSM.decrypt(jwe, kid: "iBRaf9ugUtDUe2i2cAY9i4N315O6f_cSNeEEDi9wuQY")

  """
  @spec decrypt(
          jwe :: JOSEUtils.JWE.serialized(),
          JOSEUtils.JWK.key_selector(),
          timeout :: non_neg_integer()
        ) ::
          {:ok, decrypted_content :: String.t()} | {:error, Exception.t()}
  def decrypt(<<_::binary>> = jwe, key_selector \\ [], timeout \\ 30_000) do
    with {:ok, %{"alg" => alg, "enc" => enc} = jwe_header} <- JOSEUtils.JWE.peek_header(jwe) do
      key_selector = decrypt_update_key_selector_from_jwe_header(key_selector, jwe_header)

      all_keys = :ets.tab2list(@pub_keys_tab)

      suitable_kids =
        all_keys
        |> Enum.map(fn {_kid, jwk, _nodes} -> jwk end)
        |> JOSEUtils.JWKS.decryption_keys()
        |> Enum.filter(&JOSEUtils.JWK.match_key_selector?(&1, alg: alg, enc: enc))
        |> Enum.filter(&JOSEUtils.JWK.match_key_selector?(&1, key_selector))
        |> Enum.map(& &1["kid"])

      suitable_kids_and_nodes =
        for kid <- suitable_kids do
          {_kid, _jwk, nodes} =
            Enum.find(all_keys, fn
              {^kid, _, _} -> true
              _ -> false
            end)

          {kid, nodes}
        end

      case suitable_kids_and_nodes do
        [_ | _] ->
          node_key_mapping =
            Enum.reduce(suitable_kids_and_nodes, %{}, fn {kid, nodes}, acc ->
              case Enum.find(nodes, fn node -> node in Map.keys(acc) end) do
                nil ->
                  if node() in nodes,
                    do: Map.put(acc, node(), [kid]),
                    else: Map.put(acc, List.first(nodes), [kid])

                node ->
                  Map.update!(acc, node, &[kid | &1])
              end
            end)

          do_decrypt(jwe, Enum.into(node_key_mapping, []), alg, enc, timeout)

        [] ->
          {:error, %NoSuitableKeyFoundError{}}
      end
    end
  end

  defp decrypt_update_key_selector_from_jwe_header(key_selector, %{"epk" => epk}) do
    key_selector =
      case epk do
        %{"kty" => kty} ->
          Keyword.put(key_selector, :kty, kty)

        _ ->
          key_selector
      end

    case epk do
      %{"crv" => crv} ->
        Keyword.put(key_selector, :crv, crv)

      _ ->
        key_selector
    end
  end

  defp decrypt_update_key_selector_from_jwe_header(key_selector, _) do
    key_selector
  end

  defp do_decrypt(_jwe, [], _alg_or_algs_or_nil, _enc_or_encs_or_nil, _timeout) do
    {:error, %DecryptionError{}}
  end

  defp do_decrypt(jwe, [{node, kids} | rest], alg, enc, timeout) do
    case GenServer.call({JOSEVirtualHSM, node}, {:decrypt, jwe, kids, alg, enc}, timeout) do
      {:ok, _} = result ->
        result

      {:error, _} ->
        do_decrypt(jwe, rest, alg, enc, timeout)
    end
  end

  @doc false
  @spec register_public_key(node(), JOSEUtils.JWK.t()) :: any()
  def register_public_key(node, jwk_pub) do
    GenServer.cast(__MODULE__, {:register, node, jwk_pub})
  end

  # GenServer callbacks

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    Process.flag(:sensitive, true)
    :net_kernel.monitor_nodes(true)

    :ets.new(@pub_keys_tab, [:named_table, read_concurrency: true])
    jwk_priv_ets = :ets.new(nil, [:private, read_concurrency: true])

    state =
      opts
      |> Map.put(:jwk_priv_ets, jwk_priv_ets)
      |> Map.put(:worker_pids, %{})

    load_keys(state)

    {:ok, state}
  end

  @impl true
  def format_status(_reason, [_pdict, _state]) do
    nil
  end

  @impl true
  def handle_call({:sign, kid, alg_or_algs_or_nil, payload}, from, state) do
    case GenServer.start_link(Worker, []) do
      {:ok, pid} ->
        [{_kid, jwk_priv}] = :ets.lookup(state.jwk_priv_ets, kid)

        state = %{state | worker_pids: Map.put(state.worker_pids, pid, from)}

        GenServer.cast(pid, {:sign, from, jwk_priv, alg_or_algs_or_nil, payload})

        {:noreply, state}

      {:error, reason} ->
        {:reply, {:error, %WorkerError{reason: reason}}, state}
    end
  end

  def handle_call({:decrypt, jwe, kids, enc_alg, enc_enc}, from, state) do
    case GenServer.start_link(Worker, []) do
      {:ok, pid} ->
        jwks_priv =
          for kid <- kids,
              do: :ets.lookup(state.jwk_priv_ets, kid) |> List.first() |> elem(1)

        state = %{state | worker_pids: Map.put(state.worker_pids, pid, from)}

        GenServer.cast(pid, {:decrypt, from, jwks_priv, jwe, enc_alg, enc_enc})

        {:noreply, state}

      {:error, reason} ->
        {:reply, {:error, %WorkerError{reason: reason}}, state}
    end
  end

  @impl true
  def handle_cast({:register, node, jwk_pub}, state) do
    do_register_public_key(jwk_pub, node)

    Logger.info("#{__MODULE__}: registered new key `#{jwk_pub["kid"]}` from `#{node}`")

    {:noreply, state}
  end

  @impl true
  def handle_info({:nodeup, from_node}, state) do
    case :rpc.call(from_node, __MODULE__, :public_keys, [[local_only: true]]) do
      remote_jwk_pubs when is_list(remote_jwk_pubs) ->
        for jwk_pub <- remote_jwk_pubs do
          do_register_public_key(jwk_pub, from_node)

          Logger.info("#{__MODULE__}: registered new key `#{jwk_pub["kid"]}` from `#{from_node}`")
        end

      _ ->
        Logger.info("#{__MODULE__}: node `#{from_node}` joined, #{__MODULE__} not running on it")
    end

    {:noreply, state}
  end

  def handle_info({:nodedown, from_node}, state) do
    @pub_keys_tab
    |> :ets.tab2list()
    |> Enum.each(fn
      {kid, jwk_pub, nodes} ->
        if from_node in nodes and node() not in nodes do
          :ets.delete(@pub_keys_tab, kid)

          Logger.info("#{__MODULE__}: deleted key `#{kid}` of disconnected `#{from_node}`")
        else
          :ets.insert(@pub_keys_tab, {kid, jwk_pub, nodes -- [from_node]})
        end

      _ ->
        :ok
    end)

    {:noreply, state}
  end

  def handle_info({:EXIT, from_pid, reason}, state) do
    {calling_process, worker_pids} = Map.pop(state.worker_pids, from_pid)

    e =
      case reason do
        {reason, _stacktrace} ->
          %WorkerError{reason: reason}

        reason ->
          %WorkerError{reason: reason}
      end

    if reason != :normal, do: GenServer.reply(calling_process, {:error, e})

    {:noreply, Map.put(state, :worker_pids, worker_pids)}
  end

  defp do_register_public_key(jwk_pub, from_node) do
    node_list =
      case :ets.lookup(@pub_keys_tab, jwk_pub["kid"]) do
        [{_kid, ^jwk_pub, node_list}] ->
          node_list
          |> MapSet.new()
          |> MapSet.put(from_node)
          |> MapSet.to_list()

        [] ->
          [from_node]
      end

    :ets.insert(@pub_keys_tab, {jwk_pub["kid"], jwk_pub, node_list})
  end

  defp load_keys(state) do
    for key_conf <- state[:keys] || Application.get_env(:jose_virtual_hsm, :keys, []) do
      jwk_priv = load_key(key_conf, state)

      :ets.insert(state.jwk_priv_ets, {jwk_priv["kid"], jwk_priv})

      jwk_pub = JOSEUtils.JWK.to_public(jwk_priv)

      :ets.insert(@pub_keys_tab, {jwk_pub["kid"], jwk_pub, [node()]})

      notify_new_key(jwk_pub)
    end
  end

  @spec load_key(key_load_spec(), map()) :: JOSEUtils.JWK.t()
  defp load_key({op, params}, state) do
    load_key({op, params, %{}}, state)
  end

  defp load_key({:auto_gen, {:okp, :Ed448}, %{"use" => "enc"}}, _) do
    raise "`:Ed448` cannot be used for encryption (use `:X448` instead)"
  end

  defp load_key({:auto_gen, {:okp, :Ed25519}, %{"use" => "enc"}}, _) do
    raise "`:Ed25519` cannot be used for encryption (use `:X25519` instead)"
  end

  defp load_key({:auto_gen, {:okp, :X448}, %{"use" => "sig"}}, _) do
    raise "`:X448` cannot be used for signature (use `:Ed448` instead)"
  end

  defp load_key({:auto_gen, {:okp, :X25519}, %{"use" => "sig"}}, _) do
    raise "`:X25519` cannot be used for signature (use `:Ed25519` instead)"
  end

  defp load_key({:auto_gen, key_params, key_fields}, _state) do
    key_params
    |> JOSE.JWK.generate_key()
    |> JOSE.JWK.to_map()
    |> elem(1)
    |> thumbprint_jwk()
    |> jwk_add_fields(key_fields)
  end

  defp load_key({:pem_file, path, key_fields}, state) do
    jwk_priv =
      path
      |> JOSE.JWK.from_pem_file()
      |> JOSE.JWK.to_map()
      |> elem(1)
      |> thumbprint_jwk()
      |> jwk_add_fields(key_fields)

    if state[:delete_on_load], do: File.rm!(path)

    jwk_priv
  end

  defp load_key({:der_file, path, key_fields}, state) do
    jwk_priv =
      path
      |> JOSE.JWK.from_der_file()
      |> JOSE.JWK.to_map()
      |> elem(1)
      |> thumbprint_jwk()
      |> jwk_add_fields(key_fields)

    if state[:delete_on_load], do: File.rm!(path)

    jwk_priv
  end

  defp load_key({:pem_env, env_var_name, key_fields}, state) do
    jwk_priv =
      env_var_name
      |> System.fetch_env!()
      |> JOSE.JWK.from_pem()
      |> JOSE.JWK.to_map()
      |> elem(1)
      |> thumbprint_jwk()
      |> jwk_add_fields(key_fields)

    if state[:delete_on_load], do: System.delete_env(env_var_name)

    jwk_priv
  end

  defp load_key({:der_env, env_var_name, key_fields}, state) do
    jwk_priv =
      env_var_name
      |> System.fetch_env!()
      |> Base.decode64!()
      |> JOSE.JWK.from_der()
      |> JOSE.JWK.to_map()
      |> elem(1)
      |> thumbprint_jwk()
      |> jwk_add_fields(key_fields)

    if state[:delete_on_load], do: System.delete_env(env_var_name)

    jwk_priv
  end

  defp load_key({:map_env, env_var_name, _key_fields}, state) do
    jwk_priv =
      env_var_name
      |> System.fetch_env!()
      |> Jason.decode!()
      |> thumbprint_jwk()

    if state[:delete_on_load], do: System.delete_env(env_var_name)

    jwk_priv
  end

  defp thumbprint_jwk(jwk_priv) do
    thumbprint =
      jwk_priv
      |> JOSE.JWK.from_map()
      |> JOSE.JWK.thumbprint()

    Map.put(jwk_priv, "kid", thumbprint)
  end

  defp jwk_add_fields(jwk, fields), do: Map.merge(jwk, fields)

  defp notify_new_key(jwk_pub) do
    :rpc.multicall(Node.list(), __MODULE__, :register_public_key, [node(), jwk_pub])
  end
end
