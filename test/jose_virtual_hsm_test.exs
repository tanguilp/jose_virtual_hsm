defmodule JOSEVirtualHSMTest do
  use ExUnit.Case

  alias JOSEVirtualHSM.{DecryptionError, NoSuitableKeyFoundError}

  @keys [
    {:auto_gen, {:ec, "P-256"}, %{"use" => "sig"}},
    {:auto_gen, {:rsa, 2048}, %{"use" => "sig"}},
    {:auto_gen, {:okp, :Ed25519}, %{"use" => "sig"}},
    {:auto_gen, {:ec, "P-256"}, %{"use" => "enc"}},
    {:auto_gen, {:rsa, 2048}, %{"use" => "enc"}},
    {:auto_gen, {:okp, :X25519}, %{"use" => "enc"}}
  ]

  describe "key loading" do
    test "can load an RSA key" do
      assert {:ok, pid} = JOSEVirtualHSM.start_link(keys: [{:auto_gen, {:rsa, 1024}}])
      assert [%{"kty" => "RSA"}] = JOSEVirtualHSM.public_keys()

      Process.exit(pid, :kill)
    end

    test "can load an RSA key with custom field" do
      assert {:ok, pid} =
               JOSEVirtualHSM.start_link(keys: [{:auto_gen, {:rsa, 1024}, %{"some" => "field"}}])

      assert [%{"kty" => "RSA", "some" => "field"}] = JOSEVirtualHSM.public_keys()

      Process.exit(pid, :kill)
    end

    test "can load an EC key curve P-256" do
      assert {:ok, pid} = JOSEVirtualHSM.start_link(keys: [{:auto_gen, {:ec, "P-256"}}])
      assert [%{"kty" => "EC", "crv" => "P-256"}] = JOSEVirtualHSM.public_keys()

      Process.exit(pid, :kill)
    end

    test "can load an EC key curve P-256 with custom field" do
      assert {:ok, pid} =
               JOSEVirtualHSM.start_link(
                 keys: [{:auto_gen, {:ec, "P-256"}, %{"some" => "field"}}]
               )

      assert [%{"kty" => "EC", "crv" => "P-256", "some" => "field"}] =
               JOSEVirtualHSM.public_keys()

      Process.exit(pid, :kill)
    end

    test "can load an EC key curve P-384" do
      assert {:ok, pid} = JOSEVirtualHSM.start_link(keys: [{:auto_gen, {:ec, "P-384"}}])
      assert [%{"kty" => "EC", "crv" => "P-384"}] = JOSEVirtualHSM.public_keys()

      Process.exit(pid, :kill)
    end

    test "can load an EC key curve P-384 with custom field" do
      assert {:ok, pid} =
               JOSEVirtualHSM.start_link(
                 keys: [{:auto_gen, {:ec, "P-384"}, %{"some" => "field"}}]
               )

      assert [%{"kty" => "EC", "crv" => "P-384", "some" => "field"}] =
               JOSEVirtualHSM.public_keys()

      Process.exit(pid, :kill)
    end

    test "can load an EC key curve P-521" do
      assert {:ok, pid} = JOSEVirtualHSM.start_link(keys: [{:auto_gen, {:ec, "P-521"}}])
      assert [%{"kty" => "EC", "crv" => "P-521"}] = JOSEVirtualHSM.public_keys()

      Process.exit(pid, :kill)
    end

    test "can load an EC key curve P-521 with custom field" do
      assert {:ok, pid} =
               JOSEVirtualHSM.start_link(
                 keys: [{:auto_gen, {:ec, "P-521"}, %{"some" => "field"}}]
               )

      assert [%{"kty" => "EC", "crv" => "P-521", "some" => "field"}] =
               JOSEVirtualHSM.public_keys()

      Process.exit(pid, :kill)
    end

    test "can load an OKP key Ed25519" do
      assert {:ok, pid} = JOSEVirtualHSM.start_link(keys: [{:auto_gen, {:okp, :Ed25519}}])
      assert [%{"kty" => "OKP", "crv" => "Ed25519"}] = JOSEVirtualHSM.public_keys()

      Process.exit(pid, :kill)
    end

    test "can load an EC key Ed25519 with custom field" do
      assert {:ok, pid} =
               JOSEVirtualHSM.start_link(
                 keys: [{:auto_gen, {:okp, :Ed25519}, %{"some" => "field"}}]
               )

      assert [%{"kty" => "OKP", "crv" => "Ed25519", "some" => "field"}] =
               JOSEVirtualHSM.public_keys()

      Process.exit(pid, :kill)
    end

    test "can load an OKP key Ed448" do
      assert {:ok, pid} = JOSEVirtualHSM.start_link(keys: [{:auto_gen, {:okp, :Ed448}}])
      assert [%{"kty" => "OKP", "crv" => "Ed448"}] = JOSEVirtualHSM.public_keys()

      Process.exit(pid, :kill)
    end

    test "can load an EC key Ed448 with custom field" do
      assert {:ok, pid} =
               JOSEVirtualHSM.start_link(
                 keys: [{:auto_gen, {:okp, :Ed448}, %{"some" => "field"}}]
               )

      assert [%{"kty" => "OKP", "crv" => "Ed448", "some" => "field"}] =
               JOSEVirtualHSM.public_keys()

      Process.exit(pid, :kill)
    end

    test "can load an OKP key X25519" do
      assert {:ok, pid} = JOSEVirtualHSM.start_link(keys: [{:auto_gen, {:okp, :X25519}}])
      assert [%{"kty" => "OKP", "crv" => "X25519"}] = JOSEVirtualHSM.public_keys()

      Process.exit(pid, :kill)
    end

    test "can load an EC key X25519 with custom field" do
      assert {:ok, pid} =
               JOSEVirtualHSM.start_link(
                 keys: [{:auto_gen, {:okp, :X25519}, %{"some" => "field"}}]
               )

      assert [%{"kty" => "OKP", "crv" => "X25519", "some" => "field"}] =
               JOSEVirtualHSM.public_keys()

      Process.exit(pid, :kill)
    end

    test "can load an OKP key X448" do
      assert {:ok, pid} = JOSEVirtualHSM.start_link(keys: [{:auto_gen, {:okp, :X448}}])
      assert [%{"kty" => "OKP", "crv" => "X448"}] = JOSEVirtualHSM.public_keys()

      Process.exit(pid, :kill)
    end

    test "can load an EC key X448 with custom field" do
      assert {:ok, pid} =
               JOSEVirtualHSM.start_link(keys: [{:auto_gen, {:okp, :X448}, %{"some" => "field"}}])

      assert [%{"kty" => "OKP", "crv" => "X448", "some" => "field"}] =
               JOSEVirtualHSM.public_keys()

      Process.exit(pid, :kill)
    end

    test "can load a PEM file" do
      private_pem = X509.PrivateKey.new_ec(:secp256r1) |> X509.PrivateKey.to_pem()
      File.write!("private.pem", private_pem)

      assert {:ok, pid} = JOSEVirtualHSM.start_link(keys: [{:pem_file, "private.pem"}])
      assert [%{}] = JOSEVirtualHSM.public_keys()
      refute File.exists?("private.pem")

      Process.exit(pid, :kill)
    end

    test "can load a PEM file with custom field" do
      private_pem = X509.PrivateKey.new_ec(:secp256r1) |> X509.PrivateKey.to_pem()
      File.write!("private.pem", private_pem)

      assert {:ok, pid} =
               JOSEVirtualHSM.start_link(keys: [{:pem_file, "private.pem", %{"some" => "field"}}])

      assert [%{"some" => "field"}] = JOSEVirtualHSM.public_keys()
      refute File.exists?("private.pem")

      Process.exit(pid, :kill)
    end

    test "can load a DER file" do
      private_der = X509.PrivateKey.new_ec(:secp256r1) |> X509.PrivateKey.to_der()
      File.write!("private.der", private_der)

      assert {:ok, pid} = JOSEVirtualHSM.start_link(keys: [{:der_file, "private.der"}])
      assert [%{}] = JOSEVirtualHSM.public_keys()
      refute File.exists?("private.der")

      Process.exit(pid, :kill)
    end

    test "can load a DER file with custom field" do
      private_der = X509.PrivateKey.new_ec(:secp256r1) |> X509.PrivateKey.to_der()
      File.write!("private.der", private_der)

      assert {:ok, pid} =
               JOSEVirtualHSM.start_link(keys: [{:der_file, "private.der", %{"some" => "field"}}])

      assert [%{"some" => "field"}] = JOSEVirtualHSM.public_keys()
      refute File.exists?("private.der")

      Process.exit(pid, :kill)
    end

    test "can load a PEM from env" do
      private_pem = X509.PrivateKey.new_ec(:secp256r1) |> X509.PrivateKey.to_pem()
      :ok = System.put_env("PRIV_PEM", private_pem)

      assert {:ok, pid} = JOSEVirtualHSM.start_link(keys: [{:pem_env, "PRIV_PEM"}])
      assert [%{}] = JOSEVirtualHSM.public_keys()
      assert System.get_env("PRIV_PEM") == nil

      Process.exit(pid, :kill)
    end

    test "can load a PEM from env with custom field" do
      private_pem = X509.PrivateKey.new_ec(:secp256r1) |> X509.PrivateKey.to_pem()
      :ok = System.put_env("PRIV_PEM", private_pem)

      assert {:ok, pid} =
               JOSEVirtualHSM.start_link(keys: [{:pem_env, "PRIV_PEM", %{"some" => "field"}}])

      assert [%{"some" => "field"}] = JOSEVirtualHSM.public_keys()
      assert System.get_env("PRIV_PEM") == nil

      Process.exit(pid, :kill)
    end

    test "can load a DER from env" do
      private_der = X509.PrivateKey.new_ec(:secp256r1) |> X509.PrivateKey.to_der()
      :ok = System.put_env("PRIV_DER", Base.encode64(private_der))

      assert {:ok, pid} = JOSEVirtualHSM.start_link(keys: [{:der_env, "PRIV_DER"}])
      assert [%{}] = JOSEVirtualHSM.public_keys()
      assert System.get_env("PRIV_DER") == nil

      Process.exit(pid, :kill)
    end

    test "can load a DER from env with custom field" do
      private_der = X509.PrivateKey.new_ec(:secp256r1) |> X509.PrivateKey.to_der()
      :ok = System.put_env("PRIV_DER", Base.encode64(private_der))

      assert {:ok, pid} =
               JOSEVirtualHSM.start_link(keys: [{:der_env, "PRIV_DER", %{"some" => "field"}}])

      assert [%{"some" => "field"}] = JOSEVirtualHSM.public_keys()
      assert System.get_env("PRIV_DER") == nil

      Process.exit(pid, :kill)
    end

    test "can load a map from env" do
      jwk_str =
        JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_map() |> elem(1) |> Jason.encode!()

      :ok = System.put_env("PRIV_JWK", jwk_str)

      assert {:ok, pid} = JOSEVirtualHSM.start_link(keys: [{:map_env, "PRIV_JWK"}])
      assert [%{}] = JOSEVirtualHSM.public_keys()
      assert System.get_env("PRIV_JWK") == nil

      Process.exit(pid, :kill)
    end
  end

  describe ".sign/2" do
    setup :start

    test "signing with any key" do
      assert {:ok, {jws, jwk}} = JOSEVirtualHSM.sign("test")
      assert {:ok, {"test", _}} = JOSEUtils.JWS.verify(jws, JOSEVirtualHSM.public_keys(), algs())
    end

    test "signing with an RSA key" do
      assert {:ok, {jws, jwk}} = JOSEVirtualHSM.sign("test", kty: "RSA")

      assert {:ok, {"test", _}} =
               JOSEUtils.JWS.verify(
                 jws,
                 JOSEVirtualHSM.public_keys(),
                 ["PS256", "PS384", "PS512", "RS256", "RS384", "RS512"]
               )
    end

    test "signing with an EC key" do
      assert {:ok, {jws, jwk}} = JOSEVirtualHSM.sign("test", kty: "EC")

      assert {:ok, {"test", _}} =
               JOSEUtils.JWS.verify(jws, JOSEVirtualHSM.public_keys(), ["ES256", "ES384", "ES512"])
    end

    test "signing with an OKP key" do
      assert {:ok, {jws, jwk}} = JOSEVirtualHSM.sign("test", kty: "OKP")

      assert {:ok, {"test", _}} =
               JOSEUtils.JWS.verify(jws, JOSEVirtualHSM.public_keys(), ["EdDSA"])
    end

    test "signing fail when no matching key is found" do
      assert {:error, %NoSuitableKeyFoundError{}} = JOSEVirtualHSM.sign("test", kid: "ney")
    end
  end

  describe ".encrypt_ecdh/5" do
    setup :start

    test "encrypt a payload, with ECDH-ES and curve secp256r1" do
      jwk_pub = JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_public_map() |> elem(1)

      assert {:ok, {_, ^jwk_pub}} = JOSEVirtualHSM.encrypt_ecdh("test", jwk_pub, "ECDH-ES", "A128GCM")
    end

    test "encrypt a payload, with ECDH-ES and curve X25519" do
      jwk_pub = JOSE.JWK.generate_key({:okp, :X25519}) |> JOSE.JWK.to_public_map() |> elem(1)

      assert {:ok, {_, ^jwk_pub}} = JOSEVirtualHSM.encrypt_ecdh("test", jwk_pub, "ECDH-ES", "A128GCM")
    end
  end

  describe ".decrypt/2" do
    setup :start

    test "decrypt a JWE encoded with RSA1_5 key derivation alg" do
      jwk_pub =
        JOSEVirtualHSM.public_keys() |> Enum.find(&(&1["kty"] == "RSA" and &1["use"] == "enc"))

      jwe = JOSEUtils.JWE.encrypt!("test", jwk_pub, "RSA1_5", "A128GCM")

      {:ok, {"test", _}} = JOSEVirtualHSM.decrypt(jwe)
    end

    test "decrypt a JWE encoded with RSA-OAEP key derivation alg" do
      jwk_pub =
        JOSEVirtualHSM.public_keys() |> Enum.find(&(&1["kty"] == "RSA" and &1["use"] == "enc"))

      jwe = JOSEUtils.JWE.encrypt!("test", jwk_pub, "RSA-OAEP", "A128GCM")

      {:ok, {"test", _}} = JOSEVirtualHSM.decrypt(jwe)
    end

    test "decrypt a JWE encoded with RSA-OAEP-256 key derivation alg" do
      jwk_pub =
        JOSEVirtualHSM.public_keys() |> Enum.find(&(&1["kty"] == "RSA" and &1["use"] == "enc"))

      jwe = JOSEUtils.JWE.encrypt!("test", jwk_pub, "RSA-OAEP-256", "A128GCM")

      {:ok, {"test", _}} = JOSEVirtualHSM.decrypt(jwe)
    end

    test "decrypt a JWE encoded with ECDH-ES key derivation alg and EC key" do
      jwk_pub =
        JOSEVirtualHSM.public_keys() |> Enum.find(&(&1["kty"] == "EC" and &1["use"] == "enc"))

      my_priv = JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_map() |> elem(1)
      jwe = JOSEUtils.JWE.encrypt!("test", {jwk_pub, my_priv}, "ECDH-ES", "A128GCM")

      {:ok, {"test", _}} = JOSEVirtualHSM.decrypt(jwe)
    end

    test "decrypt a JWE encoded with ECDH-ES+A128KW key derivation alg and EC key" do
      jwk_pub =
        JOSEVirtualHSM.public_keys() |> Enum.find(&(&1["kty"] == "EC" and &1["use"] == "enc"))

      my_priv = JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_map() |> elem(1)
      jwe = JOSEUtils.JWE.encrypt!("test", {jwk_pub, my_priv}, "ECDH-ES+A128KW", "A128GCM")

      {:ok, {"test", _}} = JOSEVirtualHSM.decrypt(jwe)
    end

    test "decrypt a JWE encoded with ECDH-ES+A192KW key derivation alg and EC key" do
      jwk_pub =
        JOSEVirtualHSM.public_keys() |> Enum.find(&(&1["kty"] == "EC" and &1["use"] == "enc"))

      my_priv = JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_map() |> elem(1)
      jwe = JOSEUtils.JWE.encrypt!("test", {jwk_pub, my_priv}, "ECDH-ES+A192KW", "A192GCM")

      {:ok, {"test", _}} = JOSEVirtualHSM.decrypt(jwe)
    end

    test "decrypt a JWE encoded with ECDH-ES+A256KW key derivation alg and EC key" do
      jwk_pub =
        JOSEVirtualHSM.public_keys() |> Enum.find(&(&1["kty"] == "EC" and &1["use"] == "enc"))

      my_priv = JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_map() |> elem(1)
      jwe = JOSEUtils.JWE.encrypt!("test", {jwk_pub, my_priv}, "ECDH-ES+A256KW", "A256GCM")

      {:ok, {"test", _}} = JOSEVirtualHSM.decrypt(jwe)
    end

    test "decrypt a JWE encoded with ECDH-ES key derivation alg and OKP key" do
      jwk_pub =
        JOSEVirtualHSM.public_keys() |> Enum.find(&(&1["kty"] == "OKP" and &1["use"] == "enc"))

      my_priv = JOSE.JWK.generate_key({:okp, :X25519}) |> JOSE.JWK.to_map() |> elem(1)
      jwe = JOSEUtils.JWE.encrypt!("test", {jwk_pub, my_priv}, "ECDH-ES", "A128GCM")

      {:ok, {"test", _}} = JOSEVirtualHSM.decrypt(jwe)
    end

    test "decrypt a JWE encoded with ECDH-ES+A128KW key derivation alg and OKP key" do
      jwk_pub =
        JOSEVirtualHSM.public_keys() |> Enum.find(&(&1["kty"] == "OKP" and &1["use"] == "enc"))

      my_priv = JOSE.JWK.generate_key({:okp, :X25519}) |> JOSE.JWK.to_map() |> elem(1)
      jwe = JOSEUtils.JWE.encrypt!("test", {jwk_pub, my_priv}, "ECDH-ES+A128KW", "A128GCM")

      {:ok, {"test", _}} = JOSEVirtualHSM.decrypt(jwe)
    end

    test "decrypt a JWE encoded with ECDH-ES+A192KW key derivation alg and OKP key" do
      jwk_pub =
        JOSEVirtualHSM.public_keys() |> Enum.find(&(&1["kty"] == "OKP" and &1["use"] == "enc"))

      my_priv = JOSE.JWK.generate_key({:okp, :X25519}) |> JOSE.JWK.to_map() |> elem(1)
      jwe = JOSEUtils.JWE.encrypt!("test", {jwk_pub, my_priv}, "ECDH-ES+A192KW", "A192GCM")

      {:ok, {"test", _}} = JOSEVirtualHSM.decrypt(jwe)
    end

    test "decrypt a JWE encoded with ECDH-ES+A256KW key derivation alg and OKP key" do
      jwk_pub =
        JOSEVirtualHSM.public_keys() |> Enum.find(&(&1["kty"] == "OKP" and &1["use"] == "enc"))

      my_priv = JOSE.JWK.generate_key({:okp, :X25519}) |> JOSE.JWK.to_map() |> elem(1)
      jwe = JOSEUtils.JWE.encrypt!("test", {jwk_pub, my_priv}, "ECDH-ES+A256KW", "A256GCM")

      {:ok, {"test", _}} = JOSEVirtualHSM.decrypt(jwe)
    end

    test "decryption fail when no suitable key is found" do
      jwk_pub = JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_public_map() |> elem(1)
      jwe = JOSEUtils.JWE.encrypt!("test", jwk_pub, "RSA1_5", "A128GCM")

      {:error, %DecryptionError{}} = JOSEVirtualHSM.decrypt(jwe)
    end
  end

  defp algs(),
    do: JOSE.JWA.supports() |> Enum.at(2) |> elem(1) |> elem(1) |> Kernel.++(["EdDSA"])

  defp start(_) do
    {:ok, pid} = JOSEVirtualHSM.start_link(startup: :sync, keys: @keys)

    on_exit(fn -> Process.exit(pid, :kill) end)

    :ok
  end
end
