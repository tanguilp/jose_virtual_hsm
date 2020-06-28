defmodule JOSEVirtualHSM.Worker do
  @moduledoc false

  @behaviour GenServer

  alias JOSEVirtualHSM.{DecryptionError, NoSuitableAlgFoundError}

  def start_link(_) do
    GenServer.start_link(__MODULE__, nil)
  end

  @impl true
  def init(_) do
    Process.flag(:sensitive, true)

    {:ok, nil}
  end

  @impl true
  def format_status(_reason, [_pdict, _state]) do
    nil
  end

  @impl true
  def handle_cast({:sign, calling_process, jwk_priv, alg_or_algs_or_nil, payload}, _) do
    case select_sig_alg(jwk_priv, alg_or_algs_or_nil) do
      <<_::binary>> = alg ->
        result =
          case JOSEUtils.JWS.sign(payload, jwk_priv, alg) do
            {:ok, signed_content} ->
              {:ok, {signed_content, JOSEUtils.JWK.to_public(jwk_priv)}}

            {:error, _} = error ->
              error
          end

        GenServer.reply(calling_process, result)

      nil ->
        GenServer.reply(calling_process, {:error, %NoSuitableAlgFoundError{}})
    end

    {:stop, :normal, nil}
  end

  def handle_cast({:encrypt_ecdh, calling_process, jwk_priv, jwk, alg, enc, payload}, _) do
    case JOSEUtils.JWE.encrypt(payload, {jwk, jwk_priv}, alg, enc) do
      {:ok, jwe} ->
        GenServer.reply(calling_process, {:ok, {jwe, jwk}})

      {:error, _} = error ->
        GenServer.reply(calling_process, error)
    end

    {:stop, :normal, nil}
  end

  def handle_cast({:decrypt, calling_process, jwks_priv, jwe, enc_alg, enc_enc}, _) do
    case JOSEUtils.JWE.decrypt(jwe, jwks_priv, [enc_alg], [enc_enc]) do
      {:ok, _} = result ->
        GenServer.reply(calling_process, result)

      :error ->
        GenServer.reply(calling_process, {:error, %DecryptionError{}})
    end

    {:stop, :normal, nil}
  end

  defp select_sig_alg(jwk_priv, <<_::binary>> = alg) do
    if alg in JOSEUtils.JWK.sig_algs_supported(jwk_priv), do: alg
  end

  defp select_sig_alg(_jwk_priv, []) do
    nil
  end

  defp select_sig_alg(jwk_priv, [_ | _] = algs) do
    jwk_supported_algs = jwk_priv |> JOSEUtils.JWK.sig_algs_supported() |> MapSet.new()
    algs_allowed = MapSet.new(algs)

    MapSet.intersection(jwk_supported_algs, algs_allowed) |> Enum.at(0)
  end

  defp select_sig_alg(jwk_priv, nil) do
    jwk_priv |> JOSEUtils.JWK.sig_algs_supported() |> Enum.at(0)
  end
end
