defmodule JOSEVirtualHSM.MixProject do
  use Mix.Project

  def project do
    [
      app: :jose_virtual_hsm,
      description: "Virtual JOSE HSM for signing JWSes and decrypting JWEs",
      version: "0.2.0",
      elixir: "~> 1.9",
      start_permanent: Mix.env() == :prod,
      docs: [
        main: "readme",
        extras: ["README.md"]
      ],
      deps: deps(),
      package: package(),
      source_url: "https://github.com/tanguilp/jose_virtual_hsm"
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:dialyxir, "~> 1.0.0-rc.4", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false},
      {:jose_utils, "~> 0.3.0"}
    ]
  end

  def package() do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => "https://github.com/tanguilp/jose_virtual_hsm"}
    ]
  end
end
