defmodule Bitcoinex.MixProject do
  use Mix.Project

  def project do
    [
      app: :bitcoinex,
      version: "0.1.8",
      elixir: "~> 1.11",
      package: package(),
      start_permanent: Mix.env() == :prod,
      dialyzer: dialyzer(),
      deps: deps(),
      aliases: aliases(),
      description: description(),
      source_url: "https://github.com/RiverFinancial/bitcoinex"
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:credo, "~> 1.6", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.2.0", only: [:dev, :test], runtime: false},
      {:excoveralls, "~> 0.10", only: :test},
      {:mix_test_watch, "~> 1.1", only: :dev, runtime: false},
      {:stream_data, "~> 0.1", only: :test},
      {:decimal, "~> 1.0 or ~> 2.0"},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false},
      {:benchee, ">= 1.0.0", only: :dev}
    ]
  end

  defp aliases do
    [
      "lint.all": [
        "format --check-formatted",
        "credo --strict --only warning",
        "dialyzer --halt-exit-status"
      ],
      compile: ["compile --warnings-as-errors"]
    ]
  end

  # Dialyzer configuration
  defp dialyzer do
    [
      plt_file: plt_file(),
      flags: [
        :error_handling
      ],
      ignore_warnings: ".dialyzer_ignore.exs"
    ]
  end

  # Use a custom PLT directory for CI caching.
  defp plt_file do
    {:no_warn, "_plts/dialyzer.plt"}
  end

  defp package do
    [
      files: ~w(lib test .formatter.exs mix.exs README.md UNLICENSE CHANGELOG.md SECURITY.md),
      licenses: ["Unlicense"],
      links: %{"GitHub" => "https://github.com/RiverFinancial/bitcoinex"}
    ]
  end

  defp description() do
    "Bitcoinex is a Bitcoin Library for Elixir."
  end
end
