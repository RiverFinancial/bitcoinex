defmodule Bitcoinex.MixProject do
  use Mix.Project

  def project do
    [
      app: :bitcoinex,
      version: "0.1.0",
      elixir: "~> 1.8",
      start_permanent: Mix.env() == :prod,
      dialyzer: dialyzer(),
      deps: deps(),
      aliases: aliases()
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
      {:credo, "~> 1.0.0", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.0.0-rc.6", only: [:dev, :test], runtime: false},
      {:excoveralls, "~> 0.10", only: :test},
      {:mix_test_watch, "~> 0.8", only: :dev, runtime: false},
      {:stream_data, "~> 0.1", only: :test},
      {:libsecp256k1,
       [github: "RiverFinancial/libsecp256k1", manager: :rebar, branch: "add-spec"]},
      {:timex, "~> 3.1"},
      {:decimal, "~> 1.0"}
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
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
        :error_handling,
        :race_conditions
      ],
      ignore_warnings: ".dialyzer_ignore.exs"
    ]
  end

  # Use a custom PLT directory for CI caching.
  defp plt_file do
    {:no_warn, "_plts/dialyzer.plt"}
  end
end
