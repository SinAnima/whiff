defmodule Saltmere.MixProject do
  use Mix.Project

  def project do
    [
      app: :saltmere_berths,
      version: "1.4.0",
      elixir: "~> 1.17",
      description: "Berth bookings for Saltmere Harbour",
      source_url: "https://git.harbour.test/berths",
      package: [licenses: ["CC0-1.0"]],
      deps: deps()
    ]
  end

  defp deps do
    [
      {:phoenix, "~> 1.7"},
      {:jason, "~> 1.4"},
      {:tide_model, git: "https://git.harbour.test/tide_model.git", tag: "v0.3.0"},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end
end
