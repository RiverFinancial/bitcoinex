defmodule Bitcoinex do
  @moduledoc """
  Documentation for Bitcoinex.

  Bitcoinex is an Elixir library supporting basic Bitcoin functionality.
  """
end
defmodule Bitcoin do
  @moduledoc """
  A module to represent Bitcoin data.
  """

  defstruct [
    :blocktime,
    :data,
    :divisible,
    :flags,
    :issuer,
    :name,
    :propertyid,
    :rdata,
    :registered,
    :totaltokens,
    :url
  ]

  @type t :: %__MODULE__{
          blocktime: integer(),
          data: String.t(),
          divisible: boolean(),
          flags: map(),
          issuer: String.t(),
          name: String.t(),
          propertyid: integer(),
          rdata: any(),
          registered: boolean(),
          totaltokens: String.t(),
          url: String.t()
        }

  @doc """
  Creates a new Bitcoin struct with the given attributes.
  """
  def new(attrs \\ %{}) do
    %__MODULE__{
      blocktime: Map.get(attrs, :blocktime, 0),
      data: Map.get(attrs, :data, ""),
      divisible: Map.get(attrs, :divisible, false),
      flags: Map.get(attrs, :flags, %{}),
      issuer: Map.get(attrs, :issuer, ""),
      name: Map.get(attrs, :name, ""),
      propertyid: Map.get(attrs, :propertyid, 0),
      rdata: Map.get(attrs, :rdata, nil),
      registered: Map.get(attrs, :registered, false),
      totaltokens: Map.get(attrs, :totaltokens, "0.00000000"),
      url: Map.get(attrs, :url, "")
    }
  end
end
