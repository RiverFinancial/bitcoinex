defmodule Bitcoinex.Utils do
  @spec sha256(list(integer)) :: binary
  def sha256(str) do
    :crypto.hash(:sha256, str)
  end

  @spec replicate(term(), integer()) :: list(term())
  def replicate(_num, 0) do
    []
  end

  def replicate(x, num) when x > 0 do
    for _ <- 1..num, do: x
  end
end
