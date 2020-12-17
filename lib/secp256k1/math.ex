defmodule Bitcoinex.Secp256k1.Math do
  @moduledoc """
  Contains math utilities when dealing with secp256k1 curve points and scalars.

  Several of the jacobian multiplication and addition functions are borrowed heavily from https://github.com/starkbank/ecdsa-elixir/.
  """
  alias Bitcoinex.Secp256k1.{Params, Point}

  def ipow(n, k, acc \\ 1)
  def ipow(n, k, acc) when k > 0, do: ipow(n, k - 1, n * acc)
  def ipow(_n, _k, acc), do: acc

  # EEA. x is divisor, n is mod.
  def inv(x, _n) when x == 0, do: 0
  def inv(x, n), do: inv(1, 0, modulo(x, n), n) |> modulo(n)

  defp inv(lm, hm, low, high) when low > 1 do
    r = div(high, low)

    inv(
      hm - lm * r,
      lm,
      high - low * r,
      low
    )
  end

  defp inv(lm, _hm, _low, _high) do
    lm
  end

  def modulo(x, n) do
    r = rem(x, n)
    if r < 0, do: r + n, else: r
  end

  def multiply(p, n) do
    p
    |> toJacobian()
    |> jacobianMultiply(n)
    |> fromJacobian()
  end

  def add(p, q) do
    jacobianAdd(toJacobian(p), toJacobian(q))
    |> fromJacobian()
  end

  defp toJacobian(p) do
    %Point{x: p.x, y: p.y, z: 1}
  end

  defp fromJacobian(p) do
    z = inv(p.z, Params.curve().p)

    %Point{
      x:
        modulo(
          p.x * ipow(z, 2),
          Params.curve().p
        ),
      y:
        modulo(
          p.y * ipow(z, 3),
          Params.curve().p
        )
    }
  end

  defp jacobianDouble(p) do
    if p.y == 0 do
      %Point{x: 0, y: 0, z: 0}
    else
      ysq =
        ipow(p.y, 2)
        |> modulo(Params.curve().p)

      s =
        (4 * p.x * ysq)
        |> modulo(Params.curve().p)

      m =
        (3 * ipow(p.x, 2) + Params.curve().a * ipow(p.z, 4))
        |> modulo(Params.curve().p)

      nx =
        (ipow(m, 2) - 2 * s)
        |> modulo(Params.curve().p)

      ny =
        (m * (s - nx) - 8 * ipow(ysq, 2))
        |> modulo(Params.curve().p)

      nz =
        (2 * p.y * p.z)
        |> modulo(Params.curve().p)

      %Point{x: nx, y: ny, z: nz}
    end
  end

  defp jacobianAdd(p, q) do
    if p.y == 0 do
      q
    else
      if q.y == 0 do
        p
      else
        u1 =
          (p.x * ipow(q.z, 2))
          |> modulo(Params.curve().p)

        u2 =
          (q.x * ipow(p.z, 2))
          |> modulo(Params.curve().p)

        s1 =
          (p.y * ipow(q.z, 3))
          |> modulo(Params.curve().p)

        s2 =
          (q.y * ipow(p.z, 3))
          |> modulo(Params.curve().p)

        if u1 == u2 do
          if s1 != s2 do
            %Point{x: 0, y: 0, z: 1}
          else
            jacobianDouble(p)
          end
        else
          h = u2 - u1

          r = s2 - s1

          h2 =
            (h * h)
            |> modulo(Params.curve().p)

          h3 =
            (h * h2)
            |> modulo(Params.curve().p)

          u1h2 =
            (u1 * h2)
            |> modulo(Params.curve().p)

          nx =
            (ipow(r, 2) - h3 - 2 * u1h2)
            |> modulo(Params.curve().p)

          ny =
            (r * (u1h2 - nx) - s1 * h3)
            |> modulo(Params.curve().p)

          nz =
            (h * p.z * q.z)
            |> modulo(Params.curve().p)

          %Point{x: nx, y: ny, z: nz}
        end
      end
    end
  end

  defp jacobianMultiply(_p, n) when n == 0 do
    %Point{x: 0, y: 0, z: 1}
  end

  defp jacobianMultiply(p, n) when n == 1 do
    if p.y == 0 do
      %Point{x: 0, y: 0, z: 1}
    else
      p
    end
  end

  defp jacobianMultiply(p, n)
       # curve.n
       when n < 0 or
              n >
                115_792_089_237_316_195_423_570_985_008_687_907_852_837_564_279_074_904_382_605_163_141_518_161_494_337 do
    if p.y == 0 do
      %Point{x: 0, y: 0, z: 1}
    else
      jacobianMultiply(p, modulo(n, Params.curve().n))
    end
  end

  defp jacobianMultiply(p, n) when rem(n, 2) == 0 do
    if p.y == 0 do
      %Point{x: 0, y: 0, z: 1}
    else
      jacobianMultiply(p, div(n, 2))
      |> jacobianDouble()
    end
  end

  defp jacobianMultiply(p, n) do
    if p.y == 0 do
      %Point{x: 0, y: 0, z: 1}
    else
      jacobianMultiply(p, div(n, 2))
      |> jacobianDouble()
      |> jacobianAdd(p)
    end
  end
end
