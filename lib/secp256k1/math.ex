defmodule Bitcoinex.Secp256k1.Math do
  @moduledoc """
  Contains math utilities when dealing with secp256k1 curve points and scalars.

  All of the addition and multiplication uses the secp256k1 curve paramaters.

  Several of the jacobian multiplication and addition functions are borrowed heavily from https://github.com/starkbank/ecdsa-elixir/.
  """
  alias Bitcoinex.Secp256k1.{Params, Point}

  @doc """
  ipow performs integer pow,
  where x is raised to the power of y.
  """
  @spec ipow(integer, integer) :: integer
  def ipow(x, y, acc \\ 1)
  def ipow(x, y, acc) when y > 0, do: ipow(x, y - 1, x * acc)
  def ipow(_x, _y, acc), do: acc

  @doc """
  Inv performs the Extended Euclidean Algorithm to to find
  the inverse of a number x mod n.
  """
  @spec inv(integer, integer) :: integer
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

  @spec modulo(integer, integer) :: integer
  def modulo(x, n) do
    r = rem(x, n)
    if r < 0, do: r + n, else: r
  end

  @doc """
  multiply accepts a point P and scalar n and,
  does jacobian multiplication to return resulting point.
  """
  def multiply(p, n) do
    p
    |> toJacobian()
    |> jacobianMultiply(n)
    |> fromJacobian()
  end

  @doc """
  add accepts points p and q and,
  does jacobian addition to return resulting point.
  """
  def add(p, q) do
    jacobianAdd(toJacobian(p), toJacobian(q))
    |> fromJacobian()
  end

  # Convert our point P to jacobian coordinates.
  defp toJacobian(p) do
    %Point{x: p.x, y: p.y, z: 1}
  end

  # Convert our jacobian coordinates to a point P on secp256k1 curve.
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

  # double Point P to get point P + P
  # We use the dbl-1998-cmo-2 doubling formula.
  # For reference, http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html.
  defp jacobianDouble(p) do
    if p.y == 0 do
      %Point{x: 0, y: 0, z: 0}
    else
      # XX = X1^2
      xsq =
        ipow(p.x, 2)
        |> modulo(Params.curve().p)

      # YY = Y1^2
      ysq =
        ipow(p.y, 2)
        |> modulo(Params.curve().p)

      # S = 4 * X1 * YY
      s =
        (4 * p.x * ysq)
        |> modulo(Params.curve().p)

      # M = 3 * XX + a * Z1^4
      m =
        (3 * xsq + Params.curve().a * ipow(p.z, 4))
        |> modulo(Params.curve().p)

      # T = M^2 - 2 * S
      t =
        (ipow(m, 2) - 2 * s)
        |> modulo(Params.curve().p)

      # X3 = T
      nx = t

      # Y3 = M * (S - T) - 8 * YY^2
      ny =
        (m * (s - t) - 8 * ipow(ysq, 2))
        |> modulo(Params.curve().p)

      # Z3 = 2 * Y1 * Z1
      nz =
        (2 * p.y * p.z)
        |> modulo(Params.curve().p)

      %Point{x: nx, y: ny, z: nz}
    end
  end

  # add points P and Q to get P + Q
  # We use the add-1998-cmo-2 addition formula.
  # For reference, http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html.
  defp jacobianAdd(p, q) do
    if p.y == 0 do
      q
    else
      if q.y == 0 do
        p
      else
        # U1 = X1 * Z2^2
        u1 =
          (p.x * ipow(q.z, 2))
          |> modulo(Params.curve().p)

        # U2 = X2 * Z2^2
        u2 =
          (q.x * ipow(p.z, 2))
          |> modulo(Params.curve().p)

        # S1 = Y1 * Z2^3
        s1 =
          (p.y * ipow(q.z, 3))
          |> modulo(Params.curve().p)

        # S2 = y2 * Z1^3
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
          # H = U2 - U1
          h = u2 - u1

          # r = S2 - S1
          r = s2 - s1

          # HH = H^2
          h2 =
            (h * h)
            |> modulo(Params.curve().p)

          # HHH = H * HH
          h3 =
            (h * h2)
            |> modulo(Params.curve().p)

          # V = U1 * HH
          v =
            (u1 * h2)
            |> modulo(Params.curve().p)

          # X3 = 42 - HHH - 2 * V
          nx =
            (ipow(r, 2) - h3 - 2 * v)
            |> modulo(Params.curve().p)

          # Y3 = r * (V - X3) - S1 * HHH
          ny =
            (r * (v - nx) - s1 * h3)
            |> modulo(Params.curve().p)

          # Z3 = Z1 * Z2 * H
          nz =
            (h * p.z * q.z)
            |> modulo(Params.curve().p)

          %Point{x: nx, y: ny, z: nz}
        end
      end
    end
  end

  # multply point P with scalar n
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
       # This integer is n, the integer order of G for secp256k1.
       # Unfortunately cannot call Params.curve.n to get the curve order integer,
       # so instead, it is pasted it here.
       # In the future we should move it back to Params.
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
