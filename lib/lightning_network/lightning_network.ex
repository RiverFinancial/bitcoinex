defmodule Bitcoinex.LightningNetwork do
  alias Bitcoinex.LightningNetwork.Invoice

  # defdelegate encode_invoice(invoice), to: Invoice, as: :encode
  defdelegate decode_invoice(invoice), to: Invoice, as: :decode
end
