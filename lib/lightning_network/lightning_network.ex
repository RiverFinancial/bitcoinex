defmodule Bitcoin.LightningNetwork do
  alias Bitcoinex.LightningNetwork.Invoice

  # defdelegate encode_invoice(invoice), to: Invoice, as: :encode
  defdelegate encode_decode(invoice), to: Invoice, as: :decode
end
