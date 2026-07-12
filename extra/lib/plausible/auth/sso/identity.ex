defmodule Plausible.Auth.SSO.Identity do
  @moduledoc """
  SSO Identity struct.
  """

  @type t() :: %__MODULE__{}

  @derive Plausible.Audit.Encoder
  @enforce_keys [:id, :integration_id, :name, :email, :expires_at]
  # SGC: `groups` carries the Authentik group names from the SAML assertion,
  # resolved into Plausible access by UserAuth.log_in_user via Sgc.Scope.
  defstruct [:id, :integration_id, :name, :email, :expires_at, groups: []]
end
