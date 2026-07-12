defmodule Plausible.Plugs.SSOTeamAccess do
  @moduledoc """
  Plug ensuring user is permitted to access the team
  if it has SSO setup with Force SSO policy.  
  """

  use Plausible

  def init(_) do
    []
  end

  # SGC: un-gated from on_ee — force-SSO must be enforceable on the CE build.
  import Phoenix.Controller, only: [redirect: 2]
  import Plug.Conn

  alias PlausibleWeb.Router.Helpers, as: Routes

  def call(conn, _opts) do
    current_user = conn.assigns[:current_user]
    current_team = conn.assigns[:current_team]

    # SGC: owners are exempt (upstream walls standard owners to the provision
    # notice too, which would kill the break-glass admin@sgc.ai password path —
    # `all_but_owners` should mean what it says).
    eligible_for_check? =
      not is_nil(current_user) and
        not is_nil(current_team) and
        conn.assigns[:current_team_role] != :owner and
        current_team.policy.force_sso == :all_but_owners and
        Plausible.Users.type(current_user) == :standard

    if eligible_for_check? do
      check_user(conn, current_user, current_team)
    else
      conn
    end
  end

  defp check_user(conn, user, team) do
    conn =
      case Plausible.Auth.SSO.check_ready_to_provision(user, team) do
        :ok ->
          redirect(conn, to: Routes.sso_path(conn, :provision_notice))

        {:error, issue} ->
          redirect(conn, to: Routes.sso_path(conn, :provision_issue, issue: issue))
      end

    halt(conn)
  end
end
