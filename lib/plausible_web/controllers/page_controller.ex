defmodule PlausibleWeb.PageController do
  use PlausibleWeb, :controller
  use Plausible.Repo

  plug PlausibleWeb.RequireLoggedOutPlug

  @doc """
  The root path is never accessible in Plausible.Cloud because it is handled by the upstream reverse proxy.

  This controller action is only ever triggered in self-hosted Plausible.
  """
  # SGC Authentik-first: logged-out visitors go straight to login (which
  # redirects into the Authentik SAML flow) instead of the generic Plausible
  # landing page. RequireLoggedOutPlug above already sends logged-in users to
  # their dashboard.
  def index(conn, _params) do
    redirect(conn, to: Routes.auth_path(conn, :login_form))
  end
end
