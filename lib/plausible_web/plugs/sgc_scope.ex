defmodule PlausibleWeb.Plugs.SgcScope do
  @moduledoc """
  Enforces the SGC data boundary for scoped (non-admin) SSO users.

  A scoped user's session carries `:sgc_scope` — `%{"grants" => [%{"site" =>
  domain, "hostname" => hostname-or-nil}]}` — stamped at SAML login from their
  Authentik groups (see `Plausible.Sgc.Scope` / `PlausibleWeb.SSO.RealSAMLAdapter`).
  Admins have no `:sgc_scope` on the session and pass through untouched.

  Two enforcement modes (select via `mode:` opt; default runs both):

    * `:site_access` — 404s any request whose resolved site
      (`conn.assigns.site`, set by `AuthorizeSiteAccess`) is not covered by a
      grant. Guest memberships (synced by `Plausible.Sgc.Provision`) already
      restrict this natively; the plug is defense in depth.

    * `:stats_filter` — when every grant for the site is hostname-restricted
      (Model-B: customers of `eagledrive.live` subdomains), AND-injects
      `["is", "event:hostname", [hostnames...]]` into `conn.params["filters"]`
      on the internal stats API. Top-level filters are implicitly ANDed, so no
      client-sent filter can widen past the user's own hostnames. A grant with
      `hostname: nil` covers the whole site — no filter injected.

  Compiled from `lib/` so it exists in the CE image.
  """

  @behaviour Plug

  import Plug.Conn
  import Phoenix.Controller, only: [get_format: 1]

  alias Plausible.Sgc.Scope

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, opts) do
    case get_session(conn, :sgc_scope) do
      %{"grants" => grants} when is_list(grants) ->
        opts
        |> Keyword.get(:mode, [:site_access, :stats_filter])
        |> List.wrap()
        |> Enum.reduce_while(conn, fn mode, conn ->
          case enforce(conn, grants, mode) do
            %Plug.Conn{halted: true} = halted -> {:halt, halted}
            conn -> {:cont, conn}
          end
        end)

      _ ->
        conn
    end
  end

  defp enforce(conn, grants, :site_access) do
    case conn.assigns[:site] do
      %{domain: domain} ->
        if domain in Scope.granted_sites(grants), do: conn, else: deny(conn)

      _ ->
        conn
    end
  end

  defp enforce(conn, grants, :stats_filter) do
    with %{domain: domain} <- conn.assigns[:site],
         hostnames when is_list(hostnames) <- Scope.hostnames_for(domain, grants) do
      inject_hostname_filter(conn, hostnames)
    else
      # :unrestricted (whole-site grant) or no site resolved
      _ -> conn
    end
  end

  defp inject_hostname_filter(conn, hostnames) do
    # An empty hostname list matches nothing — fail closed.
    mandatory = ["is", "event:hostname", hostnames]

    {existing, reencode?} =
      case conn.params["filters"] do
        filters when is_binary(filters) -> {decode_filters(filters), true}
        filters when is_list(filters) -> {filters, false}
        _ -> {[], false}
      end

    value =
      case existing ++ [mandatory] do
        filters when reencode? -> JSON.encode!(filters)
        filters -> filters
      end

    %{conn | params: Map.put(conn.params, "filters", value)}
  end

  defp decode_filters(json) do
    case JSON.decode(json) do
      {:ok, list} when is_list(list) -> list
      _ -> []
    end
  end

  defp deny(conn) do
    case get_format(conn) do
      "json" ->
        conn
        |> PlausibleWeb.Api.Helpers.not_found(
          "Site does not exist or user does not have sufficient access."
        )
        |> halt()

      _ ->
        conn
        |> PlausibleWeb.ControllerHelpers.render_error(404)
        |> halt()
    end
  end
end
