defmodule PlausibleWeb.Plugs.SgcScope do
  @moduledoc """
  Enforces the SGC Model-B multi-tenant isolation boundary for scoped SSO users.

  A *scoped* user's session carries `:sgc_scope` — `%{"site" => site_domain,
  "hostname" => allowed_hostname}` — stamped at SAML login from their Authentik
  groups (see `Plausible.Sgc.Scope` and `PlausibleWeb.SSO.RealSAMLAdapter`).
  Super-admins have no `:sgc_scope` on the session and pass through untouched.

  Two enforcement modes (select via `mode:` opt; default runs both):

    * `:site_access` — 404s any request whose resolved site (`conn.assigns.site`,
      set by `AuthorizeSiteAccess`) is not the scope's `site`. Wired onto the
      dashboard page controller and the internal stats API.

    * `:stats_filter` — AND-injects `["is", "event:hostname", [hostname]]` into
      `conn.params["filters"]` on the internal stats API. Because top-level filters
      are implicitly ANDed, this constrains every query (and every breakdown) to
      the user's own subdomain no matter what filters the client sends — it cannot
      be widened or removed.

  Compiled from `lib/` so it exists in the CE image.
  """

  @behaviour Plug

  import Plug.Conn
  import Phoenix.Controller, only: [get_format: 1]

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, opts) do
    case get_session(conn, :sgc_scope) do
      %{"site" => _, "hostname" => _} = scope ->
        opts
        |> Keyword.get(:mode, [:site_access, :stats_filter])
        |> List.wrap()
        |> Enum.reduce_while(conn, fn mode, conn ->
          case enforce(conn, scope, mode) do
            %Plug.Conn{halted: true} = halted -> {:halt, halted}
            conn -> {:cont, conn}
          end
        end)

      _ ->
        conn
    end
  end

  defp enforce(conn, %{"site" => allowed_site}, :site_access) do
    case conn.assigns[:site] do
      %{domain: domain} when domain != allowed_site -> deny(conn)
      _ -> conn
    end
  end

  defp enforce(conn, %{"hostname" => hostname}, :stats_filter) do
    mandatory = ["is", "event:hostname", [hostname]]

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
