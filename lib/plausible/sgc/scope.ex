defmodule Plausible.Sgc.Scope do
  @moduledoc """
  SGC Model-B multi-tenant scope resolution for Authentik-driven Plausible SSO.

  Maps an SSO user's Authentik group names (delivered in the SAML assertion's
  `groups` attribute) to a restricted view scope, or to unrestricted super-admin
  access. Scopes are the security boundary for Model B: a single captured
  `eagledrive.live` site whose subdomains belong to different customers, isolated
  per-user by a mandatory `event:hostname` filter (see
  `PlausibleWeb.Plugs.SgcScope`).

  Resolution (first match wins):

    1. member of an **admin group** (`SGC_SCOPE_ADMIN_GROUPS`) -> `nil`
       (unrestricted; sees the unified dashboard across all hostnames/sites).
    2. member of a **mapped customer group** (`SGC_SCOPE_MAP`) -> that group's
       `%{"site" => ..., "hostname" => ...}` scope.
    3. anything else -> `deny_scope/0` (**fail closed**: logged in but pinned to a
       nonexistent site so no data is ever readable). The break-glass local owner
       `admin@sgc.ai` logs in by password (no SSO, no scope) and is never affected,
       guaranteeing recovery if group names drift.

  Both env vars are JSON and are read at request time so customers can be
  onboarded/retargeted without rebuilding the image:

      SGC_SCOPE_ADMIN_GROUPS  (CSV) e.g. "webstats-admins,eagledrive-admins"
      SGC_SCOPE_MAP           (JSON) e.g.
        {"learningwell-admins": {"site":"eagledrive.live","hostname":"thelearningwell.eagledrive.live"}}

  Lives in `lib/` (not `extra/`) so it compiles into the CE image.
  """

  @default_admin_groups ~w(webstats-admins eagledrive-admins)

  @default_map %{
    "learningwell-admins" => %{
      "site" => "eagledrive.live",
      "hostname" => "thelearningwell.eagledrive.live"
    },
    "tmw-admins" => %{
      "site" => "eagledrive.live",
      "hostname" => "texasmodern-signup.eagledrive.live"
    }
  }

  @doc """
  Resolves a list of Authentik group names to the session scope value:
  `nil` (unrestricted), a `%{"site" => _, "hostname" => _}` map, or the
  fail-closed `deny_scope/0`.
  """
  @spec for_groups([String.t()] | any()) :: nil | map()
  def for_groups(groups) when is_list(groups) do
    groups = groups |> Enum.map(&to_string/1) |> Enum.reject(&(&1 == ""))

    cond do
      Enum.any?(groups, &(&1 in admin_groups())) -> nil
      scope = Enum.find_value(groups, &Map.get(scope_map(), &1)) -> normalize(scope)
      true -> deny_scope()
    end
  end

  def for_groups(_), do: deny_scope()

  @doc "A scope that matches no real site or hostname — used to fail closed."
  @spec deny_scope() :: map()
  def deny_scope, do: %{"site" => "\x00sgc-no-site", "hostname" => "\x00sgc-no-access"}

  defp normalize(%{"site" => site, "hostname" => hostname}),
    do: %{"site" => to_string(site), "hostname" => to_string(hostname)}

  defp normalize(_), do: deny_scope()

  defp admin_groups do
    case System.get_env("SGC_SCOPE_ADMIN_GROUPS") do
      blank when blank in [nil, ""] -> @default_admin_groups
      csv -> csv |> String.split(",", trim: true) |> Enum.map(&String.trim/1)
    end
  end

  defp scope_map do
    case System.get_env("SGC_SCOPE_MAP") do
      blank when blank in [nil, ""] ->
        @default_map

      json ->
        case JSON.decode(json) do
          {:ok, %{} = map} -> map
          _ -> @default_map
        end
    end
  end
end
