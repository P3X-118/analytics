defmodule Plausible.Sgc.Scope do
  @moduledoc """
  SGC access resolution for Authentik-driven Plausible SSO.

  Maps an SSO user's Authentik group names (delivered in the SAML assertion's
  `groups` attribute) to their Plausible access:

    * `:admin` — member of an admin group (`SGC_SCOPE_ADMIN_GROUPS`). Full team
      member; sees every site, no data restriction.

    * `{:grants, grants}` — a list of `%{"site" => domain, "hostname" => h}`
      grants (deduplicated), assembled from (first two combinable):

        1. the **pattern groups** `webstats-site-<domain>` — full access to
           exactly that site (`hostname: nil`), e.g. `webstats-site-cooey.club`.
           Assigning a customer a site is just an Authentik group membership —
           no code change, no deploy.
        2. the **mapped groups** (`SGC_SCOPE_MAP`) — Model-B hostname grants,
           e.g. `tmw-admins` -> eagledrive.live restricted to
           `texasmodern-signup.eagledrive.live` (`PlausibleWeb.Plugs.SgcScope`
           injects the mandatory `event:hostname` filter).
        3. no matching groups -> `{:grants, []}` — **fail closed**: the login
           succeeds but grants nothing. The break-glass local owner
           (admin@sgc.ai) logs in by password and is never scoped.

  `Plausible.Sgc.Provision` reconciles team/guest memberships from this
  resolution on every SSO login, and `PlausibleWeb.Plugs.SgcScope` enforces the
  data boundary per request.

  Env overrides are read at request time so access changes need no rebuild:

      SGC_SCOPE_ADMIN_GROUPS  (CSV) e.g. "webstats-admins,eagledrive-admins"
      SGC_SCOPE_MAP           (JSON) e.g.
        {"tmw-admins": {"site":"eagledrive.live","hostname":"texasmodern-signup.eagledrive.live"}}
  """

  @site_group_prefix "webstats-site-"

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

  @type grant() :: %{required(String.t()) => String.t() | nil}

  @doc """
  Resolves a list of Authentik group names to `:admin` or `{:grants, grants}`.
  An empty grants list means no access (fail closed).
  """
  @spec for_groups([String.t()] | any()) :: :admin | {:grants, [grant()]}
  def for_groups(groups) when is_list(groups) do
    groups = groups |> Enum.map(&to_string/1) |> Enum.reject(&(&1 == ""))

    if Enum.any?(groups, &(&1 in admin_groups())) do
      :admin
    else
      map = scope_map()

      grants =
        groups
        |> Enum.flat_map(fn group ->
          cond do
            grant = Map.get(map, group) -> [normalize(grant)]
            String.starts_with?(group, @site_group_prefix) -> [site_grant(group)]
            true -> []
          end
        end)
        |> Enum.reject(&is_nil/1)
        |> Enum.uniq()

      {:grants, grants}
    end
  end

  def for_groups(_), do: {:grants, []}

  @doc "Site domains granted (used for membership sync)."
  @spec granted_sites([grant()]) :: [String.t()]
  def granted_sites(grants), do: grants |> Enum.map(& &1["site"]) |> Enum.uniq()

  @doc """
  Hostname restrictions for a grant list on a given site domain. Returns
  `:unrestricted` when any grant covers the whole site, otherwise the list of
  allowed hostnames (empty = no access to this site at all).
  """
  @spec hostnames_for(site_domain :: String.t(), [grant()]) :: :unrestricted | [String.t()]
  def hostnames_for(site_domain, grants) do
    site_grants = Enum.filter(grants, &(&1["site"] == site_domain))

    if Enum.any?(site_grants, &is_nil(&1["hostname"])) do
      :unrestricted
    else
      site_grants |> Enum.map(& &1["hostname"]) |> Enum.uniq()
    end
  end

  defp site_grant(@site_group_prefix <> domain) when domain != "",
    do: %{"site" => domain, "hostname" => nil}

  defp site_grant(_), do: nil

  defp normalize(%{"site" => site} = grant) when is_binary(site) and site != "",
    do: %{"site" => site, "hostname" => grant["hostname"]}

  defp normalize(_), do: nil

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
