defmodule Plausible.Sgc.Provision do
  @moduledoc """
  Reconciles a Plausible SSO user's team/guest memberships from their Authentik
  groups on every SAML login (Authentik is the source of truth — grants both
  appear and disappear without touching Plausible).

  Resolution comes from `Plausible.Sgc.Scope.for_groups/1`:

    * `:admin` — the user keeps their provisioned team-wide role (default
      `viewer` from the SSO policy: sees every site). Any leftover guest grant
      rows are removed since they only apply to `guest` members.

    * `{:grants, grants}` — the user is made a `guest` team member and their
      `guest_memberships` are reconciled to exactly the granted sites (viewer
      role). Empty grants leave a guest with no site access (fail closed).
      Hostname-level (Model-B) restriction within a granted site is enforced
      separately by `PlausibleWeb.Plugs.SgcScope` from the session scope.

  Called from `PlausibleWeb.SSO.RealSAMLAdapter` right after a successful
  login; failures are logged and never break the login itself (the session
  scope still fails closed on the data path).
  """

  import Ecto.Query

  require Logger

  alias Plausible.Repo
  alias Plausible.Teams

  @spec sync(Plausible.Auth.User.t(), Teams.Team.t(), :admin | {:grants, [map()]}) :: :ok
  def sync(user, team, resolution) do
    membership = Repo.get_by(Teams.Membership, user_id: user.id, team_id: team.id)

    case {membership, resolution} do
      {nil, _} ->
        Logger.warning("SGC provision: no team membership for user #{user.id}, skipping sync")

      # Owners are never demoted or touched (break-glass safety).
      {%{role: :owner}, _} ->
        :ok

      {membership, :admin} ->
        # Full member: guest grant rows don't apply — drop any leftovers, and
        # lift a previously-demoted guest back to the team's SSO default role.
        Repo.delete_all(where(guest_query(), [gm], gm.team_membership_id == ^membership.id))

        if membership.role == :guest do
          update_role!(membership, team.policy.sso_default_role)
        end

        :ok

      {membership, {:grants, grants}} ->
        membership =
          if membership.role == :guest do
            membership
          else
            update_role!(membership, :guest)
          end

        reconcile_guest_sites(membership, Plausible.Sgc.Scope.granted_sites(grants))
    end

    :ok
  rescue
    e ->
      Logger.error("SGC provision sync failed for user #{user.id}: #{Exception.message(e)}")
      :ok
  end

  defp reconcile_guest_sites(membership, granted_domains) do
    sites = Repo.all(from s in Plausible.Site, where: s.domain in ^granted_domains)

    found_domains = Enum.map(sites, & &1.domain)

    for missing <- granted_domains -- found_domains do
      Logger.warning("SGC provision: granted site #{missing} is not a Plausible site, ignoring")
    end

    site_ids = Enum.map(sites, & &1.id)

    # Remove grants no longer backed by an Authentik group.
    Repo.delete_all(
      from gm in guest_query(),
        where: gm.team_membership_id == ^membership.id,
        where: gm.site_id not in ^site_ids
    )

    existing_site_ids =
      Repo.all(
        from gm in guest_query(),
          where: gm.team_membership_id == ^membership.id,
          select: gm.site_id
      )

    for site <- sites, site.id not in existing_site_ids do
      membership
      |> Teams.GuestMembership.changeset(site, :viewer)
      |> Repo.insert!()
    end

    :ok
  end

  defp update_role!(membership, role) do
    membership
    |> Ecto.Changeset.change(role: role)
    |> Repo.update!()
  end

  defp guest_query, do: from(gm in Teams.GuestMembership)
end
