defmodule Plausible.Users do
  @moduledoc """
  User context
  """
  use Plausible

  import Ecto.Query

  alias Plausible.Auth
  alias Plausible.Repo

  # SGC: un-gated from on_ee — SSO users exist in the CE build.
  @spec type(Auth.User.t()) :: :standard | :sso
  def type(user) do
    user.type
  end

  @spec bump_last_seen(Auth.User.t() | pos_integer(), NaiveDateTime.t()) :: :ok
  def bump_last_seen(%Auth.User{id: user_id}, now) do
    bump_last_seen(user_id, now)
  end

  def bump_last_seen(user_id, now) do
    q = from(u in Auth.User, where: u.id == ^user_id)

    Repo.update_all(q, set: [last_seen: now])

    :ok
  end

  @spec remember_last_team(Auth.User.t(), String.t() | nil) :: :ok
  def remember_last_team(%Auth.User{id: user_id}, team_identifier) do
    q = from(u in Auth.User, where: u.id == ^user_id)
    Repo.update_all(q, set: [last_team_identifier: team_identifier])
    :ok
  end

  @spec has_email_code?(Auth.User.t()) :: boolean()
  def has_email_code?(user) do
    Auth.EmailVerification.any?(user)
  end
end
