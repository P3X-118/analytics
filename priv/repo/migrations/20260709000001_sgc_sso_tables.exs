defmodule Plausible.Repo.Migrations.SgcSsoTables do
  use Ecto.Migration

  # SGC: create the SSO tables/columns in the CE build. Upstream's
  # 20250520084130_add_sso_tables_columns is gated by `enterprise_edition?()`
  # (ee?(), compile-time) and no-ops in CE, so the reused SAML SSO has no tables.
  # This re-creates them un-gated. `teams.policy` is already added by a non-gated
  # CE migration, so it's omitted. Idempotent (if_not_exists) so it's safe on DBs
  # where these were created out-of-band.
  def change do
    create_if_not_exists table(:sso_integrations) do
      add :identifier, :binary, null: false
      add :config, :jsonb, null: false
      add :team_id, references(:teams, on_delete: :delete_all), null: false
      timestamps()
    end

    create_if_not_exists unique_index(:sso_integrations, [:team_id])
    create_if_not_exists unique_index(:sso_integrations, [:identifier])

    create_if_not_exists table(:sso_domains) do
      add :identifier, :binary, null: false
      add :domain, :text, null: false
      add :validated_via, :string, null: true
      add :last_validated_at, :naive_datetime, null: true
      add :status, :string, null: false

      add :sso_integration_id, references(:sso_integrations, on_delete: :delete_all),
        null: false

      timestamps()
    end

    create_if_not_exists unique_index(:sso_domains, [:identifier])
    create_if_not_exists unique_index(:sso_domains, [:domain])
    create_if_not_exists index(:sso_domains, [:sso_integration_id])

    alter table(:users) do
      add_if_not_exists :type, :string, null: false, default: "standard"
      add_if_not_exists :sso_identity_id, :string, null: true
      add_if_not_exists :last_sso_login, :naive_datetime, null: true

      add_if_not_exists :sso_integration_id,
                        references(:sso_integrations, on_delete: :nilify_all),
                        null: true
    end

    create_if_not_exists index(:users, [:sso_integration_id])
  end
end
