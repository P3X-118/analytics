defmodule Plausible.Repo.Migrations.SgcAuditEntries do
  use Ecto.Migration

  # SGC: create the EE audit_entries table in the CE build. Upstream's
  # 20250708102205_audit_entries is gated by `enterprise_edition?()` and no-ops
  # in CE, but the reused SAML SSO writes audit entries on every login
  # (RealSAMLAdapter.consume -> Plausible.Audit.Entry.persist!), which 500s the
  # SAML consume without this table. Companion to 20260709000001_sgc_sso_tables.
  # Idempotent (if_not_exists) so it's safe on the DB where this was applied
  # out-of-band on 2026-07-11 (same version number, so it's already recorded in
  # schema_migrations there and will simply be skipped).
  def change do
    create_if_not_exists table(:audit_entries, primary_key: false) do
      add(:id, :uuid, primary_key: true)
      add :name, :string, null: false
      add :entity, :string, null: false
      add :entity_id, :string, null: false
      add :meta, :map, default: %{}
      add :change, :map, default: %{}
      add :user_id, :integer
      add :team_id, :integer
      add :datetime, :naive_datetime_usec, null: false
      add :actor_type, :string, null: false
    end

    create_if_not_exists index(:audit_entries, [:entity])
    create_if_not_exists index(:audit_entries, [:entity_id])
    create_if_not_exists index(:audit_entries, [:user_id])
    create_if_not_exists index(:audit_entries, [:team_id])
    create_if_not_exists index(:audit_entries, [:datetime])
  end
end
