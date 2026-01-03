from django.db import migrations

SQL_ENFORCE_IMMUTABLE = """
-- Prevent updates or deletes on AuditChainCheck
CREATE OR REPLACE FUNCTION prevent_auditchaincheck_update()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'AuditChainCheck entries are immutable and cannot be modified or deleted';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_auditchaincheck_update ON api_payment_auditchaincheck;

CREATE TRIGGER trg_prevent_auditchaincheck_update
BEFORE UPDATE OR DELETE ON api_payment_auditchaincheck
FOR EACH ROW EXECUTE FUNCTION prevent_auditchaincheck_update();
"""

SQL_REVERT = """
DROP TRIGGER IF EXISTS trg_prevent_auditchaincheck_update ON api_payment_auditchaincheck;
DROP FUNCTION IF EXISTS prevent_auditchaincheck_update CASCADE;
"""

class Migration(migrations.Migration):

    dependencies = [
        ("api_payment", "0001_initial"),
    ]

    operations = [
        migrations.RunSQL(SQL_ENFORCE_IMMUTABLE, SQL_REVERT),
    ]
