from __future__ import annotations

from shevek_collect.syntax_extract import extract_syntax


def _refs(sql: str) -> list[dict[str, object]]:
    result = extract_syntax("database/example.sql", sql)
    return result["syntax"]["references"]  # type: ignore[index]


def test_sql_extracts_declarations_and_data_routine_references() -> None:
    result = extract_syntax(
        "database/procedures/usp_ProcessOrder.sql",
        """
CREATE OR ALTER PROCEDURE [dbo].[usp_ProcessOrder] @OrderId int AS
BEGIN
    UPDATE oh SET Status = 40
    FROM dbo.OrderHeader oh
    JOIN dbo.Customer c ON c.CustomerId = oh.CustomerId
    WHERE oh.OrderId = @OrderId;

    INSERT INTO dbo.AuditLog(EntityId) VALUES(@OrderId);
    EXEC dbo.usp_SetOrderStatus @OrderId, 40;
    EXEC(@dynamic_sql);
END
GO
""".lstrip(),
    )

    assert result["language"] == "sql"
    assert result["parse"]["status"] == "parsed"  # type: ignore[index]
    assert result["parse"]["validation_level"] == "structural_scan"  # type: ignore[index]
    assert (
        result["syntax"]["schema_version"]  # type: ignore[index]
        == "shevek.syntax_observations.v2"
    )
    symbols = result["syntax"]["symbols"]  # type: ignore[index]
    assert [(symbol["kind"], symbol["qualname"]) for symbol in symbols] == [
        ("procedure", "dbo.usp_ProcessOrder")
    ]

    observed = {
        (ref["kind"], ref["target"], ref["target_kind"], ref["target_form"])
        for ref in result["syntax"]["references"]  # type: ignore[index]
    }
    assert ("write", "dbo.OrderHeader", "relation", "identifier") in observed
    assert ("read", "dbo.OrderHeader", "relation", "identifier") in observed
    assert ("read", "dbo.Customer", "relation", "identifier") in observed
    assert ("write", "dbo.AuditLog", "relation", "identifier") in observed
    assert ("execute", "dbo.usp_SetOrderStatus", "routine", "identifier") in observed
    assert ("execute", None, "routine", "dynamic") in observed
    assert all(
        ref["containing_symbol"] == "dbo.usp_ProcessOrder"
        for ref in result["syntax"]["references"]  # type: ignore[index]
    )


def test_sql_trigger_attachment_and_pseudo_tables_are_conservative() -> None:
    result = extract_syntax(
        "database/triggers/trg_OrderHeader_Audit.sql",
        """
CREATE OR ALTER TRIGGER dbo.trg_OrderHeader_Audit ON dbo.OrderHeader AFTER UPDATE AS
BEGIN
    INSERT dbo.AuditLog(EntityId) SELECT OrderId FROM inserted;
    UPDATE c SET LastActivityDate = GETDATE()
    FROM dbo.Customer c JOIN inserted i ON i.CustomerId = c.CustomerId;
END
GO
""".lstrip(),
    )

    observed = {
        (ref["kind"], ref["target"])
        for ref in result["syntax"]["references"]  # type: ignore[index]
    }
    assert ("defined_on", "dbo.OrderHeader") in observed
    assert ("write", "dbo.AuditLog") in observed
    assert ("write", "dbo.Customer") in observed
    assert ("read", "dbo.Customer") in observed
    assert not any(target in {"inserted", "deleted"} for _, target in observed)


def test_sql_schema_declarations_and_foreign_key_references() -> None:
    result = extract_syntax(
        "database/schema/001.sql",
        """
CREATE TABLE dbo.Customer (
    CustomerId int PRIMARY KEY
);
GO
CREATE TABLE dbo.OrderHeader (
    OrderId int PRIMARY KEY,
    CustomerId int REFERENCES dbo.Customer(CustomerId)
);
GO
CREATE VIEW dbo.vw_OpenOrders AS
SELECT o.OrderId FROM dbo.OrderHeader o;
GO
""".lstrip(),
    )

    symbols = {
        (symbol["kind"], symbol["qualname"])
        for symbol in result["syntax"]["symbols"]  # type: ignore[index]
    }
    assert symbols == {
        ("table", "dbo.Customer"),
        ("table", "dbo.OrderHeader"),
        ("view", "dbo.vw_OpenOrders"),
    }
    observed = {
        (ref["kind"], ref["target"])
        for ref in result["syntax"]["references"]  # type: ignore[index]
    }
    assert ("reference", "dbo.Customer") in observed
    assert ("read", "dbo.OrderHeader") in observed


def test_sql_does_not_infer_references_from_comments_or_string_literals() -> None:
    refs = _refs(
        """
-- UPDATE dbo.NotARealReference
SELECT 'FROM dbo.AlsoNotAReference' AS Example
FROM dbo.RealTable;
DECLARE @sql nvarchar(max) = N'UPDATE dbo.DynamicTarget SET x = 1';
EXEC(@sql);
""".lstrip()
    )

    assert ("read", "dbo.RealTable") in {(ref["kind"], ref["target"]) for ref in refs}
    targets = {ref["target"] for ref in refs if ref["target"] is not None}
    assert "dbo.NotARealReference" not in targets
    assert "dbo.AlsoNotAReference" not in targets
    assert "dbo.DynamicTarget" not in targets
    assert any(ref["kind"] == "execute" and ref["target_form"] == "dynamic" for ref in refs)


def test_sql_cte_name_is_not_emitted_as_external_relation() -> None:
    refs = _refs(
        """
WITH Recent AS (
    SELECT OrderId FROM dbo.OrderHeader
)
SELECT r.OrderId FROM Recent r JOIN dbo.Customer c ON 1 = 1;
""".lstrip()
    )

    observed = {(ref["kind"], ref["target"]) for ref in refs}
    assert ("read", "dbo.OrderHeader") in observed
    assert ("read", "dbo.Customer") in observed
    assert ("read", "Recent") not in observed


def test_sql_scanner_does_not_require_sql_server_dialect() -> None:
    result = extract_syntax(
        "database/report.sql",
        "CREATE OR REPLACE VIEW `reporting`.`open_orders` AS "
        "SELECT * FROM `sales`.`orders`; CALL reporting.refresh_cache();",
    )

    assert result["parse"]["dialect"] == "unknown"  # type: ignore[index]
    symbols = result["syntax"]["symbols"]  # type: ignore[index]
    assert ("view", "reporting.open_orders") in {
        (symbol["kind"], symbol["qualname"]) for symbol in symbols
    }
    refs = {
        (ref["kind"], ref["target"])
        for ref in result["syntax"]["references"]  # type: ignore[index]
    }
    assert ("read", "sales.orders") in refs
    assert ("execute", "reporting.refresh_cache") in refs


def test_sql_scanner_handles_dml_modifiers_and_cursor_names_conservatively() -> None:
    refs = _refs(
        """
DELETE TOP (1000) FROM dbo.AuditLog WHERE CreatedDate < GETDATE();
DECLARE c CURSOR LOCAL FAST_FORWARD FOR SELECT OrderId FROM dbo.OrderHeader;
FETCH NEXT FROM c INTO @id;
MERGE dbo.InventoryBalance AS target
USING dbo.InventoryStage AS source ON source.WidgetId = target.WidgetId
WHEN MATCHED THEN UPDATE SET OnHand = source.OnHand;
""".lstrip()
    )

    observed = {(ref["kind"], ref["target"]) for ref in refs}
    assert ("write", "dbo.AuditLog") in observed
    assert ("read", "dbo.OrderHeader") in observed
    assert ("write", "dbo.InventoryBalance") in observed
    assert ("read", "dbo.InventoryStage") in observed
    assert not any(target in {"TOP", "c", "SET", "AS"} for _, target in observed)
