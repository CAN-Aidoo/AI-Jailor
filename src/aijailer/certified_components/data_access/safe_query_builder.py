"""Certified Safe Query Builder.

Provides parameterized database queries ONLY. String interpolation
is architecturally impossible by API design.

Prevents:
- CWE-89: SQL Injection
- CWE-564: SQL Injection via Hibernate
- CWE-943: Improper Neutralization of Special Elements in Data Query Logic
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from aijailer.core.exceptions import AiJailerError


class SecurityViolation(AiJailerError):
    """Raised when a certified component detects SQL injection risk."""

    def __init__(self, message: str):
        super().__init__(
            code="security_violation",
            message=message,
            details={"component": "safe_query_builder"},
        )


class QueryType(str, Enum):
    SELECT = "SELECT"
    INSERT = "INSERT"
    UPDATE = "UPDATE"
    DELETE = "DELETE"


# Patterns that indicate attempted SQL injection in parameter values
_INJECTION_PATTERNS = [
    r";\s*(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|EXEC|UNION)\b",
    r"['\"]\s*(OR|AND)\s+['\"0-9]",
    r"--\s*$",
    r"/\*.*\*/",
    r"\bUNION\s+ALL\s+SELECT\b",
    r"\bSLEEP\s*\(",
    r"\bBENCHMARK\s*\(",
    r"\bWAITFOR\s+DELAY\b",
    r"\bCHAR\s*\(",
    r"0x[0-9a-fA-F]+",
]


@dataclass(frozen=True)
class SafeQuery:
    """An immutable, parameterized query.

    The SQL template uses $1, $2, ... placeholders.
    Parameters are ALWAYS bound separately — never interpolated.
    """

    sql: str
    params: tuple[Any, ...]
    query_type: QueryType

    def __str__(self) -> str:
        return f"{self.query_type.value} query with {len(self.params)} bound params"


@dataclass
class WhereClause:
    """Builder for WHERE conditions — always parameterized."""

    conditions: list[str] = field(default_factory=list)
    params: list[Any] = field(default_factory=list)
    _param_counter: int = 0

    def _next_param(self) -> str:
        self._param_counter += 1
        return f"${self._param_counter}"

    def eq(self, column: str, value: Any) -> "WhereClause":
        """column = $N"""
        self._validate_identifier(column)
        param = self._next_param()
        self.conditions.append(f"{column} = {param}")
        self.params.append(value)
        return self

    def neq(self, column: str, value: Any) -> "WhereClause":
        """column != $N"""
        self._validate_identifier(column)
        param = self._next_param()
        self.conditions.append(f"{column} != {param}")
        self.params.append(value)
        return self

    def gt(self, column: str, value: Any) -> "WhereClause":
        """column > $N"""
        self._validate_identifier(column)
        param = self._next_param()
        self.conditions.append(f"{column} > {param}")
        self.params.append(value)
        return self

    def lt(self, column: str, value: Any) -> "WhereClause":
        """column < $N"""
        self._validate_identifier(column)
        param = self._next_param()
        self.conditions.append(f"{column} < {param}")
        self.params.append(value)
        return self

    def is_in(self, column: str, values: list[Any]) -> "WhereClause":
        """column IN ($N, $M, ...)"""
        self._validate_identifier(column)
        placeholders = []
        for v in values:
            param = self._next_param()
            placeholders.append(param)
            self.params.append(v)
        self.conditions.append(f"{column} IN ({', '.join(placeholders)})")
        return self

    def is_null(self, column: str) -> "WhereClause":
        """column IS NULL"""
        self._validate_identifier(column)
        self.conditions.append(f"{column} IS NULL")
        return self

    def is_not_null(self, column: str) -> "WhereClause":
        """column IS NOT NULL"""
        self._validate_identifier(column)
        self.conditions.append(f"{column} IS NOT NULL")
        return self

    def build(self, param_offset: int = 0) -> tuple[str, list[Any]]:
        """Build the WHERE clause string and parameters."""
        if not self.conditions:
            return "", []

        # Re-number parameters with offset
        clause = " AND ".join(self.conditions)
        if param_offset > 0:
            for i in range(self._param_counter, 0, -1):
                clause = clause.replace(f"${i}", f"${i + param_offset}")

        return f"WHERE {clause}", self.params

    @staticmethod
    def _validate_identifier(name: str) -> None:
        """Validate a SQL identifier (table/column name).

        Only allows alphanumeric + underscore + dot (for schema.table).
        NO string interpolation of user input into identifiers.
        """
        if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_.]*$", name):
            raise SecurityViolation(
                f"Invalid SQL identifier: '{name}'. "
                "Only alphanumeric, underscore, and dot allowed."
            )


class SafeQueryBuilder:
    """Builds parameterized SQL queries.

    String interpolation is impossible — all values are bound as parameters.
    Table and column names are validated against an identifier allowlist.
    """

    def __init__(self) -> None:
        self._allowed_tables: set[str] | None = None  # None = allow all safe identifiers

    def allow_tables(self, tables: list[str]) -> "SafeQueryBuilder":
        """Restrict operations to a specific set of tables."""
        self._allowed_tables = set(tables)
        return self

    def select(
        self,
        table: str,
        columns: list[str] | None = None,
        where: WhereClause | None = None,
        order_by: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> SafeQuery:
        """Build a parameterized SELECT query."""
        self._validate_table(table)
        cols = ", ".join(self._validate_columns(columns or ["*"]))

        sql = f"SELECT {cols} FROM {table}"
        params: list[Any] = []

        if where:
            where_sql, where_params = where.build()
            if where_sql:
                sql += f" {where_sql}"
                params.extend(where_params)

        if order_by:
            WhereClause._validate_identifier(order_by.lstrip("-"))
            direction = "DESC" if order_by.startswith("-") else "ASC"
            col = order_by.lstrip("-")
            sql += f" ORDER BY {col} {direction}"

        if limit is not None:
            params.append(limit)
            sql += f" LIMIT ${len(params)}"

        if offset is not None:
            params.append(offset)
            sql += f" OFFSET ${len(params)}"

        return SafeQuery(sql=sql, params=tuple(params), query_type=QueryType.SELECT)

    async def insert(
        self,
        table: str,
        data: dict[str, Any],
        returning: list[str] | None = None,
    ) -> SafeQuery:
        """Build a parameterized INSERT query."""
        self._validate_table(table)
        if not data:
            raise SecurityViolation("INSERT requires at least one column")

        columns = list(data.keys())
        self._validate_columns(columns)
        self._check_param_values(list(data.values()))

        placeholders = [f"${i+1}" for i in range(len(columns))]
        col_str = ", ".join(columns)
        val_str = ", ".join(placeholders)
        params = list(data.values())

        sql = f"INSERT INTO {table} ({col_str}) VALUES ({val_str})"

        if returning:
            ret_cols = ", ".join(self._validate_columns(returning))
            sql += f" RETURNING {ret_cols}"

        return SafeQuery(sql=sql, params=tuple(params), query_type=QueryType.INSERT)

    async def update(
        self,
        table: str,
        data: dict[str, Any],
        where: WhereClause | None = None,
    ) -> SafeQuery:
        """Build a parameterized UPDATE query.

        WHERE clause is REQUIRED to prevent accidental full-table updates.
        """
        self._validate_table(table)
        if not data:
            raise SecurityViolation("UPDATE requires at least one column")
        if where is None or not where.conditions:
            raise SecurityViolation(
                "UPDATE without WHERE clause is forbidden (prevents accidental data loss)"
            )

        columns = list(data.keys())
        self._validate_columns(columns)
        self._check_param_values(list(data.values()))

        set_clauses = [f"{col} = ${i+1}" for i, col in enumerate(columns)]
        params = list(data.values())

        sql = f"UPDATE {table} SET {', '.join(set_clauses)}"

        where_sql, where_params = where.build(param_offset=len(params))
        sql += f" {where_sql}"
        params.extend(where_params)

        return SafeQuery(sql=sql, params=tuple(params), query_type=QueryType.UPDATE)

    async def delete(
        self,
        table: str,
        where: WhereClause,
    ) -> SafeQuery:
        """Build a parameterized DELETE query.

        WHERE clause is REQUIRED — cannot delete all rows.
        """
        self._validate_table(table)
        if not where.conditions:
            raise SecurityViolation(
                "DELETE without WHERE clause is forbidden"
            )

        sql = f"DELETE FROM {table}"
        where_sql, where_params = where.build()
        sql += f" {where_sql}"

        return SafeQuery(sql=sql, params=tuple(where_params), query_type=QueryType.DELETE)

    def _validate_table(self, table: str) -> None:
        """Validate table name is safe."""
        WhereClause._validate_identifier(table)
        if self._allowed_tables is not None and table not in self._allowed_tables:
            raise SecurityViolation(
                f"Table '{table}' is not in the allowed tables list"
            )

    @staticmethod
    def _validate_columns(columns: list[str]) -> list[str]:
        """Validate all column names are safe identifiers."""
        for col in columns:
            if col != "*":
                WhereClause._validate_identifier(col)
        return columns

    @staticmethod
    def _check_param_values(values: list[Any]) -> None:
        """Check parameter values for obvious injection attempts."""
        for val in values:
            if isinstance(val, str):
                for pattern in _INJECTION_PATTERNS:
                    if re.search(pattern, val, re.IGNORECASE):
                        raise SecurityViolation(
                            f"Potential SQL injection detected in parameter value"
                        )
