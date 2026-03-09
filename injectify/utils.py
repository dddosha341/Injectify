import logging

logger = logging.getLogger("injectify")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


class InjectionDetectedError(Exception):
    """Exception when SQL injection is detected in the route."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


# Valid values for --dbms (from SQLMap documentation)
VALID_DBMS = [
    "mysql",
    "postgresql",
    "oracle",
    "microsoft sql server",
    "sqlite",
    "microsoft access",
    "firebird",
    "sybase",
    "db2",
    "informix",
    "hsqldb",
    "h2",
    "monetdb",
    "derby",
    "vertica",
    "mckoi",
    "presto",
    "altibase",
    "mimer",
    "cratedb",
    "greenplum",
    "cubrid",
    "drizzle",
    "iris",
    "cache",
    "frontbase",
    "extremedb",
    "tidb",
    "cockroachdb",
    "memsql",
    "percona",
    "mariadb",
    "maxdb",
    "redshift",
    "vertica",
]
