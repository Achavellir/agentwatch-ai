# Dependency check — November 7, 2026

pip-audit 2.9.0 queried the PyPI vulnerability service for the six exact runtime versions in requirements-lock.txt. These matched the six runtime packages in the local project environment. No known vulnerabilities were reported and no entries were skipped.

Checked: cloudpickle 3.1.2, joblib 1.6.0, numpy 2.5.3, scikit-learn 1.7.2, scipy 1.18.1, threadpoolctl 3.7.0.

Scope: an advisory-database check of these versions on this date. It does not scan application logic, prove absence of vulnerabilities, audit the OS/build tools, or cover different versions resolved by future installations. The package installer pins scikit-learn but allows compatible transitive dependencies. The version snapshot does not contain artifact hashes. The audit tool was installed separately; only package names and versions were sent to the database.

Validation: all 46 unit/regression tests passed; the frozen synthetic evaluation passed (4/4 designed scenarios flagged; 5/40 normal sessions flagged). One designed scenario is benign high-volume traffic, so scenario coverage is not attack accuracy. Representative real-agent validation remains outstanding.

Command: `python -m pip_audit -r requirements-lock.txt --no-deps --disable-pip --format json --output dependency-audit.json`.
