import sqlite3


def write_db(cves: list):
    """Write the CVE data to the database."""
    print("Updating CVE knowledge database...")
    conn = sqlite3.connect('cve.sqlite')
    cursor = conn.cursor()
    cursor.execute("DROP TABLE IF EXISTS cve")
    cursor.execute("DROP TABLE IF EXISTS cpe_match")

    cursor.execute("CREATE TABLE cve (cve_id TEXT PRIMARY KEY)")
    cursor.execute("""
        CREATE TABLE cpe_match (
           cve_id TEXT, vendor TEXT, product TEXT,
           version TEXT, version_start TEXT, version_end TEXT,
           FOREIGN KEY (cve_id) REFERENCES cve(cve_id)
       )""")

    prev_cve_id = None
    for cve in cves:
        # Sometimes the same CVE is listed twice in the feed
        cve_id = cve['id']
        if prev_cve_id == cve_id:
            continue
        prev_cve_id = cve_id

        # Insert CVE main table
        cursor.execute("INSERT INTO cve (cve_id) VALUES(?)", (cve_id,))
        # Insert CPE match to instance table
        for cpe_match in cve['cpe_match']:
            cursor.execute("""
                INSERT INTO cpe_match (
                    cve_id, vendor, product,
                    version, version_start, version_end
                ) VALUES (?, ?, ?, ?, ?, ?)
                """, (
                cve_id, cpe_match['vendor'], cpe_match['product'],
                cpe_match.get('version'),
                cpe_match.get('version_start'),
                cpe_match.get('version_end')))

    conn.commit()
    conn.close()


def cleanup_db():
    """Remove duplicate CPE matches from the database."""
    conn = sqlite3.connect('cve.sqlite')
    cursor = conn.cursor()

    cursor.execute("""
        DELETE FROM cpe_match WHERE ROWID NOT IN (
            SELECT MIN(ROWID) FROM cpe_match
            GROUP BY vendor, product, version, version_start, version_end
        )""")

    cursor.execute("SELECT COUNT(*) FROM cpe_match")
    count = cursor.fetchone()[0]
    print(f"Amount of distinct CPE matches in the database: {count}.")

    conn.commit()
    cursor.close()
    conn.close()
