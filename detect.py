import sqlite3
from thefuzz import fuzz
import packaging.version
import xml.etree.ElementTree as ET


def parse_xml(pom_file: str):
    """Parse the Maven project file and return a list of dependencies."""
    print(f"Parsing dependency list for Maven project file {pom_file}...")
    tree = ET.parse(pom_file)
    root = tree.getroot()

    # Extract the namespace from the root tag
    namespace = root.tag.split('}')[0] + '}'

    dependencies = [{
        # Caution! It's Id instead of ID!
        "group": dependency.find(f"{namespace}groupId").text,
        "artifact": dependency.find(f"{namespace}artifactId").text,
        "version": dependency.find(f"{namespace}version").text
    } for dependency in root.findall(
        f"./{namespace}dependencies/{namespace}dependency")]

    return dependencies


def match(dependency: dict):
    """Match one dependency against CPEs in the database."""

    conn = sqlite3.connect('cve.sqlite')
    cursor = conn.cursor()

    # First find similar vendor names or product names
    cursor.execute(
        "SELECT * FROM cpe_match WHERE vendor LIKE ? OR product LIKE ?",
        (dependency["group"], dependency["artifact"]))

    # Finer examination of vendor and product
    column_names = [column[0] for column in cursor.description]
    cpe_matches = [dict(zip(column_names, row)) for row in cursor.fetchall()]

    # Drop the CPE matches that are not similar enough
    cpe_matches = [
        cpe_match for cpe_match in cpe_matches
        if fuzz.ratio(
            dependency["group"] + dependency["artifact"],
            cpe_match["vendor"] + cpe_match["product"]) > 90
    ]

    # Examine the version
    for cpe_match in cpe_matches:
        # Exact version match
        if dependency.get("version") == cpe_match.get("version"):
            return True

        # Version range match
        start_matched, end_matched = False, False
        if cpe_match.get("version_start"):
            start_matched = \
                packaging.version.parse(dependency.get("version")) >= \
                packaging.version.parse(cpe_match.get("version_start"))

        if cpe_match.get("version_end"):
            end_matched = \
                packaging.version.parse(dependency.get("version")) < \
                packaging.version.parse(cpe_match.get("version_end"))

        if start_matched and end_matched:
            return True

    return False


def match_all(dependencies: list):
    """Match all dependencies against CPEs in the database."""
    print("Matching dependencies against CPEs in the database...")
    matched = []
    for dependency in dependencies:
        print("Examining dependency: " +
              dependency["group"] + ":" + dependency["artifact"] + "...")
        if match(dependency):
            matched.append(dependency)

    print(f"""
================ DETECTION COMPLETED ================ 

Examined {len(dependencies)} dependencies.
{len(dependencies) - len(matched)}\tdependency(ies) are safe.
{len(matched)}\tdependency(ies) are vulnerable:
""")

    for dependency in matched:
        print(":".join([
            dependency['group'],
            dependency['artifact'],
            dependency['version']]))

    print(f"""
================     SAFE HACKING     ================
""")
