# Modified based on template in course repo:
# https://github.com/joannacss/sse-fa23/blob/master/HW1/parser.py

import json
import requests
import gzip
import tempfile
import datetime


def fetch_feed(url: str):
    """Fetch the JSON feed from give URL."""
    response = requests.get(url)
    if response.status_code == 404:
        raise requests.HTTPError(404)
    # Save the JSON feed in a temporary file
    with tempfile.TemporaryFile() as temp:
        temp.write(response.content)  # save gzip contents to file
        temp.seek(0)  # reset the file handler to the beginning of file
        with gzip.open(temp, 'rb') as f:
            return json.loads(f.read())


def condense_cpe_match(cpe_match: dict):
    """Condense the CPE match to a dictionary with relevant information."""
    if cpe_match["vulnerable"]:
        condensed = {
            "version_start": cpe_match.get("versionStartIncluding", None),
            "version_end": cpe_match.get("versionEndExcluding", None)
        }
        _, _, _, vendor, product, version, *_ = \
            cpe_match["cpe23Uri"].split(":")
        condensed["vendor"] = vendor
        condensed["product"] = product
        if version != "*":
            condensed["version"] = version
        return condensed
    else:
        return None


def traverse_nodes(node: dict):
    """Traverse the children in nodes to get all the CPE matches."""
    if node:
        # Handle the cpe_match at current level
        cpe_matches = []
        for cpe_match in node["cpe_match"]:
            condensed = condense_cpe_match(cpe_match)
            if condensed:
                cpe_matches.append(condensed)
        # Handle the children of the node
        for child in node["children"]:
            cpe_matches.extend(traverse_nodes(child))
        return cpe_matches
    else:
        return []  # Stop the recursion


def parse(feed: dict):
    """Parse the JSON data from the NVD CVE JSON data feed."""
    # Extract the relevant information
    cves = []
    for cve_item in feed["CVE_Items"]:
        nodes = cve_item["configurations"]["nodes"]
        if nodes:
            cve = {"id": cve_item["cve"]["CVE_data_meta"]["ID"],
                   "cpe_match": []}
            for node in nodes:
                cve["cpe_match"].extend(traverse_nodes(node))
                cves.append(cve)
    return cves


def parse_years(years: int):
    """Parse the JSON data from the NVD CVE JSON data feed."""
    cur_year = datetime.date.today().year
    data = []
    for year in range(cur_year - years + 1, cur_year + 1):
        url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-" \
              f"{year}.json.gz"
        try:
            print(f"Parsing CVE feed for {year}...")
            data.extend(parse(fetch_feed(url)))
            print(f"Parsed {len(data)} CVEs.")
        except requests.HTTPError:
            print(f"CVE feed for {year} is not available, skipping it.")

    return data
