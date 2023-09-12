# Vulnerable Dependency Finder for Maven

A simple **V**ulnerable **D**ependency Finder for Maven projects. Homework 1 of
CSE60770 Secure Software Engineering, Fall 2023.

## Usage

Run `./main.py -h` to see the usage info.

Two modes are supported: `detectOnly` and `doAll`. `detectOnly` detects the
vulnerable dependencies using existing vulnerabilities knowledge
database, `doAll` will fetch CVE data feed from NVD and rebuild the database
before detecting.

In `doAll` mode, `-y` or `--help` option can be used to specify the range of
years to fetch CVE data feed. For example, `-y 2` will fetch data feed from the
current year and the last year, which is the default behavior.

```shell
$ python3 main.py doAll sample.xml -y 5
```

The knowledge database is stored in `cve.db`.

## Design Ideas

The program comprises four modules:

- `main`: the main entry of the program, which parses the command line
  arguments and calls the other modules.
- `parse`: the CVE JSON data feed is fetched and parsed, CVE ID and relevant
  CPE match info are extracted.
- `database`: writes the parsed CVE info into a SQLite database. Duplicates are
  removed to improve performance.
- `detect`: parses `pom.xml` to form a list of dependencies, then match them
  against the database and reports vulnerable dependencies.

The matching process is as follows:

- Using the `LIKE` operator in SQL to find CPEs that have similar vendor name
  or product name.
- Using `ratio()` in `thefuzz` library to further verify the similarity
  between dependency and CPE.
- Using `packaging` library to compare the version numbers to see if the
  dependency is affected by the vulnerability.
