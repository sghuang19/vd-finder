#! python3

from argparse import ArgumentParser

import parse
import database
import detect


def main():
    """Main function to parse command line arguments."""

    parser = ArgumentParser(
        description="A simple Vulnerable Dependency Finder for Maven")

    parser.add_argument("mode", type=str,
                        choices=["detectOnly", "doAll"], help="""
Modes for running the program. detectOnly consults the existing knowledge 
base to list all vulnerable dependencies. doAll erases and rebuilds the 
knowledge base before detection.""")

    parser.add_argument("path", type=str, nargs='?',
                        default="./pom.xml",
                        help="Path to Maven project file.")

    parser.add_argument("--years", "-y", type=int, nargs='?',
                        default=2, help="""
Number of years of CVD feeds to fetch. The default is 2, i.e. data from the
current year and the past year will be fetched.""")

    args = parser.parse_args()

    if args.mode == "detectOnly":
        print("Detecting vulnerable dependencies for Maven project at path: "
              f"{args.path}")
        detect.match_all(detect.parse_xml(args.path))
    elif args.mode == "doAll":
        print("Rebuild vulnerability database and detect for Maven project at "
              f"{args.path}")
        data = parse.parse_years(args.years)
        database.write_db(data)
        database.cleanup_db()
        detect.match_all(detect.parse_xml(args.path))


if __name__ == "__main__":
    main()
