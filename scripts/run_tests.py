import subprocess


def main():
    """Run the tests."""

    subprocess.run(["poetry", "run", "pytest"], check=True)


if __name__ == "__main__":
    main()
