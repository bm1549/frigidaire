import setuptools

with open("README.md") as fh:
    long_description = fh.read()

# Overridden by publish GH Action
version = "0.0.0-dev"

print("Using version " + version)

setuptools.setup(
    name="frigidaire",
    version=version,
    author="Brian Marks",
    description="Python API for the Frigidaire 2.0 App",
    license="MIT",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/bm1549/frigidaire",
    packages=setuptools.find_packages(),
    install_requires=["requests>=2.25.1"],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "responses>=0.23",
            "freezegun>=1.2",
            "ruff>=0.5.0",
            "mypy>=1.8",
            "types-requests",
            "pre-commit>=3.0",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
