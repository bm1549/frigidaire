import setuptools
import sys

with open("README.md", "r") as fh:
    long_description = fh.read()

# Default
version = "SNAPSHOT"

if "--version" in sys.argv:
    idx = sys.argv.index("--version")
    sys.argv.pop(idx)
    version = sys.argv.pop(idx)

print("Using version " + version)

setuptools.setup(
    name='frigidaire',
    version=version,
    author="Brian Marks",
    description="Python API for the Frigidaire 2.0 App",
    license="MIT",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/bm1549/frigidaire",
    packages=setuptools.find_packages(),
    install_requires=[
        "certifi>=2020.12.5",
        "chardet>=4.0.0",
        "idna>=2.10",
        "requests>=2.25.1",
        "urllib3>==1.26.42",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
     ],
 )
