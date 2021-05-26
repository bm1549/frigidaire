import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()


setuptools.setup(
    name='frigidaire',
    version='0.8',
    author="Brian Marks",
    description="Python API for the Frigidaire 2.0 App",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/bm1549/frigidaire",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
     ],
 )
