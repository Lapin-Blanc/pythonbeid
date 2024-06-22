from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="pythonbeid",
    version="0.1.0",
    author="Fabien Toune",
    author_email="fabien.toune@gmail.com",
    description="Un module pour lire les informations des cartes d'identité belges",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Lapin-Blanc/pythonbeid",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=[
        "pyscard",
    ],
)