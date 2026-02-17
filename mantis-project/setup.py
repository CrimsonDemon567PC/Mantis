# setup.py
from setuptools import setup, find_packages
from pathlib import Path

HERE = Path(__file__).parent
README = HERE / "README.md"

setup(
    name="mantis-lang",
    version="1.0.3",
    author="Vincent Noll",
    author_email="vincent@example.com",
    description="Mantis 7 Python Compiler & Multi-File Source Manager",
    long_description=README.read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    url="https://github.com/CrimsonDemon567PC/Mantis",
    packages=find_packages(include=["mantis", "mantis.*"]),
    python_requires=">=3.11",
    install_requires=[],
    extras_require={},
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    entry_points={
        "console_scripts": [
            "mantis=mantis.cli:main",
        ],
    },
)