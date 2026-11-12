from setuptools import find_packages, setup

setup(
    name="saltmere-tides",
    version="1.4.0",
    description="Tide predictions for Saltmere Harbour",
    author="Harbour Office",
    license="CC0-1.0",
    url="https://git.harbour.test/tides",
    python_requires=">=3.10",
    packages=find_packages(),
    install_requires=[
        "requests>=2.31",
        "numpy",
    ],
    entry_points={
        "console_scripts": [
            "tides = tides.cli:main",
        ],
    },
)
