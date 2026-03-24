"""
SecProbe — Setup configuration.
"""

from setuptools import setup, find_packages

from secprobe import __version__

setup(
    name="secprobe",
    version=__version__,
    description="SecProbe — Security Testing Toolkit",
    author="SecProbe Team",
    python_requires=">=3.10",
    packages=find_packages(),
    install_requires=[
        "requests>=2.31.0",
        "dnspython>=2.4.0",
        "urllib3>=2.0.0",
    ],
    entry_points={
        "console_scripts": [
            "secprobe=secprobe.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
)
