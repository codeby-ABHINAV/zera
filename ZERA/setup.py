from setuptools import setup, find_packages

setup(
    name="zera-scanner",
    version="1.0.0",
    description="ZERA Web Vulnerability Scanner CLI Tool",
    author="Abhinav",
    author_email="your-email@example.com",
    packages=find_packages(),
    install_requires=[
        "requests",
        "beautifulsoup4",
    ],
    entry_points={
        "console_scripts": [
            "zera=zera_scanner.scanner:main",
        ],
    },
    python_requires='>=3.6',
)

