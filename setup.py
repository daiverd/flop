from setuptools import setup, find_packages

with open("requirements.txt") as f:
    requirements = f.read().splitlines()

setup(
    name="flop",
    version="0.1.0",
    description="Reusable OAuth authentication module for Flask microservices",
    author="Your Name",
    author_email="your.email@example.com",
    py_modules=["auth"],
    install_requires=requirements,
    python_requires=">=3.7",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Framework :: Flask",
    ],
    keywords="flask oauth authentication microservices",
    include_package_data=True,
    package_data={
        "": ["users.yaml"],
    },
)