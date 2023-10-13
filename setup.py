from setuptools import setup, find_packages

setup(
    name="ProtocolDataUnits",
    version="1.0.0",
    packages=find_packages(exclude=('tests', 'docs')),
    install_requires=[
        # Any dependencies project has, e.g.
        # 'requests',
    ],
    author="Jay Patel",
    author_email="patel999jay@gmail.com",
    description="ProtocolDataUnits python tools, based on ProtocolDataUnits.jl",
    long_description=open('README.md', encoding='utf-8').read(),
    long_description_content_type="text/markdown",
    url="https://github.com/patel999jay/ProtocolDataUnits",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
