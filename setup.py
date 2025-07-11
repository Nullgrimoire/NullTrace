from setuptools import setup, find_packages

setup(
    name="NullTrace",
    version="1.0.0",
    author="Nullgrimoire",
    description="A modular IP and network recon scanner with banner grabbing and vulnerability hints.",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "colorama",
        "requests"
    ],
    entry_points={
        'console_scripts': [
            'nulltrace=nulltrace.NullTrace:main'
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.7',
)
