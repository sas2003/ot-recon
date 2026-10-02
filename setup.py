from setuptools import setup, find_packages

setup(
    name="ot-recon",
    version="1.2",
    packages=find_packages(),
    install_requires=["pyyaml", "rich"],
    extras_require={
        "dev": ["pytest", "pytest-cov"],
    },
    entry_points={
        'console_scripts': [
            'ot-recon=ot_recon.main:main'
        ]
    }
)
